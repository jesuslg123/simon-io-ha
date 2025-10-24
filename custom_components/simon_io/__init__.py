"""Simon iO integration."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

import aiohttp
from aiosimon_io import Installation, SimonAuth

# Patch the Device class to add async_stop method
from .device_extensions import patch_device_class
patch_device_class()
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_TOKEN_EXPIRES_AT,
    CONF_USERNAME,
    DOMAIN,
    PLATFORMS,
    TOKEN_REFRESH_BUFFER,
    UPDATE_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)


class SimonDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Class to manage fetching data from the Simon iO API."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the coordinator."""
        self.entry = entry
        self.hass = hass
        self.session: aiohttp.ClientSession | None = None
        self.auth_client: SimonAuth | None = None
        self.installations: dict[str, Installation] = {}
        self._password: str | None = None  # Temporary password storage for auth
        self._fast_poll_until: datetime | None = None
        self._fast_poll_interval = timedelta(seconds=2)
        self._fast_poll_duration = timedelta(seconds=10)

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )

    async def async_call_with_auth_retry(self, func, *args, **kwargs):
        """Call a coroutine-producing function; on auth failure refresh token and retry once.

        This is intended to wrap any device action. It will:
        - attempt the call
        - if it fails with a likely auth error (401/403/expired token), refresh tokens
        - retry the call once
        """
        # First, try normally
        try:
            return await func(*args, **kwargs)
        except Exception as ex:
            if self._is_auth_error(ex):
                _LOGGER.warning("Action failed due to auth error, attempting token refresh and retry: %s", ex)
                try:
                    await self._refresh_token(force=True)
                except Exception as refresh_ex:
                    _LOGGER.error("Token refresh after action failure also failed: %s", refresh_ex)
                    raise ex

                # Retry once
                try:
                    return await func(*args, **kwargs)
                except Exception as retry_ex:
                    _LOGGER.error("Action retry after token refresh failed: %s", retry_ex)
                    raise retry_ex
            # Not an auth error -> propagate
            raise

    def _is_auth_error(self, ex: Exception) -> bool:
        """Best-effort detection of authentication-related errors from underlying client."""
        msg = str(ex).lower()
        # Common markers
        if any(k in msg for k in ["unauthorized", "forbidden", "invalid token", "token expired", "expired token", "401", "403"]):
            return True
        # aiohttp ClientResponseError often has status attribute
        status = getattr(ex, "status", None) or getattr(getattr(ex, "response", None), "status", None)
        if status in (401, 403):
            return True
        return False

    def trigger_fast_polling(self) -> None:
        """Trigger fast polling for a short duration after user action."""
        self._fast_poll_until = datetime.now() + self._fast_poll_duration
        # Update the coordinator's update interval temporarily
        self.update_interval = self._fast_poll_interval
        _LOGGER.debug("Fast polling triggered for %s seconds", self._fast_poll_duration.total_seconds())

    async def _async_update_data(self) -> dict[str, Any]:
        """Update data via library."""
        # Check if we should return to normal polling
        if self._fast_poll_until and datetime.now() >= self._fast_poll_until:
            self._fast_poll_until = None
            self.update_interval = timedelta(seconds=UPDATE_INTERVAL)
            _LOGGER.debug("Fast polling ended, returning to normal interval")
        
        _LOGGER.info("Starting data update")
        try:
            # Ensure we have a valid session and auth client
            await self._ensure_auth_client()
            _LOGGER.info("Auth client ensured, proceeding with data fetch")

            # Get all installations
            _LOGGER.info("Fetching installations from Simon iO")
            installations_list = await Installation.async_get_installations(
                self.auth_client, ttl=5
            )
            _LOGGER.info("Successfully fetched %d installations", len(installations_list))

            # Store installations and get all devices
            all_devices = {}
            self.installations = {}

            for installation in installations_list:
                _LOGGER.debug("Processing installation: %s (%s)", installation.name, installation.id)
                self.installations[installation.id] = installation
                devices = await installation.async_get_devices()
                _LOGGER.debug("Found %d devices in installation %s", len(devices), installation.name)
                all_devices.update(devices)

            _LOGGER.info("Data update completed successfully. Total devices: %d", len(all_devices))
            return {
                "installations": self.installations,
                "devices": all_devices,
            }

        except Exception as ex:
            # On auth error, attempt one refresh and retry the whole fetch
            if self._is_auth_error(ex):
                _LOGGER.warning("Data update failed due to auth error; refreshing token and retrying once: %s", ex)
                try:
                    await self._refresh_token(force=True)
                    # Retry once
                    installations_list = await Installation.async_get_installations(
                        self.auth_client, ttl=5
                    )

                    all_devices = {}
                    self.installations = {}
                    for installation in installations_list:
                        self.installations[installation.id] = installation
                        devices = await installation.async_get_devices()
                        all_devices.update(devices)

                    return {
                        "installations": self.installations,
                        "devices": all_devices,
                    }
                except Exception as retry_ex:
                    _LOGGER.error("Retry after token refresh failed: %s", retry_ex)
                    raise UpdateFailed(f"Auth retry failed: {retry_ex}") from retry_ex

            _LOGGER.error("Error updating Simon iO data: %s", ex)
            _LOGGER.error("Exception type: %s", type(ex).__name__)
            import traceback
            _LOGGER.error("Traceback: %s", traceback.format_exc())
            raise UpdateFailed(f"Error communicating with Simon iO API: {ex}") from ex

    async def _ensure_auth_client(self) -> None:
        """Ensure we have a valid auth client with fresh tokens."""
        _LOGGER.info("Ensuring auth client is available")
        
        if self.session is None:
            _LOGGER.info("Creating new aiohttp session")
            self.session = aiohttp.ClientSession()

        # Create or recreate auth client
        if self.auth_client is None:
            _LOGGER.info("Creating new SimonAuth client")
            # Prefer using a stored password (temporary during setup). If no
            # password is available (we remove it after initial setup), try to
            # reuse stored tokens (access/refresh) from the config entry.
            _LOGGER.debug("Client ID: %s", self.entry.data.get(CONF_CLIENT_ID))
            _LOGGER.debug("Client Secret: %s", self.entry.data.get(CONF_CLIENT_SECRET))
            _LOGGER.debug("Username: %s", self.entry.data.get(CONF_USERNAME))

            try:
                if self._password:
                    _LOGGER.debug("Using stored password for SimonAuth")
                    self.auth_client = SimonAuth(
                        client_id=self.entry.data[CONF_CLIENT_ID],
                        client_secret=self.entry.data[CONF_CLIENT_SECRET],
                        username=self.entry.data[CONF_USERNAME],
                        password=self._password,
                        session=self.session,
                    )
                else:
                    # Try to reuse stored tokens if available
                    access_token = self.entry.data.get(CONF_ACCESS_TOKEN)
                    refresh_token = self.entry.data.get(CONF_REFRESH_TOKEN)
                    token_expires_at = self.entry.data.get(CONF_TOKEN_EXPIRES_AT)

                    if not (access_token or refresh_token):
                        _LOGGER.error("No password or tokens available for authentication")
                        raise ConfigEntryAuthFailed(
                            "Password required for authentication - please re-authenticate"
                        )

                    _LOGGER.debug("Creating SimonAuth using stored tokens")
                    # Provide an empty password; we will populate tokens below
                    self.auth_client = SimonAuth(
                        client_id=self.entry.data[CONF_CLIENT_ID],
                        client_secret=self.entry.data[CONF_CLIENT_SECRET],
                        username=self.entry.data[CONF_USERNAME],
                        password="",
                        session=self.session,
                    )

                    # Restore tokens so SimonAuth can use them/refresh them
                    self.auth_client.access_token = access_token
                    self.auth_client.refresh_token = refresh_token
                    if token_expires_at:
                        try:
                            if isinstance(token_expires_at, str):
                                self.auth_client.token_expires_at = datetime.fromisoformat(token_expires_at)
                            elif isinstance(token_expires_at, datetime):
                                self.auth_client.token_expires_at = token_expires_at
                        except Exception:
                            _LOGGER.warning(
                                "Failed to parse stored token expiry '%s'", token_expires_at
                            )

                _LOGGER.info("SimonAuth client created successfully")

                # Test the auth client immediately (this will refresh tokens if needed)
                _LOGGER.info("Testing auth client by getting access token")
                test_token = await self.auth_client.async_get_access_token()
                # Persist any potentially updated tokens (library may refresh on demand)
                await self._persist_tokens()
                _LOGGER.info("Auth client test successful, token obtained")

            except ConfigEntryAuthFailed:
                # Propagate reauth requests
                raise
            except Exception as ex:
                _LOGGER.error("Failed to create or test SimonAuth client: %s", ex)
                _LOGGER.error("Exception type: %s", type(ex).__name__)
                import traceback
                _LOGGER.error("Traceback: %s", traceback.format_exc())
                raise ConfigEntryAuthFailed(f"Failed to create auth client: {ex}") from ex

        # After ensuring the client exists, optionally refresh if expiry is near
        token_expires_at = self.entry.data.get(CONF_TOKEN_EXPIRES_AT)
        _LOGGER.debug("Token expiry data: %s (type: %s)", token_expires_at, type(token_expires_at))
        if token_expires_at:
            try:
                if isinstance(token_expires_at, str):
                    expires_at = datetime.fromisoformat(token_expires_at)
                elif isinstance(token_expires_at, datetime):
                    expires_at = token_expires_at
                else:
                    expires_at = None

                if expires_at and (datetime.now() + timedelta(seconds=TOKEN_REFRESH_BUFFER) >= expires_at):
                    _LOGGER.info("Token expires soon, refreshing")
                    await self._refresh_token()
            except (ValueError, TypeError) as ex:
                _LOGGER.warning("Failed to parse token expiry time '%s': %s", token_expires_at, ex)

    def set_password(self, password: str) -> None:
        """Set the password for authentication."""
        _LOGGER.info("Setting password in coordinator")
        _LOGGER.debug("Password provided: %s", "***" if password else "EMPTY")
        self._password = password
        # Clear existing auth client to force recreation with new password
        self.auth_client = None
        _LOGGER.info("Password set and auth client cleared")

    async def _refresh_token(self, force: bool = False) -> None:
        """Refresh the access token using SimonAuth and persist it to the entry.

        If 'force' is True, we clear the in-memory access_token first to force a refresh.
        """
        if not self.auth_client:
            await self._ensure_auth_client()

        try:
            if force and hasattr(self.auth_client, "access_token"):
                setattr(self.auth_client, "access_token", None)

            _LOGGER.debug("Requesting (re)fresh access token from SimonAuth")
            await self.auth_client.async_get_access_token()
            await self._persist_tokens()
            _LOGGER.info("Token refresh completed and persisted")
        except Exception as ex:
            _LOGGER.error("Failed to refresh token: %s", ex)
            raise ConfigEntryAuthFailed("Token refresh failed") from ex

    async def _persist_tokens(self) -> None:
        """Persist tokens from SimonAuth to the config entry if available."""
        if not self.auth_client:
            return
        access_token = getattr(self.auth_client, "access_token", None)
        refresh_token = getattr(self.auth_client, "refresh_token", None)
        token_expires_at = getattr(self.auth_client, "token_expires_at", None)

        # Normalize expiry to ISO string
        if token_expires_at is not None:
            if hasattr(token_expires_at, "isoformat"):
                token_expires_at = token_expires_at.isoformat()
            elif not isinstance(token_expires_at, str):
                token_expires_at = str(token_expires_at)

        # Update entry data only if we have any token values
        new_data = {**self.entry.data}
        if access_token is not None:
            new_data[CONF_ACCESS_TOKEN] = access_token
        if refresh_token is not None:
            new_data[CONF_REFRESH_TOKEN] = refresh_token
        if token_expires_at is not None:
            new_data[CONF_TOKEN_EXPIRES_AT] = token_expires_at

        if new_data != self.entry.data:
            _LOGGER.debug("Persisting updated tokens to config entry")
            self.hass.config_entries.async_update_entry(self.entry, data=new_data)

    async def async_setup(self) -> None:
        """Set up the coordinator."""
        try:
            await self._ensure_auth_client()
            await self.async_config_entry_first_refresh()
            
            # Only cleanup password after successful setup and first refresh
            _LOGGER.info("Coordinator setup successful, cleaning up password")
            await self._cleanup_password()
        except ConfigEntryAuthFailed:
            raise
        except Exception as ex:
            raise ConfigEntryNotReady(f"Failed to setup Simon iO: {ex}") from ex

    async def _cleanup_password(self) -> None:
        """Remove password from config entry after successful setup."""
        _LOGGER.info("Starting password cleanup")
        if CONF_PASSWORD in self.entry.data:
            _LOGGER.info("Password found in config entry, removing it")
            # Create new data without password
            new_data = {k: v for k, v in self.entry.data.items() if k != CONF_PASSWORD}
            
            # Update the config entry
            self.hass.config_entries.async_update_entry(self.entry, data=new_data)
            _LOGGER.info("Password removed from config entry")
            
            # Clear password from memory
            self._password = None
            _LOGGER.info("Password cleared from memory")
        else:
            _LOGGER.info("No password found in config entry to cleanup")

    async def async_unload(self) -> None:
        """Unload the coordinator."""
        if self.session:
            await self.session.close()
            self.session = None
        self.auth_client = None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Simon iO from a config entry."""
    _LOGGER.info("Setting up Simon iO integration")
    _LOGGER.debug("Config entry data keys: %s", list(entry.data.keys()))
    _LOGGER.debug("Config entry data values: %s", {k: "***" if "password" in k.lower() or "secret" in k.lower() or "token" in k.lower() else v for k, v in entry.data.items()})
    
    coordinator = SimonDataUpdateCoordinator(hass, entry)

    # Check if we have a password stored (temporary during setup)
    password = entry.data.get(CONF_PASSWORD)
    _LOGGER.info("Password found in config entry: %s", "YES" if password else "NO")
    if password:
        _LOGGER.info("Setting password in coordinator")
        _LOGGER.debug("Password length: %d characters", len(password))
        coordinator.set_password(password)
    else:
        _LOGGER.warning("No password found in config entry - this may cause authentication issues")

    try:
        _LOGGER.info("Starting coordinator setup")
        await coordinator.async_setup()
        _LOGGER.info("Coordinator setup completed successfully")
    except ConfigEntryAuthFailed as ex:
        _LOGGER.error("Authentication failed during setup: %s", ex)
        # Trigger reauth flow
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": "reauth", "entry_id": entry.entry_id},
                data=entry.data,
            )
        )
        return False
    except ConfigEntryNotReady as ex:
        _LOGGER.error("Integration not ready: %s", ex)
        return False

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Set up platforms
    _LOGGER.info("Setting up platforms: %s", PLATFORMS)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register options flow
    entry.async_on_unload(
        entry.add_update_listener(async_reload_entry)
    )
    
    # Options flow is provided via the ConfigFlow's async_get_options_flow
    # implementation in config_flow.py, no runtime registration required.

    _LOGGER.info("Simon iO integration setup completed successfully")
    return True


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_unload()

    return unload_ok
