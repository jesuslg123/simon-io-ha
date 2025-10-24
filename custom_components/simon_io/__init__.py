"""Simon iO integration."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

import aiohttp
from aiosimon_io import Installation, SimonAuth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
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

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )

    async def _async_update_data(self) -> dict[str, Any]:
        """Update data via library."""
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

        # Check if we need to refresh the token
        token_expires_at = self.entry.data.get(CONF_TOKEN_EXPIRES_AT)
        if token_expires_at:
            expires_at = datetime.fromisoformat(token_expires_at)
            if datetime.now() + timedelta(seconds=TOKEN_REFRESH_BUFFER) >= expires_at:
                _LOGGER.info("Token expires soon, refreshing")
                await self._refresh_token()

        # Create or recreate auth client
        if self.auth_client is None:
            _LOGGER.info("Creating new SimonAuth client")
            # We need the password for Simon iO OAuth2 password grant
            if not self._password:
                _LOGGER.error("No password available for authentication")
                raise ConfigEntryAuthFailed("Password required for authentication - please re-authenticate")
            
            _LOGGER.debug("Using stored credentials for SimonAuth")
            _LOGGER.debug("Client ID: %s", self.entry.data[CONF_CLIENT_ID])
            _LOGGER.debug("Client Secret: %s", self.entry.data[CONF_CLIENT_SECRET])
            _LOGGER.debug("Username: %s", self.entry.data[CONF_USERNAME])
            _LOGGER.debug("Password: %s", "***" if self._password else "EMPTY")
            
            try:
                self.auth_client = SimonAuth(
                    client_id=self.entry.data[CONF_CLIENT_ID],
                    client_secret=self.entry.data[CONF_CLIENT_SECRET],
                    username=self.entry.data[CONF_USERNAME],
                    password=self._password,
                    session=self.session,
                )
                _LOGGER.info("SimonAuth client created successfully")
                
                # Test the auth client immediately
                _LOGGER.info("Testing auth client by getting access token")
                test_token = await self.auth_client.async_get_access_token()
                _LOGGER.info("Auth client test successful, token obtained")
                
            except Exception as ex:
                _LOGGER.error("Failed to create or test SimonAuth client: %s", ex)
                _LOGGER.error("Exception type: %s", type(ex).__name__)
                import traceback
                _LOGGER.error("Traceback: %s", traceback.format_exc())
                raise ConfigEntryAuthFailed(f"Failed to create auth client: {ex}") from ex

    def set_password(self, password: str) -> None:
        """Set the password for authentication."""
        _LOGGER.info("Setting password in coordinator")
        _LOGGER.debug("Password provided: %s", "***" if password else "EMPTY")
        self._password = password
        # Clear existing auth client to force recreation with new password
        self.auth_client = None
        _LOGGER.info("Password set and auth client cleared")

    async def _refresh_token(self) -> None:
        """Refresh the access token."""
        try:
            # For now, we'll trigger a reauth flow
            # In a real implementation, you'd use the refresh token
            raise ConfigEntryAuthFailed("Token expired, reauth required")
        except Exception as ex:
            _LOGGER.error("Failed to refresh token: %s", ex)
            raise ConfigEntryAuthFailed("Token refresh failed") from ex

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
                context={"source": "reauth"},
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

    _LOGGER.info("Simon iO integration setup completed successfully")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_unload()

    return unload_ok
