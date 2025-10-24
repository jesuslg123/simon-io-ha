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
        try:
            # Ensure we have a valid session and auth client
            await self._ensure_auth_client()

            # Get all installations
            installations_list = await Installation.async_get_installations(
                self.auth_client, ttl=5
            )

            # Store installations and get all devices
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

        except Exception as ex:
            _LOGGER.error("Error updating Simon iO data: %s", ex)
            raise UpdateFailed(f"Error communicating with Simon iO API: {ex}") from ex

    async def _ensure_auth_client(self) -> None:
        """Ensure we have a valid auth client with fresh tokens."""
        if self.session is None:
            self.session = aiohttp.ClientSession()

        # Check if we need to refresh the token
        token_expires_at = self.entry.data.get(CONF_TOKEN_EXPIRES_AT)
        if token_expires_at:
            expires_at = datetime.fromisoformat(token_expires_at)
            if datetime.now() + timedelta(seconds=TOKEN_REFRESH_BUFFER) >= expires_at:
                await self._refresh_token()

        # Create or recreate auth client
        if self.auth_client is None:
            # We need the password for Simon iO OAuth2 password grant
            if not self._password:
                raise ConfigEntryAuthFailed("Password required for authentication - please re-authenticate")
            
            self.auth_client = SimonAuth(
                client_id=self.entry.data[CONF_CLIENT_ID],
                client_secret=self.entry.data[CONF_CLIENT_SECRET],
                username=self.entry.data[CONF_USERNAME],
                password=self._password,
                session=self.session,
            )

    def set_password(self, password: str) -> None:
        """Set the password for authentication."""
        self._password = password
        # Clear existing auth client to force recreation with new password
        self.auth_client = None

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
            
            # After successful setup, remove password from config entry
            await self._cleanup_password()
        except ConfigEntryAuthFailed:
            raise
        except Exception as ex:
            raise ConfigEntryNotReady(f"Failed to setup Simon iO: {ex}") from ex

    async def _cleanup_password(self) -> None:
        """Remove password from config entry after successful setup."""
        if CONF_PASSWORD in self.entry.data:
            # Create new data without password
            new_data = {k: v for k, v in self.entry.data.items() if k != CONF_PASSWORD}
            
            # Update the config entry
            self.hass.config_entries.async_update_entry(self.entry, data=new_data)
            
            # Clear password from memory
            self._password = None

    async def async_unload(self) -> None:
        """Unload the coordinator."""
        if self.session:
            await self.session.close()
            self.session = None
        self.auth_client = None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Simon iO from a config entry."""
    coordinator = SimonDataUpdateCoordinator(hass, entry)

    # Check if we have a password stored (temporary during setup)
    password = entry.data.get(CONF_PASSWORD)
    if password:
        coordinator.set_password(password)

    try:
        await coordinator.async_setup()
    except ConfigEntryAuthFailed:
        # Trigger reauth flow
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": "reauth"},
                data=entry.data,
            )
        )
        return False
    except ConfigEntryNotReady:
        return False

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_unload()

    return unload_ok
