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
        self.session: aiohttp.ClientSession | None = None
        self.auth_client: SimonAuth | None = None
        self.installations: dict[str, Installation] = {}

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
            self.auth_client = SimonAuth(
                client_id=self.entry.data[CONF_CLIENT_ID],
                client_secret=self.entry.data[CONF_CLIENT_SECRET],
                username=self.entry.data[CONF_USERNAME],
                password="",  # We don't store the password
                session=self.session,
            )

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
        except ConfigEntryAuthFailed:
            raise
        except Exception as ex:
            raise ConfigEntryNotReady(f"Failed to setup Simon iO: {ex}") from ex

    async def async_unload(self) -> None:
        """Unload the coordinator."""
        if self.session:
            await self.session.close()
            self.session = None
        self.auth_client = None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Simon iO from a config entry."""
    coordinator = SimonDataUpdateCoordinator(hass, entry)

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
