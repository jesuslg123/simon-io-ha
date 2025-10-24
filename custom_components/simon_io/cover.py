"""Cover platform for Simon iO integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.cover import CoverEntity, CoverDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SimonDataUpdateCoordinator
from .const import DOMAIN, DEVICE_TYPE_COVER

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Simon iO cover entities."""
    coordinator: SimonDataUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id]

    entities = []
    devices = coordinator.data.get("devices", {})

    for device_id, device in devices.items():
        # Check if this device is a cover/blind based on capabilities or type
        device_type = device.get_device_type()
        capabilities = device.get_capabilities()

        if (
            DEVICE_TYPE_COVER in device_type.lower()
            or "level" in capabilities
            or "blind" in device_type.lower()
            or "shutter" in device_type.lower()
        ):
            entities.append(SimonCoverEntity(coordinator, device_id, device))

    async_add_entities(entities)


class SimonCoverEntity(CoverEntity):
    """Representation of a Simon iO cover entity."""

    def __init__(
        self,
        coordinator: SimonDataUpdateCoordinator,
        device_id: str,
        device: Any,
    ) -> None:
        """Initialize the cover entity."""
        self.coordinator = coordinator
        self.device_id = device_id
        self.device = device
        self._attr_name = device.name
        self._attr_unique_id = f"{DOMAIN}_{device_id}"
        self._attr_device_class = CoverDeviceClass.BLIND

    @property
    def current_cover_position(self) -> int | None:
        """Return current position of cover."""
        if not self.device:
            return None
        
        # Get current level/position from device
        # Assuming the device has a level property
        level = getattr(self.device, 'level', None)
        if level is not None:
            return int(level)
        return None

    @property
    def is_closed(self) -> bool | None:
        """Return if the cover is closed."""
        position = self.current_cover_position
        if position is not None:
            return position == 0
        return None

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        if self.device:
            await self.device.async_set_level(100)
            await self.coordinator.async_request_refresh()

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        if self.device:
            await self.device.async_set_level(0)
            await self.coordinator.async_request_refresh()

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        """Move the cover to a specific position."""
        position = kwargs.get("position")
        if self.device and position is not None:
            await self.device.async_set_level(position)
            await self.coordinator.async_request_refresh()

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Stop the cover."""
        # Simon iO devices might not support stop, but we can implement it
        # by maintaining the current position
        _LOGGER.debug("Stop cover requested for %s", self.name)

    @property
    def available(self) -> bool:
        """Return if the entity is available."""
        return self.coordinator.last_update_success and self.device is not None

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self.async_on_remove(
            self.coordinator.async_add_listener(self.async_write_ha_state)
        )

    async def async_update(self) -> None:
        """Update the entity."""
        # Update device reference from coordinator data
        devices = self.coordinator.data.get("devices", {})
        self.device = devices.get(self.device_id)
