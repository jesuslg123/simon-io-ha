"""Light platform for Simon iO integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.light import LightEntity, ColorMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SimonDataUpdateCoordinator
from .const import DOMAIN, DEVICE_TYPE_LIGHT, CAPABILITY_BRIGHTNESS

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Simon iO light entities."""
    coordinator: SimonDataUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id]

    entities = []
    devices = coordinator.data.get("devices", {})

    for device_id, device in devices.items():
        # Check if this device is a light based on capabilities or type
        device_type = device.get_device_type()
        capabilities = device.get_capabilities()

        if (
            DEVICE_TYPE_LIGHT in device_type.lower()
            or CAPABILITY_BRIGHTNESS in capabilities
            or "light" in device_type.lower()
            or "dimmer" in device_type.lower()
        ):
            entities.append(SimonLightEntity(coordinator, device_id, device))

    async_add_entities(entities)


class SimonLightEntity(LightEntity):
    """Representation of a Simon iO light entity."""

    def __init__(
        self,
        coordinator: SimonDataUpdateCoordinator,
        device_id: str,
        device: Any,
    ) -> None:
        """Initialize the light entity."""
        self.coordinator = coordinator
        self.device_id = device_id
        self.device = device
        self._attr_name = device.name
        self._attr_unique_id = f"{DOMAIN}_{device_id}"
        
        # Determine supported color modes based on capabilities
        capabilities = device.get_capabilities()
        if CAPABILITY_BRIGHTNESS in capabilities:
            self._attr_supported_color_modes = {ColorMode.BRIGHTNESS}
            self._attr_color_mode = ColorMode.BRIGHTNESS
        else:
            self._attr_supported_color_modes = {ColorMode.ONOFF}
            self._attr_color_mode = ColorMode.ONOFF

    @property
    def is_on(self) -> bool | None:
        """Return true if light is on."""
        if not self.device:
            return None
        
        # Get current state from device
        state = getattr(self.device, 'state', None)
        if state is not None:
            return bool(state)
        return None

    @property
    def brightness(self) -> int | None:
        """Return the brightness of the light."""
        if not self.device or not self.is_on:
            return None
        
        # Get current level/brightness from device
        level = getattr(self.device, 'level', None)
        if level is not None:
            # Convert percentage to 0-255 range
            return int((level / 100) * 255)
        return None

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the light on."""
        if not self.device:
            return

        brightness = kwargs.get("brightness")
        
        if brightness is not None and CAPABILITY_BRIGHTNESS in self.device.get_capabilities():
            # Convert brightness from 0-255 to percentage
            level = int((brightness / 255) * 100)
            await self.coordinator.async_call_with_auth_retry(self.device.async_set_level, level)
        else:
            # Just turn on
            await self.coordinator.async_call_with_auth_retry(self.device.async_set_state, True)
        
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the light off."""
        if self.device:
            await self.coordinator.async_call_with_auth_retry(self.device.async_set_state, False)
            await self.coordinator.async_request_refresh()

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
