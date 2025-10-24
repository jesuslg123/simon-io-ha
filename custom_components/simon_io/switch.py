"""Switch platform for Simon iO integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SimonDataUpdateCoordinator
from .const import DOMAIN, DEVICE_TYPE_SWITCH, CAPABILITY_ON_OFF, CAPABILITY_BRIGHTNESS

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Simon iO switch entities."""
    coordinator: SimonDataUpdateCoordinator = hass.data[DOMAIN][config_entry.entry_id]

    entities = []
    devices = coordinator.data.get("devices", {})

    for device_id, device in devices.items():
        # Check if this device is a switch based on capabilities or type
        device_type = device.get_device_type()
        capabilities = device.get_capabilities()

        if (
            DEVICE_TYPE_SWITCH in device_type.lower()
            or CAPABILITY_ON_OFF in capabilities
            or "switch" in device_type.lower()
            or "outlet" in device_type.lower()
            or "relay" in device_type.lower()
        ):
            # Only add if it doesn't have brightness capability (lights handle that)
            if CAPABILITY_BRIGHTNESS not in capabilities:
                entities.append(SimonSwitchEntity(coordinator, device_id, device))

    async_add_entities(entities)


class SimonSwitchEntity(SwitchEntity):
    """Representation of a Simon iO switch entity."""

    def __init__(
        self,
        coordinator: SimonDataUpdateCoordinator,
        device_id: str,
        device: Any,
    ) -> None:
        """Initialize the switch entity."""
        self.coordinator = coordinator
        self.device_id = device_id
        self.device = device
        self._attr_name = device.name
        self._attr_unique_id = f"{DOMAIN}_{device_id}"

    @property
    def is_on(self) -> bool | None:
        """Return true if switch is on."""
        if not self.device:
            return None
        
        # Get current state from device
        state = getattr(self.device, 'state', None)
        if state is not None:
            return bool(state)
        return None

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the switch on."""
        if self.device:
            await self.coordinator.async_call_with_auth_retry(self.device.async_set_state, True)
            await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the switch off."""
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
