"""Cover platform for Simon iO integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.cover import (
    CoverEntity,
    CoverDeviceClass,
)

# Support constants moved around in different HA versions. Try importing
# them if available; otherwise fall back to the standard bitmask values.
try:
    # Newer/older HA may expose these at module level
    from homeassistant.components.cover import (
        SUPPORT_OPEN,
        SUPPORT_CLOSE,
        SUPPORT_SET_POSITION,
        SUPPORT_STOP,
    )
except Exception:
    # Fallback bitmask values (standard HA flags)
    SUPPORT_OPEN = 1
    SUPPORT_CLOSE = 2
    SUPPORT_SET_POSITION = 4
    SUPPORT_STOP = 8
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
        
        # Determine device class based on actual device type
        device_type = device.get_device_type() or ""
        if "shutter" in device_type.lower():
            self._attr_device_class = CoverDeviceClass.SHUTTER
        elif "blind" in device_type.lower():
            self._attr_device_class = CoverDeviceClass.BLIND
        else:
            # Default fallback
            self._attr_device_class = CoverDeviceClass.SHUTTER
        
        # State tracking for movement
        self._is_opening = False
        self._is_closing = False
        self._last_position = None
        self._target_position = None

    @property
    def current_cover_position(self) -> int | None:
        """Return current position of cover."""
        if not self.device:
            return None
        
        # Prefer the device's helper to read level (aiosimon_io.Device.get_level())
        try:
            if hasattr(self.device, "get_level"):
                level = self.device.get_level()
            else:
                # Fallback to an attribute if present (older models)
                level = getattr(self.device, "level", None)

            if level is not None:
                position = int(level)
                self._last_position = position
                return position
        except Exception as ex:
            _LOGGER.debug("Error reading level for %s: %s", self.name, ex)

        # If we can't get the position from device, return last known position
        return self._last_position

    @property
    def supported_features(self) -> int:
        """Return supported features for this cover."""
        # We implement open/close/set position/stop handlers
        return SUPPORT_OPEN | SUPPORT_CLOSE | SUPPORT_SET_POSITION | SUPPORT_STOP

    @property
    def is_closed(self) -> bool | None:
        """Return if the cover is closed."""
        position = self.current_cover_position
        if position is not None:
            return position == 0
        return None

    @property
    def is_opening(self) -> bool:
        """Return if the cover is opening."""
        return self._is_opening

    @property
    def is_closing(self) -> bool:
        """Return if the cover is closing."""
        return self._is_closing

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Open the cover."""
        if self.device:
            _LOGGER.debug("Opening cover %s", self.name)
            self._is_opening = True
            self._is_closing = False
            self._target_position = 100
            self.async_write_ha_state()
            
            try:
                await self.device.async_set_level(100)
                _LOGGER.debug("Successfully sent open command to %s", self.name)
            except Exception as ex:
                _LOGGER.error("Failed to open cover %s: %s", self.name, ex)
                self._is_opening = False
                self.async_write_ha_state()
                raise
            
            # Trigger fast polling to quickly update state
            self.coordinator.trigger_fast_polling()
            await self.coordinator.async_request_refresh()

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Close the cover."""
        if self.device:
            _LOGGER.debug("Closing cover %s", self.name)
            self._is_opening = False
            self._is_closing = True
            self._target_position = 0
            self.async_write_ha_state()
            
            try:
                await self.device.async_set_level(0)
                _LOGGER.debug("Successfully sent close command to %s", self.name)
            except Exception as ex:
                _LOGGER.error("Failed to close cover %s: %s", self.name, ex)
                self._is_closing = False
                self.async_write_ha_state()
                raise
            
            # Trigger fast polling to quickly update state
            self.coordinator.trigger_fast_polling()
            await self.coordinator.async_request_refresh()

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        """Move the cover to a specific position."""
        position = kwargs.get("position")
        if self.device and position is not None:
            _LOGGER.debug("Setting cover %s position to %d%%", self.name, position)
            
            # Determine movement direction
            current_pos = self.current_cover_position or 0
            if position > current_pos:
                self._is_opening = True
                self._is_closing = False
            elif position < current_pos:
                self._is_opening = False
                self._is_closing = True
            else:
                self._is_opening = False
                self._is_closing = False
            
            self._target_position = position
            self.async_write_ha_state()
            
            try:
                await self.device.async_set_level(position)
                _LOGGER.debug("Successfully sent position command to %s", self.name)
            except Exception as ex:
                _LOGGER.error("Failed to set position for cover %s: %s", self.name, ex)
                self._is_opening = False
                self._is_closing = False
                self.async_write_ha_state()
                raise
            
            # Trigger fast polling to quickly update state
            self.coordinator.trigger_fast_polling()
            await self.coordinator.async_request_refresh()

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Stop the cover."""
        _LOGGER.debug("Stopping cover %s", self.name)
        
        # Stop movement tracking
        self._is_opening = False
        self._is_closing = False
        self._target_position = None
        self.async_write_ha_state()
        
        # Send stop action to device using the API's stop action
        if self.device:
            try:
                await self.device.async_stop()
                _LOGGER.debug("Successfully sent stop command to %s", self.name)
            except Exception as ex:
                _LOGGER.error("Failed to stop cover %s: %s", self.name, ex)
                # Still update our state even if the command failed
                self.async_write_ha_state()
                raise
        
        # Trigger fast polling to quickly update state
        self.coordinator.trigger_fast_polling()
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
        
        # Check if we've reached our target position
        if self._target_position is not None:
            current_pos = self.current_cover_position
            if current_pos is not None:
                # Consider position reached if within 5% of target
                if abs(current_pos - self._target_position) <= 5:
                    self._is_opening = False
                    self._is_closing = False
                    self._target_position = None
                    _LOGGER.debug("Cover %s reached target position", self.name)
