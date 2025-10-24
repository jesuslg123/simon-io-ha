"""Extensions to the aiosimon_io Device class."""
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiosimon_io import Device

logger = logging.getLogger(__name__)


async def async_stop(self: "Device") -> None:
    """
    Stop a moving cover/blind device by sending the stop action.
    
    This sends the API request: {"multilevel": {"blinds": {"action": "stop"}}}
    
    Raises:
        ValueError: If the device type or subtype is not defined.
        Exception: If an error occurs while sending the stop command.
    """
    logger.debug(f"Stopping device '{self.name}'")
    device_type = self.get_type()
    device_subtype = self.get_subtype()
    
    if device_type is None or device_subtype is None:
        raise ValueError("Device type or subtype is not defined.")
    
    # Build the stop action body
    body = {device_type: {device_subtype: {"action": "stop"}}}
    
    try:
        local_path = f"{self._hub_devices_endpoint}/{self.id}"
        sns_path = f"{self._sns_devices_endpoint.format(installation_id=self.installation.id)}/{self.id}"
        response: dict = await self.installation._async_request_switcher(
            "PATCH", local_path, sns_path, json=body
        )
        
        for key, value in response.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                logger.warning(
                    f"Attribute '{key}' does not exist in the Device class. Ignoring it."
                )
    except Exception as e:
        logger.error(f"Error stopping device {self.name}: {e}")
        raise


def patch_device_class():
    """Add async_stop method to the aiosimon_io Device class."""
    from aiosimon_io import Device
    
    if not hasattr(Device, 'async_stop'):
        Device.async_stop = async_stop
        logger.debug("Patched Device class with async_stop method")
