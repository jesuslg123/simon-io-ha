"""Config flow for Simon iO integration."""
from __future__ import annotations

import logging
from typing import Any

import aiohttp
from aiosimon_io import SimonAuth, User
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import config_validation as cv
import voluptuous as vol

from .const import (
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_REFRESH_TOKEN,
    CONF_ACCESS_TOKEN,
    CONF_TOKEN_EXPIRES_AT,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_UNKNOWN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CLIENT_ID): str,
        vol.Required(CONF_CLIENT_SECRET): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_REAUTH_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_MANUAL_REAUTH_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CLIENT_ID): str,
        vol.Required(CONF_CLIENT_SECRET): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


async def validate_auth(
    hass: HomeAssistant, client_id: str, client_secret: str, username: str, password: str
) -> dict[str, Any] | None:
    """Validate the authentication credentials."""
    _LOGGER.info("Starting authentication validation")
    _LOGGER.debug("Client ID: %s", client_id)
    _LOGGER.debug("Client Secret: %s", client_secret)
    _LOGGER.debug("Username: %s", username)
    _LOGGER.debug("Password: %s", "***" if password else "EMPTY")
    
    try:
        # Create session and auth client exactly like in your working test
        session = aiohttp.ClientSession()
        try:
            _LOGGER.info("Creating SimonAuth client")
            auth_client = SimonAuth(
                client_id=client_id,
                client_secret=client_secret,
                username=username,
                password=password,
                session=session,
            )
            
            _LOGGER.info("Testing authentication by getting current user")
            # Test authentication by getting current user
            user = await User.async_get_current_user(auth_client)
            _LOGGER.info("Successfully authenticated user: %s %s", user.name, user.lastName)
            
            _LOGGER.info("Getting access token")
            # Get tokens from the auth client
            access_token = await auth_client.async_get_access_token()
            _LOGGER.info("Successfully obtained access token")
            
            # Get additional token info if available
            refresh_token = getattr(auth_client, 'refresh_token', None)
            token_expires_at = getattr(auth_client, 'token_expires_at', None)
            
            # Ensure token_expires_at is stored as a string
            if token_expires_at is not None:
                if hasattr(token_expires_at, 'isoformat'):
                    # It's a datetime object, convert to string
                    token_expires_at = token_expires_at.isoformat()
                elif not isinstance(token_expires_at, str):
                    # Convert to string if it's not already
                    token_expires_at = str(token_expires_at)
            
            _LOGGER.debug("Refresh token: %s", "Present" if refresh_token else "None")
            _LOGGER.debug("Token expires at: %s (type: %s)", token_expires_at, type(token_expires_at))
            
            return {
                "user_id": user.id,
                "user_name": f"{user.name} {user.lastName}",
                "user_email": user.email,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expires_at": token_expires_at,
            }
        finally:
            # Always close the session
            await session.close()
            
    except Exception as ex:
        _LOGGER.error("Authentication failed: %s", ex)
        _LOGGER.error("Exception type: %s", type(ex).__name__)
        import traceback
        _LOGGER.error("Traceback: %s", traceback.format_exc())
        
        if "invalid" in str(ex).lower() or "unauthorized" in str(ex).lower():
            return ERROR_INVALID_AUTH
        if "connect" in str(ex).lower() or "timeout" in str(ex).lower():
            return ERROR_CANNOT_CONNECT
        return ERROR_UNKNOWN


class SimonConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Simon iO."""

    VERSION = 1

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        """Return the options flow handler for this config entry.

        Home Assistant will call this to get the options flow instead of
        requiring a manual registration at runtime.
        """
        return SimonOptionsFlowHandler(config_entry)

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._reauth_entry: config_entries.ConfigEntry | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            _LOGGER.info("User input received in config flow")
            _LOGGER.debug("User input keys: %s", list(user_input.keys()))
            _LOGGER.debug("User input values: %s", {k: "***" if "password" in k.lower() or "secret" in k.lower() else v for k, v in user_input.items()})
            
            # Validate authentication
            auth_result = await validate_auth(
                self.hass,
                user_input[CONF_CLIENT_ID],
                user_input[CONF_CLIENT_SECRET],
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
            )

            if isinstance(auth_result, str):
                _LOGGER.error("Authentication validation failed: %s", auth_result)
                errors["base"] = auth_result
            else:
                _LOGGER.info("Authentication validation successful")
                # Store data including password temporarily for initial setup
                # Password will be removed after successful coordinator setup
                data = {
                    CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                    CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                    CONF_USERNAME: user_input[CONF_USERNAME],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],  # Temporary storage
                    CONF_ACCESS_TOKEN: auth_result["access_token"],
                    CONF_REFRESH_TOKEN: auth_result["refresh_token"],
                    CONF_TOKEN_EXPIRES_AT: auth_result["token_expires_at"],
                }
                _LOGGER.info("Storing config entry data with temporary password")
                _LOGGER.debug("Stored data keys: %s", list(data.keys()))
                _LOGGER.debug("Stored data values: %s", {k: "***" if "password" in k.lower() or "secret" in k.lower() or "token" in k.lower() else v for k, v in data.items()})

                await self.async_set_unique_id(auth_result["user_id"])
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"Simon iO ({auth_result['user_name']})",
                    data=data,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauth upon an API authentication error."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauth confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None and self._reauth_entry:
            _LOGGER.info("Re-authenticating with existing credentials")
            # Validate authentication with stored credentials and new password
            auth_result = await validate_auth(
                self.hass,
                self._reauth_entry.data[CONF_CLIENT_ID],
                self._reauth_entry.data[CONF_CLIENT_SECRET],
                self._reauth_entry.data[CONF_USERNAME],
                user_input[CONF_PASSWORD],
            )

            if isinstance(auth_result, str):
                _LOGGER.error("Re-authentication failed: %s", auth_result)
                errors["base"] = auth_result
            else:
                _LOGGER.info("Re-authentication successful")
                # Ensure token_expires_at is stored as a string
                token_expires_at = auth_result["token_expires_at"]
                if token_expires_at is not None:
                    if hasattr(token_expires_at, 'isoformat'):
                        token_expires_at = token_expires_at.isoformat()
                    elif not isinstance(token_expires_at, str):
                        token_expires_at = str(token_expires_at)
                
                # Update the entry with new tokens and temporary password
                self.hass.config_entries.async_update_entry(
                    self._reauth_entry,
                    data={
                        **self._reauth_entry.data,
                        CONF_PASSWORD: user_input[CONF_PASSWORD],  # Temporary storage
                        CONF_ACCESS_TOKEN: auth_result["access_token"],
                        CONF_REFRESH_TOKEN: auth_result["refresh_token"],
                        CONF_TOKEN_EXPIRES_AT: token_expires_at,
                    },
                )
                await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=STEP_REAUTH_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_manual_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle manual reauth with all credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            _LOGGER.info("Manual re-authentication requested")
            _LOGGER.debug("Manual reauth input keys: %s", list(user_input.keys()))
            
            # Validate authentication with new credentials
            auth_result = await validate_auth(
                self.hass,
                user_input[CONF_CLIENT_ID],
                user_input[CONF_CLIENT_SECRET],
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
            )

            if isinstance(auth_result, str):
                _LOGGER.error("Manual re-authentication failed: %s", auth_result)
                errors["base"] = auth_result
            else:
                _LOGGER.info("Manual re-authentication successful")
                # Ensure token_expires_at is stored as a string
                token_expires_at = auth_result["token_expires_at"]
                if token_expires_at is not None:
                    if hasattr(token_expires_at, 'isoformat'):
                        token_expires_at = token_expires_at.isoformat()
                    elif not isinstance(token_expires_at, str):
                        token_expires_at = str(token_expires_at)
                
                # Update the entry with new credentials and tokens
                self.hass.config_entries.async_update_entry(
                    self._reauth_entry,
                    data={
                        CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                        CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],  # Temporary storage
                        CONF_ACCESS_TOKEN: auth_result["access_token"],
                        CONF_REFRESH_TOKEN: auth_result["refresh_token"],
                        CONF_TOKEN_EXPIRES_AT: token_expires_at,
                    },
                )
                await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="manual_reauth",
            data_schema=STEP_MANUAL_REAUTH_DATA_SCHEMA,
            errors=errors,
        )


class SimonOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for Simon iO."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            if user_input.get("reauth"):
                # Trigger manual reauth flow
                return await self.async_step_manual_reauth()
            elif user_input.get("password_reauth"):
                # Trigger password-only reauth flow
                return await self.async_step_password_reauth()

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional("reauth", default=False): bool,
                    vol.Optional("password_reauth", default=False): bool,
                }
            ),
        )

    async def async_step_manual_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle manual reauth with all credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            _LOGGER.info("Manual re-authentication requested from options")
            _LOGGER.debug("Manual reauth input keys: %s", list(user_input.keys()))
            
            # Validate authentication with new credentials
            auth_result = await validate_auth(
                self.hass,
                user_input[CONF_CLIENT_ID],
                user_input[CONF_CLIENT_SECRET],
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
            )

            if isinstance(auth_result, str):
                _LOGGER.error("Manual re-authentication failed: %s", auth_result)
                errors["base"] = auth_result
            else:
                _LOGGER.info("Manual re-authentication successful")
                # Ensure token_expires_at is stored as a string
                token_expires_at = auth_result["token_expires_at"]
                if token_expires_at is not None:
                    if hasattr(token_expires_at, 'isoformat'):
                        token_expires_at = token_expires_at.isoformat()
                    elif not isinstance(token_expires_at, str):
                        token_expires_at = str(token_expires_at)
                
                # Update the entry with new credentials and tokens
                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    data={
                        CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                        CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],  # Temporary storage
                        CONF_ACCESS_TOKEN: auth_result["access_token"],
                        CONF_REFRESH_TOKEN: auth_result["refresh_token"],
                        CONF_TOKEN_EXPIRES_AT: token_expires_at,
                    },
                )
                await self.hass.config_entries.async_reload(self.config_entry.entry_id)
                return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="manual_reauth",
            data_schema=STEP_MANUAL_REAUTH_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_password_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle password-only reauth."""
        errors: dict[str, str] = {}

        if user_input is not None:
            _LOGGER.info("Password re-authentication requested from options")
            # Validate authentication with stored credentials and new password
            auth_result = await validate_auth(
                self.hass,
                self.config_entry.data[CONF_CLIENT_ID],
                self.config_entry.data[CONF_CLIENT_SECRET],
                self.config_entry.data[CONF_USERNAME],
                user_input[CONF_PASSWORD],
            )

            if isinstance(auth_result, str):
                _LOGGER.error("Password re-authentication failed: %s", auth_result)
                errors["base"] = auth_result
            else:
                _LOGGER.info("Password re-authentication successful")
                # Ensure token_expires_at is stored as a string
                token_expires_at = auth_result["token_expires_at"]
                if token_expires_at is not None:
                    if hasattr(token_expires_at, 'isoformat'):
                        token_expires_at = token_expires_at.isoformat()
                    elif not isinstance(token_expires_at, str):
                        token_expires_at = str(token_expires_at)
                
                # Update the entry with new tokens and temporary password
                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    data={
                        **self.config_entry.data,
                        CONF_PASSWORD: user_input[CONF_PASSWORD],  # Temporary storage
                        CONF_ACCESS_TOKEN: auth_result["access_token"],
                        CONF_REFRESH_TOKEN: auth_result["refresh_token"],
                        CONF_TOKEN_EXPIRES_AT: token_expires_at,
                    },
                )
                await self.hass.config_entries.async_reload(self.config_entry.entry_id)
                return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="password_reauth",
            data_schema=STEP_REAUTH_DATA_SCHEMA,
            errors=errors,
        )
