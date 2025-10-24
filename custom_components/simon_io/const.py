"""Constants for the Simon iO integration."""

DOMAIN = "simon_io"

# Configuration keys
CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_ACCESS_TOKEN = "access_token"
CONF_TOKEN_EXPIRES_AT = "token_expires_at"

# Platform names
PLATFORMS = ["cover", "light", "switch"]

# Update intervals
UPDATE_INTERVAL = 30  # seconds
TOKEN_REFRESH_BUFFER = 300  # seconds before expiry to refresh token

# Device capabilities
CAPABILITY_BRIGHTNESS = "brightness"
CAPABILITY_ON_OFF = "on_off"
CAPABILITY_LEVEL = "level"
CAPABILITY_STOP = "stop"

# Device types
DEVICE_TYPE_COVER = "cover"
DEVICE_TYPE_LIGHT = "light"
DEVICE_TYPE_SWITCH = "switch"

# Error messages
ERROR_INVALID_AUTH = "invalid_auth"
ERROR_CANNOT_CONNECT = "cannot_connect"
ERROR_UNKNOWN = "unknown"
