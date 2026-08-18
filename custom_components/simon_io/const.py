"""Constants for the Simon iO integration."""

DOMAIN = "simon"

# Configuration keys
CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_ACCESS_TOKEN = "access_token"
CONF_TOKEN_EXPIRES_AT = "token_expires_at"
CONF_LOCKOUT_UNTIL = "lockout_until"

# Platform names
PLATFORMS = ["cover", "light", "switch"]

# Update intervals
UPDATE_INTERVAL = 36  # seconds
UPDATE_INTERVAL_JITTER = 5  # seconds - random variation to add/subtract from UPDATE_INTERVAL
TOKEN_REFRESH_BUFFER = 0  # aiosimon_io already applies its own 500-second safety margin
RETRY_DELAY_SECONDS = 2  # delay between retries after refresh/errors
LOCKOUT_COOLDOWN_CHECK_INTERVAL = 3600  # seconds to wait between checks while locked out
AUTH_FAILURE_COOLDOWN_SECONDS = 3600  # minimum pause after a failed auth request

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
