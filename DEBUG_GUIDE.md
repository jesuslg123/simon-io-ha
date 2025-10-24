# Simon iO Integration Debug Guide

## Enable Debug Logging

To see detailed logs of what's happening during authentication, add this to your Home Assistant `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.simon_io: debug
    aiosimon_io: debug
    aiosimon_io.auth: debug
```

## What to Look For

When you try to set up the integration again, look for these log messages:

### 1. Config Flow Logs
- `"Starting authentication validation"`
- `"Creating SimonAuth client"`
- `"Testing authentication by getting current user"`
- `"Successfully authenticated user: ..."`
- `"Getting access token"`
- `"Successfully obtained access token"`

### 2. Coordinator Setup Logs
- `"Setting up Simon iO integration"`
- `"Password found in config entry: YES/NO"`
- `"Setting password in coordinator"`
- `"Starting coordinator setup"`
- `"Ensuring auth client is available"`
- `"Creating new SimonAuth client"`
- `"Testing auth client by getting access token"`
- `"Auth client test successful, token obtained"`

### 3. Data Update Logs
- `"Starting data update"`
- `"Auth client ensured, proceeding with data fetch"`
- `"Fetching installations from Simon iO"`
- `"Successfully fetched X installations"`

## Common Issues to Check

### Issue 1: Password Not Being Passed
If you see:
```
Password found in config entry: NO
```
This means the password wasn't stored during config flow.

### Issue 2: Auth Client Creation Fails
If you see:
```
Failed to create or test SimonAuth client: ...
```
This means there's an issue with the SimonAuth constructor or the credentials.

### Issue 3: Token Request Fails
If you see the original error:
```
Authentication failed: 400 {"error":"invalid_request","detail":"Missing parameters. \"username\" and \"password\" required"}
```
This means the SimonAuth isn't passing the credentials correctly to the API.

## Next Steps

1. **Enable debug logging** as shown above
2. **Restart Home Assistant** to apply the logging configuration
3. **Try to add the integration again** through the UI
4. **Check the logs** in Home Assistant (Settings > System > Logs)
5. **Look for the specific log messages** mentioned above
6. **Share the relevant log entries** so we can identify the exact issue

## Quick Test

You can also test the authentication directly by running the test script:

1. Update `test_auth.py` with your actual credentials
2. Uncomment the `asyncio.run(test_auth())` line
3. Run: `python test_auth.py`

This will help confirm if the issue is with the library itself or with our integration.
