# Simon iO Integration Debug Checklist

## Current Status
✅ **Library Test**: Confirmed working with your credentials  
❌ **Integration Test**: Still failing with 400 error  

## Debugging Steps

### Step 1: Enable Debug Logging
Add this to your `configuration.yaml`:
```yaml
logger:
  default: info
  logs:
    custom_components.simon_io: debug
    aiosimon_io: debug
    aiosimon_io.auth: debug
```

### Step 2: Test Integration Format
1. Update `test_integration_format.py` with your actual password
2. Run: `python test_integration_format.py`
3. This will confirm if our integration's authentication format works

### Step 3: Check Home Assistant Logs
When you try to add the integration, look for these specific log messages:

#### Config Flow Logs (Should appear first):
```
INFO:custom_components.simon_io.config_flow:User input received in config flow
DEBUG:custom_components.simon_io.config_flow:User input keys: ['client_id', 'client_secret', 'username', 'password']
DEBUG:custom_components.simon_io.config_flow:User input values: {'client_id': '2_3qwwln2ghyiok8gw4844088cwwswg884o08s84wggk8g80occc', 'client_secret': '***', 'username': 'jesuslg123@gmail.com', 'password': '***'}
INFO:custom_components.simon_io.config_flow:Starting authentication validation
INFO:custom_components.simon_io.config_flow:Creating SimonAuth client
INFO:custom_components.simon_io.config_flow:Testing authentication by getting current user
INFO:custom_components.simon_io.config_flow:Successfully authenticated user: Jesus Lopez
INFO:custom_components.simon_io.config_flow:Getting access token
INFO:custom_components.simon_io.config_flow:Successfully obtained access token
INFO:custom_components.simon_io.config_flow:Authentication validation successful
INFO:custom_components.simon_io.config_flow:Storing config entry data with temporary password
```

#### Coordinator Setup Logs (Should appear after config flow):
```
INFO:custom_components.simon_io:Setting up Simon iO integration
DEBUG:custom_components.simon_io:Config entry data keys: ['client_id', 'client_secret', 'username', 'password', 'access_token', 'refresh_token', 'token_expires_at']
DEBUG:custom_components.simon_io:Config entry data values: {'client_id': '2_3qwwln2ghyiok8gw4844088cwwswg884o08s84wggk8g80occc', 'client_secret': '***', 'username': 'jesuslg123@gmail.com', 'password': '***', 'access_token': '***', 'refresh_token': '***', 'token_expires_at': '***'}
INFO:custom_components.simon_io:Password found in config entry: YES
INFO:custom_components.simon_io:Setting password in coordinator
DEBUG:custom_components.simon_io:Password length: X characters
INFO:custom_components.simon_io:Starting coordinator setup
INFO:custom_components.simon_io:Ensuring auth client is available
INFO:custom_components.simon_io:Creating new SimonAuth client
DEBUG:custom_components.simon_io:Using stored credentials for SimonAuth
DEBUG:custom_components.simon_io:Client ID: 2_3qwwln2ghyiok8gw4844088cwwswg884o08s84wggk8g80occc
DEBUG:custom_components.simon_io:Client Secret: ***
DEBUG:custom_components.simon_io:Username: jesuslg123@gmail.com
DEBUG:custom_components.simon_io:Password: ***
INFO:custom_components.simon_io:SimonAuth client created successfully
INFO:custom_components.simon_io:Testing auth client by getting access token
INFO:custom_components.simon_io:Auth client test successful, token obtained
```

## Potential Issues to Look For

### Issue 1: Config Flow Fails
If you see the 400 error during config flow:
- **Problem**: The `validate_auth` function isn't working
- **Solution**: Check if the integration format test passes

### Issue 2: Password Not Stored
If you see:
```
INFO:custom_components.simon_io:Password found in config entry: NO
```
- **Problem**: Password isn't being stored in config entry
- **Solution**: Check config flow logs for storage issues

### Issue 3: Password Not Retrieved
If you see:
```
DEBUG:custom_components.simon_io:Password: EMPTY
```
- **Problem**: Password isn't being retrieved from config entry
- **Solution**: Check config entry data logs

### Issue 4: Auth Client Creation Fails
If you see:
```
ERROR:custom_components.simon_io:Failed to create or test SimonAuth client: ...
```
- **Problem**: SimonAuth constructor or test fails
- **Solution**: Check if credentials are being passed correctly

### Issue 5: Data Update Fails
If you see the 400 error during data update:
- **Problem**: The auth client isn't working during normal operation
- **Solution**: Check if password cleanup is happening too early

## Next Steps

1. **Run the integration format test** to confirm our authentication format works
2. **Enable debug logging** and try adding the integration
3. **Check the logs** for the specific messages above
4. **Identify which step fails** and share the relevant log entries

The enhanced logging will show us exactly where the issue occurs!
