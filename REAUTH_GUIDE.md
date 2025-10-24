# Simon iO Re-authentication Guide

## Overview

The Simon iO integration now supports multiple ways to re-authenticate and update credentials without removing and re-adding the entire integration.

## Re-authentication Options

### 1. **Automatic Re-authentication**
- **When it happens**: Automatically triggered when tokens expire
- **What it does**: Prompts for password only (uses stored client credentials)
- **User action**: Enter your password when prompted

### 2. **Manual Re-authentication** 
- **When to use**: When you want to update all credentials (client ID, secret, username, password)
- **What it does**: Allows you to enter completely new credentials
- **User action**: Go to integration options and select "Re-authenticate with new credentials"

### 3. **Password-Only Update**
- **When to use**: When you only need to update your password
- **What it does**: Updates password while keeping existing client credentials
- **User action**: Go to integration options and select "Update password only"

## How to Access Re-authentication

### Method 1: Through Integration Settings

1. **Go to Settings** → **Devices & Services**
2. **Find "Simon iO"** in your integrations list
3. **Click on the integration** to open its details
4. **Click "Configure"** (gear icon) in the top right
5. **Select your re-authentication option**:
   - ✅ **"Re-authenticate with new credentials"** - Update all credentials
   - ✅ **"Update password only"** - Update just the password

### Method 2: Through Integration Options

1. **Go to Settings** → **Devices & Services**
2. **Find "Simon iO"** in your integrations list
3. **Click the three dots menu** (⋮) next to the integration
4. **Select "Options"**
5. **Choose your re-authentication method**

## Re-authentication Scenarios

### Scenario 1: Password Changed
**Use**: Password-Only Update
1. Go to integration options
2. Select "Update password only"
3. Enter your new password
4. Integration will update automatically

### Scenario 2: New Simon iO App Credentials
**Use**: Manual Re-authentication
1. Go to integration options
2. Select "Re-authenticate with new credentials"
3. Enter your new:
   - Client ID
   - Client Secret
   - Username
   - Password
4. Integration will update automatically

### Scenario 3: Token Expired
**Use**: Automatic Re-authentication
1. Home Assistant will automatically prompt you
2. Enter your current password
3. Integration will refresh tokens automatically

## Security Features

### ✅ **Password Security**
- Passwords are only stored temporarily during setup/re-auth
- Passwords are automatically removed after successful authentication
- Passwords are never permanently stored in configuration

### ✅ **Token Management**
- Access tokens are automatically refreshed
- Refresh tokens are stored securely
- Token expiry is monitored and handled automatically

### ✅ **Credential Validation**
- All credentials are validated before saving
- Authentication is tested during re-auth process
- Invalid credentials are rejected with clear error messages

## Troubleshooting

### Re-authentication Fails
1. **Check your credentials** - Ensure they're correct
2. **Check your internet connection** - Simon iO API must be accessible
3. **Check Simon iO service status** - Service might be down
4. **Try manual re-authentication** - Use the full credential update

### Integration Not Responding
1. **Restart Home Assistant** - Sometimes needed after re-auth
2. **Check logs** - Look for authentication errors
3. **Remove and re-add integration** - Last resort option

### Credentials Not Updating
1. **Wait a few minutes** - Changes can take time to propagate
2. **Check integration status** - Should show "Connected"
3. **Test device control** - Try controlling a Simon device

## Benefits

### ✅ **No Data Loss**
- Device configurations are preserved
- Automation rules remain intact
- Entity names and settings are maintained

### ✅ **Convenient Updates**
- No need to remove and re-add integration
- Quick password updates
- Easy credential management

### ✅ **Automatic Handling**
- Token expiry handled automatically
- Seamless re-authentication
- Minimal user intervention required

## Best Practices

1. **Keep credentials secure** - Don't share your Simon iO credentials
2. **Update passwords regularly** - For security best practices
3. **Test after re-auth** - Verify devices are working correctly
4. **Monitor integration status** - Check for any issues after updates

The re-authentication system makes it easy to maintain your Simon iO integration without losing your configuration! 🎉
