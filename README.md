# Simon iO Home Assistant Integration

A custom Home Assistant integration for Simon Series 270 smart home devices including smart blinds, lights, and switches.

## ⚠️ Important: Client Credentials Required

**This integration requires you to obtain your own Simon iO API credentials.** The integration author does not provide client IDs or secrets.

This integration is built using the [aiosimon-io](https://github.com/datakatalyst/aiosimon-io) Python library and provides a Home Assistant interface for Simon's cloud-based API.

## Features

- **Smart Blinds/Shutters**: Control position, open/close, and stop operations
- **Dimmable Lights**: On/off control and brightness adjustment
- **Switches**: On/off control for outlets and relays
- **OAuth2 Authentication**: Secure cloud-based authentication with automatic token refresh
- **Real-time Updates**: Device states update every 30 seconds
- **Multiple Installations**: Support for multiple Simon iO installations
- **Re-authentication Support**: Easy credential updates without losing configuration

## Prerequisites

Before installing this integration, you must have:

1. **Simon Series 270 devices** (blinds, lights, switches)
2. **Simon iO account** with active devices
3. **Simon iO API credentials**:
   - Client ID
   - Client Secret
   - Username (your Simon iO account email)
   - Password (your Simon iO account password)

## Installation

### Method 1: Manual Installation

1. Download this repository
2. Copy the `custom_components/simon_io` folder to your Home Assistant `custom_components` directory
3. Restart Home Assistant
4. Go to **Settings** > **Devices & Services** > **Add Integration**
5. Search for "Simon iO" and follow the setup wizard

### Method 2: HACS Installation (Coming Soon)

This integration will be available through HACS (Home Assistant Community Store) in the future.

## Configuration

### Setup Process

1. **Add Integration**: Go to Settings > Devices & Services > Add Integration
2. **Search**: Look for "Simon iO" in the integration list
3. **Enter Credentials**: Provide your Client ID, Client Secret, Username, and Password
4. **Authentication**: The integration will authenticate with Simon iO API
5. **Device Discovery**: Your Simon devices will be automatically discovered and added

### Security Notes

- **Password Storage**: Your password is only used during initial authentication and re-authentication
- **Token Management**: The integration stores only refresh tokens, not passwords
- **Re-authentication**: If tokens expire, you'll be prompted to re-enter your password

## Re-authentication

The integration supports multiple ways to update credentials:

### Automatic Re-authentication
- Triggered automatically when tokens expire
- Prompts for password only (uses stored client credentials)

### Manual Re-authentication
- Update all credentials (Client ID, Secret, Username, Password)
- Access via: Settings > Devices & Services > Simon iO > Configure

### Password-Only Update
- Update just your password
- Access via: Settings > Devices & Services > Simon iO > Options

## Supported Devices

### Smart Blinds/Shutters
- Position control (0-100%)
- Open/Close commands
- Stop functionality
- Real-time position feedback

### Dimmable Lights
- On/Off control
- Brightness adjustment (0-100%)
- Automatic brightness scaling

### Switches
- On/Off control for outlets
- Relay control
- Simple binary state management

## Device Types

The integration automatically detects device types based on Simon iO device capabilities:

- **Covers**: Devices with level control (blinds, shutters)
- **Lights**: Devices with brightness capability
- **Switches**: Devices with on/off capability only

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:

1. **Check Credentials**: Verify your Client ID, Client Secret, Username, and Password
2. **Re-authenticate**: Use the integration's re-authentication options
3. **Check Network**: Ensure Home Assistant can reach Simon iO API
4. **Contact Simon Support**: If credentials are invalid or expired

### Device Not Appearing

If devices don't appear:

1. **Check Installation**: Verify your Simon iO installation is properly configured
2. **Device Capabilities**: Ensure devices have the required capabilities
3. **Logs**: Check Home Assistant logs for error messages

### Performance Issues

If you experience slow updates:

1. **Update Interval**: The default update interval is 30 seconds
2. **Network**: Check your internet connection speed
3. **API Limits**: Simon iO may have API rate limits

## Logs

To enable debug logging, add this to your `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.simon_io: debug
```

## Development

### Requirements

- Python 3.9+
- Home Assistant 2023.1+
- aiosimon-io library

### Local Development

1. Clone this repository
2. Copy to your Home Assistant `custom_components` directory
3. Install dependencies: `pip install aiosimon-io`
4. Restart Home Assistant

### Testing

Test the integration with:

1. **Unit Tests**: Run `pytest tests/`
2. **Integration Tests**: Test with real Simon devices
3. **Manual Testing**: Verify all device operations work correctly

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This integration is not officially endorsed by Simon S.A. It is an independent project using the [aiosimon-io](https://github.com/datakatalyst/aiosimon-io) library.

**Important**: This integration requires users to obtain their own Simon iO API credentials. The author does not provide client IDs or secrets.

## Support

For support and questions:

1. **Issues**: Open an issue on GitHub
2. **Discussions**: Use GitHub Discussions
3. **Documentation**: Check this README and code comments

## Changelog

### Version 1.0.0
- Initial release
- Support for Simon Series 270 devices
- OAuth2 authentication
- Cover, Light, and Switch platforms
- Automatic device discovery
- Real-time state updates
- Re-authentication support
- Enhanced cover platform with full position control
