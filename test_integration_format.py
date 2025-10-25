#!/usr/bin/env python3
"""Test script to verify Simon iO credentials in Home Assistant integration format."""

import asyncio
import aiohttp
import logging
from aiosimon_io import SimonAuth, User

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Your actual credentials from the test
CLIENT_ID = "2_3qwwln2ghyiok8gw4844088cwwswg884o08s84wggk8g80occc"
CLIENT_SECRET = "4rmn5137sbgg0os0sog40sksgsoc8okckw00csogkssgg4scw4"
USERNAME = "jesuslg123@gmail.com"
PASSWORD = "your_password_here"  # Replace with your actual password

async def test_integration_format():
    """Test authentication using the same format as our integration."""
    logger.info("Testing Simon iO authentication in integration format")
    
    # Simulate the validate_auth function from our integration
    try:
        session = aiohttp.ClientSession()
        try:
            logger.info("Creating SimonAuth client")
            auth_client = SimonAuth(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                username=USERNAME,
                password=PASSWORD,
                session=session,
            )
            
            logger.info("Testing authentication by getting current user")
            user = await User.async_get_current_user(auth_client)
            logger.info("Successfully authenticated user: %s %s", user.name, user.lastName)
            
            logger.info("Getting access token")
            access_token = await auth_client.async_get_access_token()
            logger.info("Successfully obtained access token")
            
            # Get additional token info if available
            refresh_token = getattr(auth_client, 'refresh_token', None)
            token_expires_at = getattr(auth_client, 'token_expires_at', None)
            
            logger.debug("Refresh token: %s", "Present" if refresh_token else "None")
            logger.debug("Token expires at: %s", token_expires_at)
            
            result = {
                "user_id": user.id,
                "user_name": f"{user.name} {user.lastName}",
                "user_email": user.email,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expires_at": token_expires_at,
            }
            
            logger.info("Integration format test completed successfully!")
            logger.info("Result keys: %s", list(result.keys()))
            return result
            
        finally:
            await session.close()
            
    except Exception as ex:
        logger.error("Integration format test failed: %s", ex)
        logger.error("Exception type: %s", type(ex).__name__)
        import traceback
        logger.error("Traceback: %s", traceback.format_exc())
        return None

if __name__ == "__main__":
    print("Simon iO Integration Format Test")
    print("=" * 50)
    print("This test uses the exact same format as our Home Assistant integration")
    print("=" * 50)
    
    # Update the password above before running
    if PASSWORD == "your_password_here":
        print("Please update the PASSWORD variable with your actual password")
        print("Then uncomment the line below to run the test")
    else:
        print("Running integration format test...")
        result = asyncio.run(test_integration_format())
        if result:
            print("✅ Test passed! The integration format works correctly.")
        else:
            print("❌ Test failed! There's an issue with the integration format.")
