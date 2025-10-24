#!/usr/bin/env python3
"""Test script to debug Simon iO authentication."""

import asyncio
import aiohttp
import logging
from aiosimon_io import SimonAuth, User

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def test_simon_auth():
    """Test Simon iO authentication."""
    # Replace these with your actual credentials
    CLIENT_ID = "your_client_id"
    CLIENT_SECRET = "your_client_secret"
    USERNAME = "your_username"
    PASSWORD = "your_password"
    
    logger.info("Starting Simon iO authentication test")
    logger.info("Client ID: %s", CLIENT_ID)
    logger.info("Client Secret: %s", CLIENT_SECRET)
    logger.info("Username: %s", USERNAME)
    logger.info("Password: %s", "***" if PASSWORD else "EMPTY")
    
    try:
        async with aiohttp.ClientSession() as session:
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
            logger.info("User email: %s", user.email)
            logger.info("User ID: %s", user.id)
            
            logger.info("Getting access token")
            access_token = await auth_client.async_get_access_token()
            logger.info("Successfully obtained access token: %s", access_token[:20] + "...")
            
            logger.info("Authentication test completed successfully!")
            
    except Exception as ex:
        logger.error("Authentication test failed: %s", ex)
        logger.error("Exception type: %s", type(ex).__name__)
        import traceback
        logger.error("Traceback: %s", traceback.format_exc())

if __name__ == "__main__":
    print("Simon iO Authentication Test")
    print("=" * 40)
    print("Please update the credentials in this script before running")
    print("=" * 40)
    
    # Uncomment the line below to run the test
    # asyncio.run(test_simon_auth())
    
    print("To run the test:")
    print("1. Update the credentials in this script")
    print("2. Uncomment the asyncio.run() line")
    print("3. Run: python test_auth.py")
