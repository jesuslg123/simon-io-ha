"""Home Assistant-independent authentication helpers for Simon iO."""
from __future__ import annotations

from typing import Any


async def async_refresh_token(auth_client: Any, *, force: bool) -> None:
    """Refresh through the correct library flow without clearing the token.

    SimonAuth treats a missing access token as a request for password
    authentication. Forced refreshes must therefore call its explicit refresh
    token method while leaving the current access token intact.
    """
    if force:
        await auth_client.async_refresh_access_token()
    else:
        await auth_client.async_get_access_token()
