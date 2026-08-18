#!/usr/bin/env python3
"""Unit tests for HA-independent authentication helpers."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

_HELPERS_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "simon_io"
    / "auth_helpers.py"
)
_SPEC = importlib.util.spec_from_file_location("simon_io_auth_helpers", str(_HELPERS_PATH))
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)  # type: ignore[attr-defined]

async_refresh_token = _MODULE.async_refresh_token


class FakeAuthClient:
    """Record which SimonAuth token method is used."""

    def __init__(self) -> None:
        self.access_token = "existing-access-token"
        self.get_calls = 0
        self.refresh_calls = 0

    async def async_get_access_token(self) -> str:
        self.get_calls += 1
        return self.access_token

    async def async_refresh_access_token(self) -> None:
        self.refresh_calls += 1


class TestAuthHelpers(unittest.IsolatedAsyncioTestCase):
    async def test_forced_refresh_uses_refresh_grant_and_preserves_access_token(self):
        client = FakeAuthClient()

        await async_refresh_token(client, force=True)

        self.assertEqual(client.refresh_calls, 1)
        self.assertEqual(client.get_calls, 0)
        self.assertEqual(client.access_token, "existing-access-token")

    async def test_normal_refresh_uses_library_token_selection(self):
        client = FakeAuthClient()

        await async_refresh_token(client, force=False)

        self.assertEqual(client.get_calls, 1)
        self.assertEqual(client.refresh_calls, 0)


if __name__ == "__main__":
    unittest.main()
