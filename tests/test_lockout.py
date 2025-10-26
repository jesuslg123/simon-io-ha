#!/usr/bin/env python3
"""Unit tests for lockout parsing helper."""
from __future__ import annotations

import unittest
import importlib.util
from pathlib import Path

# Import the helper module directly from file to avoid importing the HA package
_LOCKOUT_PATH = Path(__file__).resolve().parents[1] / "custom_components" / "simon_io" / "lockout.py"
_SPEC = importlib.util.spec_from_file_location("simon_io_lockout", str(_LOCKOUT_PATH))
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)  # type: ignore[attr-defined]

extract_lockout_seconds = _MODULE.extract_lockout_seconds


class TestLockoutParsing(unittest.TestCase):
    def test_extracts_seconds_from_message(self):
        msg = (
            'Authentication failed: 401 {"error":"invalid_grant","detail":"Too many failed login attempts, '
            'please try in 271579934 seconds.","status":401,"type":"about:blank","title":"Unauthorized","origin":"cloud"}'
        )
        self.assertEqual(extract_lockout_seconds(msg), 271579934)

    def test_case_insensitive_and_spaces(self):
        msg = "too MANY failed login attempts, please try in 123 seconds"
        self.assertEqual(extract_lockout_seconds(msg), 123)

    def test_no_match_returns_none(self):
        self.assertIsNone(extract_lockout_seconds("some other error"))
        self.assertIsNone(extract_lockout_seconds("Too many attempts, try later"))
        self.assertIsNone(extract_lockout_seconds(""))

    def test_non_integer_is_none(self):
        msg = "Too many failed login attempts, please try in xx seconds"
        self.assertIsNone(extract_lockout_seconds(msg))


if __name__ == "__main__":
    unittest.main()
