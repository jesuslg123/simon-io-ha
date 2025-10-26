"""Helpers for detecting server lockout responses (HA-independent)."""
from __future__ import annotations

import re
from typing import Optional

_LOCKOUT_REGEX = re.compile(
    r"Too many failed login attempts, please try in (\d+) seconds",
    re.IGNORECASE,
)


def extract_lockout_seconds(message: str) -> Optional[int]:
    """Parse lockout seconds from an error message.

    Expected snippet:
    "Too many failed login attempts, please try in 271579934 seconds."
    Returns None when not present or not parseable.
    """
    match = _LOCKOUT_REGEX.search(message or "")
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None
