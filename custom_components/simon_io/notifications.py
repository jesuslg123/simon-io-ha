"""Notification helper for Simon iO integration.

Centralizes Home Assistant persistent notifications to keep __init__ tidy.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from .const import DOMAIN


class SimonIoNotifications:
    """Helper for creating/dismissing persistent notifications."""

    LOCKOUT_ID = f"{DOMAIN}_lockout"
    REAUTH_ID = f"{DOMAIN}_reauth_required"

    @staticmethod
    def notify_lockout(hass: Any, until: datetime) -> None:
        """Notify user that account is locked until the given datetime.

        Uses translations if available; falls back to English.
        """
        async def _do() -> None:
            try:
                lang = getattr(getattr(hass, "config", None), "language", "en") or "en"
                translations = await hass.helpers.translation.async_get_translations(
                    lang, category="component", integrations={DOMAIN}
                )
                title = translations.get(
                    f"component.{DOMAIN}.notification.lockout.title",
                    "Simon iO: Account locked",
                )
                message_tmpl = translations.get(
                    f"component.{DOMAIN}.notification.lockout.message",
                    (
                        "The Simon iO cloud has locked your account due to too many failed login attempts. "
                        "The integration will pause retries until {until} and then try again. "
                        "If you recently changed your password, open the Simon iO integration and re-authenticate."
                    ),
                )
                message = message_tmpl.replace("{until}", until.isoformat())
            except Exception:
                title = "Simon iO: Account locked"
                message = (
                    "The Simon iO cloud has locked your account due to too many failed login attempts. "
                    f"The integration will pause retries until {until.isoformat()} and then try again. "
                    "If you recently changed your password, open the Simon iO integration and re-authenticate."
                )
            try:
                hass.components.persistent_notification.async_create(
                    message,
                    title=title,
                    notification_id=SimonIoNotifications.LOCKOUT_ID,
                )
            except Exception:
                pass

        hass.async_create_task(_do())

    @staticmethod
    def dismiss_lockout(hass: Any) -> None:
        """Dismiss the lockout notification, if present."""
        try:
            hass.components.persistent_notification.async_dismiss(
                SimonIoNotifications.LOCKOUT_ID
            )
        except Exception:
            pass

    @staticmethod
    def notify_reauth_required(hass: Any) -> None:
        """Notify user that reauthentication is required (localized)."""
        async def _do() -> None:
            try:
                lang = getattr(getattr(hass, "config", None), "language", "en") or "en"
                translations = await hass.helpers.translation.async_get_translations(
                    lang, category="component", integrations={DOMAIN}
                )
                title = translations.get(
                    f"component.{DOMAIN}.notification.reauth_required.title",
                    "Simon iO: Reauthentication required",
                )
                message = translations.get(
                    f"component.{DOMAIN}.notification.reauth_required.message",
                    (
                        "Simon iO credentials are missing, invalid, or expired. "
                        "Please open the Simon iO integration in Home Assistant and re-authenticate to restore connectivity."
                    ),
                )
            except Exception:
                title = "Simon iO: Reauthentication required"
                message = (
                    "Simon iO credentials are missing, invalid, or expired. "
                    "Please open the Simon iO integration in Home Assistant and re-authenticate to restore connectivity."
                )
            try:
                hass.components.persistent_notification.async_create(
                    message,
                    title=title,
                    notification_id=SimonIoNotifications.REAUTH_ID,
                )
            except Exception:
                pass

        hass.async_create_task(_do())

    @staticmethod
    def dismiss_reauth_required(hass: Any) -> None:
        """Dismiss the reauthentication notification, if present."""
        try:
            hass.components.persistent_notification.async_dismiss(
                SimonIoNotifications.REAUTH_ID
            )
        except Exception:
            pass
