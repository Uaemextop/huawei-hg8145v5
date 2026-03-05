"""
Session lifecycle management for authenticated operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from motorola_firmware.authenticator import Authenticator, AuthenticationError
from motorola_firmware.logger import get_logger


class SessionManager:
    """Track and refresh authenticated sessions."""

    def __init__(self, authenticator: Authenticator) -> None:
        self.authenticator = authenticator
        self.logger = get_logger(__name__)
        self._active = False
        self._started_at: Optional[datetime] = None

    def start_session(self) -> None:
        """Start a session, refreshing the token if required."""
        try:
            if not self.authenticator.validate_token():
                self.logger.info("Token invalid or expired; refreshing")
                self.authenticator.refresh_token()
            self._active = True
            self._started_at = datetime.now(timezone.utc)
            self.logger.info("Session started")
        except AuthenticationError as exc:
            self._active = False
            self.logger.error("Failed to start session: %s", exc)
            raise

    def end_session(self) -> None:
        """Mark session as inactive."""
        self._active = False
        self.logger.info("Session ended")

    def is_active(self) -> bool:
        """Return True if a session is active."""
        return self._active

    def get_session_info(self) -> Dict[str, object]:
        """Return details about the current session."""
        return {
            "active": self._active,
            "started_at": self._started_at.isoformat() if self._started_at else "",
            "expires_at": self._expires_at(),
        }

    def refresh_if_needed(self) -> None:
        """Refresh token when nearing expiry."""
        if not self._active:
            return
        if self.authenticator.is_token_expired():
            self.logger.info("Token nearing expiry; refreshing")
            self.authenticator.refresh_token()

    def _expires_at(self) -> str:
        if self.authenticator._token_expiry:  # noqa: SLF001
            return self.authenticator._token_expiry.isoformat()
        return ""
