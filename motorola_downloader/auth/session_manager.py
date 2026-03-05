"""Session management module for Motorola Firmware Downloader.

Manages the lifecycle of authenticated sessions including starting,
ending, refreshing, and monitoring session state.
"""

import time
from typing import Any, Dict, Optional

from motorola_downloader.auth.authenticator import Authenticator
from motorola_downloader.exceptions import SessionError
from motorola_downloader.settings import Settings
from motorola_downloader.utils.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)


class SessionManager:
    """Manages authenticated session lifecycle.

    Wraps the Authenticator to provide session-level operations including
    automatic token refresh, session state tracking, and graceful
    session termination.

    Args:
        settings: Application settings instance.
        http_client: Optional HTTP client to share across components.
    """

    def __init__(
        self,
        settings: Settings,
        http_client: Optional[HTTPClient] = None,
    ) -> None:
        """Initialize the SessionManager.

        Args:
            settings: Application settings for session configuration.
            http_client: Optional shared HTTP client instance.
        """
        self._settings = settings
        self._http_client = http_client or HTTPClient(
            timeout=settings.get_int("download", "timeout", fallback=30)
        )
        self._authenticator = Authenticator(settings, self._http_client)
        self.logger = get_logger(__name__)

        self._active: bool = False
        self._session_start_time: float = 0.0
        self._last_activity_time: float = 0.0

    def start_session(self) -> bool:
        """Start an authenticated session.

        Attempts to validate existing tokens or authenticate with stored
        credentials. Must be called before performing any authenticated
        operations.

        Returns:
            True if the session was started successfully.

        Raises:
            SessionError: If the session cannot be started.
        """
        self.logger.info("Starting session...")

        try:
            # First, try existing token
            if self._authenticator.validate_token():
                self._active = True
                self._session_start_time = time.time()
                self._last_activity_time = time.time()
                self.logger.info("Session started with existing valid token")
                return True

            # Try refreshing
            guid = self._settings.get("motorola_server", "guid", fallback="")
            if guid:
                try:
                    if self._authenticator.refresh_token():
                        self._active = True
                        self._session_start_time = time.time()
                        self._last_activity_time = time.time()
                        self.logger.info("Session started with refreshed token")
                        return True
                except Exception:
                    self.logger.info("Token refresh failed, new auth required")

            # Need fresh authentication
            if guid:
                if self._authenticator.authenticate(guid):
                    self._active = True
                    self._session_start_time = time.time()
                    self._last_activity_time = time.time()
                    self.logger.info("Session started with fresh authentication")
                    return True

            self.logger.warning(
                "No GUID configured. Please set GUID in config.ini or authenticate manually"
            )
            return False

        except Exception as exc:
            self.logger.error("Failed to start session: %s", exc)
            raise SessionError(f"Session start failed: {exc}") from exc

    def end_session(self) -> None:
        """End the current session and clean up resources.

        Closes the HTTP client connection and marks the session as inactive.
        """
        if self._active:
            duration = time.time() - self._session_start_time
            self.logger.info(
                "Ending session (duration: %.1f seconds)", duration
            )

        self._active = False
        self._session_start_time = 0.0
        self._last_activity_time = 0.0

        try:
            self._http_client.close()
        except Exception as exc:
            self.logger.warning("Error closing HTTP client: %s", exc)

        self.logger.info("Session ended")

    def is_active(self) -> bool:
        """Check if the current session is active and authenticated.

        Returns:
            True if the session is active with a valid token.
        """
        if not self._active:
            return False

        if self._authenticator.is_token_expired():
            self.logger.info("Session token expired, session no longer active")
            self._active = False
            return False

        return True

    def get_session_info(self) -> Dict[str, Any]:
        """Get information about the current session.

        Returns:
            Dictionary containing session state information.
        """
        info: Dict[str, Any] = {
            "active": self._active,
            "guid": self._authenticator.guid,
            "has_token": self._authenticator.token is not None,
            "session_duration": 0.0,
            "last_activity": 0.0,
        }

        if self._active and self._session_start_time > 0:
            info["session_duration"] = time.time() - self._session_start_time
        if self._last_activity_time > 0:
            info["last_activity"] = time.time() - self._last_activity_time

        return info

    def refresh_if_needed(self) -> bool:
        """Refresh the session token if it is near expiration.

        Checks the auto_refresh setting and token expiration threshold
        before attempting a refresh.

        Returns:
            True if no refresh was needed or refresh was successful.
        """
        auto_refresh = self._settings.get_bool(
            "authentication", "auto_refresh", fallback=True
        )

        if not auto_refresh:
            return True

        if not self._authenticator.is_token_expired():
            self._last_activity_time = time.time()
            return True

        self.logger.info("Token near expiration, attempting refresh")

        try:
            success = self._authenticator.refresh_token()
            if success:
                self._last_activity_time = time.time()
                self.logger.info("Session token refreshed successfully")
            return success
        except Exception as exc:
            self.logger.error("Session token refresh failed: %s", exc)
            self._active = False
            return False

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for the current session.

        Automatically refreshes the token if needed before returning headers.

        Returns:
            Dictionary of HTTP headers with authentication.

        Raises:
            SessionError: If the session is not active.
        """
        if not self._active:
            raise SessionError("Session is not active. Call start_session() first")

        self.refresh_if_needed()
        self._last_activity_time = time.time()

        return self._authenticator.get_headers()

    @property
    def authenticator(self) -> Authenticator:
        """Get the underlying Authenticator instance.

        Returns:
            The Authenticator used by this session.
        """
        return self._authenticator

    @property
    def http_client(self) -> HTTPClient:
        """Get the shared HTTP client instance.

        Returns:
            The HTTPClient used by this session.
        """
        return self._http_client
