"""
Session manager for the Motorola Firmware Downloader.

Manages the lifecycle of authenticated sessions — start, end, refresh,
and status checking.  Wraps :class:`Authenticator` so that callers do
not need to interact with token mechanics directly.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from motorola_firmware.authenticator import Authenticator
from motorola_firmware.exceptions import AuthenticationError, SessionError
from motorola_firmware.http_client import HttpClient
from motorola_firmware.settings import Settings
from motorola_firmware.utils.logger import log


class SessionManager:
    """Manages authenticated session lifecycle with Motorola servers.

    Provides high-level ``start_session`` / ``end_session`` semantics on
    top of the lower-level :class:`Authenticator` token mechanics.

    Args:
        settings: Application settings instance.
        authenticator: Authenticator instance for token management.
        http_client: HTTP client for session-related requests.
    """

    def __init__(
        self,
        settings: Settings,
        authenticator: Authenticator,
        http_client: HttpClient,
    ) -> None:
        """Initialize the session manager.

        Args:
            settings: Application settings instance.
            authenticator: Authenticator for JWT management.
            http_client: HTTP client for network operations.
        """
        self._settings = settings
        self._authenticator = authenticator
        self._http_client = http_client
        self._active = False
        self._session_start_time: Optional[float] = None

    # ── Public API ─────────────────────────────────────────────────

    def start_session(self) -> bool:
        """Start an authenticated session.

        Validates the current token or initiates a refresh if needed.

        Returns:
            True if session started successfully.

        Raises:
            SessionError: If session cannot be established.
        """
        log.info("[SESSION] Starting session …")

        try:
            if self._authenticator.validate_token():
                self._active = True
                self._session_start_time = time.time()
                log.info("[SESSION] ✓ Session started with existing valid token")
                return True

            if self._authenticator.is_token_expired():
                try:
                    self._authenticator.refresh_token()
                    self._active = True
                    self._session_start_time = time.time()
                    log.info("[SESSION] ✓ Session started after token refresh")
                    return True
                except AuthenticationError:
                    log.warning("[SESSION] Token refresh failed — new auth needed")

            log.warning("[SESSION] Could not start: authentication required")
            return False

        except Exception as error:
            log.error("[SESSION] Failed to start session: %s", error)
            raise SessionError(f"Session start failed: {error}") from error

    def start_session_with_credentials(self, guid: str, password: str) -> bool:
        """Start a session using explicit credentials.

        Args:
            guid: Device identifier for authentication.
            password: Authentication password.

        Returns:
            True if session started successfully.

        Raises:
            SessionError: If authentication fails.
        """
        log.info("[SESSION] Starting session with credentials …")
        try:
            success = self._authenticator.authenticate(guid, password)
            if success:
                self._active = True
                self._session_start_time = time.time()
                log.info("[SESSION] ✓ Session started with new credentials")
                return True
            return False
        except AuthenticationError as error:
            log.error("[SESSION] Authentication failed: %s", error)
            raise SessionError(f"Session start failed: {error}") from error

    def end_session(self) -> None:
        """End the current session and clean up resources."""
        if self._active:
            duration = 0.0
            if self._session_start_time:
                duration = time.time() - self._session_start_time
            self._active = False
            self._session_start_time = None
            log.info("[SESSION] Session ended (duration: %.0f seconds)", duration)
        else:
            log.debug("[SESSION] No active session to end")

    def is_active(self) -> bool:
        """Check if the current session is active with a valid token.

        Returns:
            True if session is active and token is valid.
        """
        if not self._active:
            return False
        if not self._authenticator.validate_token():
            log.warning("[SESSION] Token no longer valid")
            self._active = False
            return False
        return True

    def get_session_info(self) -> Dict[str, Any]:
        """Get information about the current session.

        Returns:
            Dictionary with session status, start time, and duration.
        """
        info: Dict[str, Any] = {
            "active": self._active,
            "start_time": self._session_start_time,
            "duration_seconds": 0.0,
            "token_valid": False,
        }
        if self._session_start_time:
            info["duration_seconds"] = time.time() - self._session_start_time
        if self._active:
            info["token_valid"] = self._authenticator.validate_token()
        return info

    def refresh_if_needed(self) -> bool:
        """Refresh the authentication token if it is near expiration.

        Returns:
            True if no refresh was needed or refresh succeeded.

        Raises:
            SessionError: If token refresh fails.
        """
        if not self._active:
            return False

        if not self._authenticator.is_token_expired():
            return True

        try:
            log.info("[SESSION] Token near expiry, refreshing …")
            self._authenticator.refresh_token()
            log.info("[SESSION] ✓ Token refreshed")
            return True
        except AuthenticationError as error:
            self._active = False
            log.error("[SESSION] Token refresh failed: %s", error)
            raise SessionError(f"Session refresh failed: {error}") from error

    def get_authenticated_headers(self) -> Dict[str, str]:
        """Get HTTP headers for authenticated requests.

        Automatically refreshes the token if needed.

        Returns:
            Dictionary of authenticated HTTP headers.

        Raises:
            SessionError: If no active session or token retrieval fails.
        """
        if not self._active:
            raise SessionError("No active session")
        try:
            return self._authenticator.get_headers()
        except AuthenticationError as error:
            self._active = False
            raise SessionError(
                f"Could not get authenticated headers: {error}"
            ) from error
