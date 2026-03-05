"""Session management module for Motorola Firmware Downloader.

Manages the lifecycle of authenticated sessions including start, end,
and automatic token refresh.
"""

from datetime import datetime
from typing import Optional

from motorola_downloader.core.authenticator import Authenticator, AuthenticationError
from motorola_downloader.core.http_client import HTTPClient
from motorola_downloader.core.settings import Settings
from motorola_downloader.utils.logger import get_logger


class SessionManager:
    """Manages authenticated session lifecycle.

    Handles session initialization, token refresh, and session termination.
    """

    def __init__(
        self,
        settings: Settings,
        authenticator: Authenticator,
        http_client: HTTPClient,
    ) -> None:
        """Initialize session manager.

        Args:
            settings: Configuration settings
            authenticator: Authenticator instance
            http_client: HTTP client instance
        """
        self.settings = settings
        self.authenticator = authenticator
        self.http_client = http_client
        self.logger = get_logger(__name__)

        self._session_active = False
        self._session_start_time: Optional[datetime] = None

    def start_session(self, password: Optional[str] = None) -> bool:
        """Start authenticated session.

        Attempts to use existing token from settings, or performs
        new authentication if password provided.

        Args:
            password: Optional password for new authentication

        Returns:
            True if session started successfully, False otherwise

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            # Try to load existing token from settings
            jwt_token = self.settings.get("motorola_server", "jwt_token")
            refresh_token = self.settings.get("motorola_server", "refresh_token")

            if jwt_token:
                self.logger.info("Loading existing JWT token from configuration")
                try:
                    self.authenticator.set_token(jwt_token, refresh_token)

                    # Validate token
                    if self.authenticator.validate_token():
                        self.logger.info("Existing token is valid")
                        self._session_active = True
                        self._session_start_time = datetime.now()
                        return True
                    else:
                        self.logger.warning("Existing token is invalid or expired")

                        # Try to refresh
                        if refresh_token:
                            self.logger.info("Attempting to refresh token")
                            if self.authenticator.refresh_token():
                                self._save_tokens()
                                self._session_active = True
                                self._session_start_time = datetime.now()
                                return True

                except Exception as e:
                    self.logger.warning(f"Failed to use existing token: {e}")

            # If no valid token and password provided, authenticate
            if password:
                self.logger.info("Performing new authentication")
                guid = self.settings.get("motorola_server", "guid")

                if self.authenticator.authenticate(guid, password):
                    # Save tokens to configuration
                    self._save_tokens()

                    self._session_active = True
                    self._session_start_time = datetime.now()
                    self.logger.info("Session started successfully")
                    return True
                else:
                    self.logger.error("Authentication failed")
                    return False

            else:
                self.logger.error("No valid token and no password provided for authentication")
                return False

        except Exception as e:
            self.logger.error(f"Failed to start session: {e}")
            raise AuthenticationError(f"Failed to start session: {e}")

    def end_session(self) -> bool:
        """End current session.

        Returns:
            True if session ended successfully, False otherwise
        """
        try:
            if not self._session_active:
                self.logger.warning("No active session to end")
                return False

            self._session_active = False

            if self._session_start_time:
                duration = (datetime.now() - self._session_start_time).total_seconds()
                self.logger.info(f"Session ended (duration: {duration:.0f}s)")
                self._session_start_time = None

            return True

        except Exception as e:
            self.logger.error(f"Error ending session: {e}")
            return False

    def is_active(self) -> bool:
        """Check if session is currently active.

        Returns:
            True if session is active with valid token, False otherwise
        """
        if not self._session_active:
            return False

        # Verify token is still valid
        if not self.authenticator.validate_token():
            self.logger.warning("Session token is no longer valid")
            return False

        return True

    def get_session_info(self) -> dict[str, any]:
        """Get current session information.

        Returns:
            Dictionary containing session information
        """
        info = {
            "active": self._session_active,
            "authenticated": self.authenticator.is_authenticated(),
            "guid": self.authenticator.guid,
        }

        if self._session_start_time:
            duration = (datetime.now() - self._session_start_time).total_seconds()
            info["duration_seconds"] = int(duration)
            info["start_time"] = self._session_start_time.isoformat()

        return info

    def refresh_if_needed(self) -> bool:
        """Refresh token if it's close to expiration.

        Returns:
            True if token is valid (refreshed or not), False if refresh failed
        """
        try:
            if not self._session_active:
                self.logger.warning("No active session")
                return False

            # Check if token needs refresh
            if self.authenticator.is_token_expired():
                self.logger.info("Token expired or close to expiration, refreshing")

                if self.authenticator.refresh_token():
                    # Save updated tokens
                    self._save_tokens()
                    self.logger.info("Token refreshed successfully")
                    return True
                else:
                    self.logger.error("Token refresh failed")
                    self._session_active = False
                    return False

            # Token is still valid
            return True

        except Exception as e:
            self.logger.error(f"Error refreshing token: {e}")
            return False

    def _save_tokens(self) -> None:
        """Save current tokens to configuration file."""
        try:
            jwt_token = self.authenticator.get_token()
            if jwt_token:
                self.settings.update("motorola_server", "jwt_token", jwt_token)
                self.logger.debug("JWT token saved to configuration")

            # Note: refresh_token would need to be exposed by authenticator
            # For now, we only save JWT token

        except Exception as e:
            self.logger.warning(f"Failed to save tokens to configuration: {e}")
