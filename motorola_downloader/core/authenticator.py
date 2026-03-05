"""Authentication module for Motorola Firmware Downloader.

Handles JWT authentication with Motorola servers, including token refresh
and validation.
"""

import base64
import json
import time
from datetime import datetime, timedelta
from typing import Optional

from motorola_downloader.core.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.validators import validate_guid, validate_jwt


class AuthenticationError(Exception):
    """Exception raised when authentication fails."""
    pass


class Authenticator:
    """JWT authentication manager for Motorola servers.

    Handles authentication, token refresh, and validation with exponential backoff
    retry logic for network failures.
    """

    def __init__(
        self,
        base_url: str,
        guid: str,
        http_client: HTTPClient,
        auto_refresh: bool = True,
        refresh_threshold: int = 3600,  # 1 hour before expiration
    ) -> None:
        """Initialize authenticator.

        Args:
            base_url: Motorola server base URL
            guid: Device GUID for authentication
            http_client: HTTP client for requests
            auto_refresh: Whether to automatically refresh expiring tokens
            refresh_threshold: Seconds before expiration to trigger refresh

        Raises:
            ValueError: If GUID format is invalid
        """
        if not validate_guid(guid):
            raise ValueError(f"Invalid GUID format: {guid}")

        self.base_url = base_url.rstrip("/")
        self.guid = guid
        self.http_client = http_client
        self.auto_refresh = auto_refresh
        self.refresh_threshold = refresh_threshold
        self.logger = get_logger(__name__)

        self._jwt_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    def authenticate(self, guid: str, password: str) -> bool:
        """Authenticate with Motorola server and obtain JWT token.

        Uses exponential backoff (1s, 2s, 4s) for retries.
        Maximum 3 retry attempts.

        Args:
            guid: Device GUID
            password: Authentication password

        Returns:
            True if authentication successful, False otherwise

        Raises:
            AuthenticationError: If authentication fails after all retries
        """
        if not validate_guid(guid):
            self.logger.error(f"Invalid GUID format: {guid}")
            raise AuthenticationError(f"Invalid GUID format: {guid}")

        endpoint = f"{self.base_url}/auth/login"
        payload = {
            "guid": guid,
            "password": password,
            "client_version": "1.0.0"
        }

        # Retry with exponential backoff
        max_retries = 3
        base_delay = 1.0

        for attempt in range(max_retries):
            try:
                self.logger.info(f"Authentication attempt {attempt + 1}/{max_retries}")

                response = self.http_client.post(
                    endpoint,
                    json_data=payload,
                    headers={"Content-Type": "application/json"}
                )

                if not response:
                    raise AuthenticationError("No response from server")

                data = response.json()

                # Check for successful authentication
                if data.get("code") == "0000" or data.get("success"):
                    # Extract JWT token from response
                    self._jwt_token = data.get("jwt_token") or data.get("token")
                    self._refresh_token = data.get("refresh_token")

                    # Extract token expiration
                    if data.get("expires_in"):
                        expires_in = int(data["expires_in"])
                        self._token_expiry = datetime.now() + timedelta(seconds=expires_in)
                    elif data.get("expiry"):
                        self._token_expiry = datetime.fromtimestamp(int(data["expiry"]))
                    else:
                        # Default to 24 hours if not specified
                        self._token_expiry = datetime.now() + timedelta(hours=24)

                    if not self._jwt_token:
                        raise AuthenticationError("No JWT token in response")

                    self.logger.info("Authentication successful")
                    return True

                else:
                    error_msg = data.get("message") or data.get("desc") or "Unknown error"
                    self.logger.error(f"Authentication failed: {error_msg}")

                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        self.logger.info(f"Retrying in {delay} seconds...")
                        time.sleep(delay)
                    else:
                        raise AuthenticationError(f"Authentication failed: {error_msg}")

            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON response: {e}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                else:
                    raise AuthenticationError("Invalid server response")

            except Exception as e:
                self.logger.error(f"Authentication error: {e}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                else:
                    raise AuthenticationError(f"Authentication failed: {e}")

        return False

    def refresh_token(self) -> bool:
        """Refresh expired JWT token using refresh token.

        Returns:
            True if refresh successful, False otherwise

        Raises:
            AuthenticationError: If refresh fails and no refresh token available
        """
        if not self._refresh_token:
            self.logger.error("No refresh token available")
            raise AuthenticationError("No refresh token available")

        endpoint = f"{self.base_url}/auth/refresh"
        payload = {
            "refresh_token": self._refresh_token,
            "guid": self.guid
        }

        # Retry with exponential backoff
        max_retries = 3
        base_delay = 1.0

        for attempt in range(max_retries):
            try:
                self.logger.info(f"Token refresh attempt {attempt + 1}/{max_retries}")

                response = self.http_client.post(
                    endpoint,
                    json_data=payload,
                    headers={"Content-Type": "application/json"}
                )

                if not response:
                    raise AuthenticationError("No response from server")

                data = response.json()

                if data.get("code") == "0000" or data.get("success"):
                    # Update tokens
                    self._jwt_token = data.get("jwt_token") or data.get("token")
                    new_refresh = data.get("refresh_token")
                    if new_refresh:
                        self._refresh_token = new_refresh

                    # Update expiration
                    if data.get("expires_in"):
                        expires_in = int(data["expires_in"])
                        self._token_expiry = datetime.now() + timedelta(seconds=expires_in)

                    self.logger.info("Token refresh successful")
                    return True

                else:
                    error_msg = data.get("message") or data.get("desc") or "Unknown error"
                    self.logger.error(f"Token refresh failed: {error_msg}")

                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        time.sleep(delay)
                    else:
                        raise AuthenticationError(f"Token refresh failed: {error_msg}")

            except Exception as e:
                self.logger.error(f"Token refresh error: {e}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                else:
                    raise AuthenticationError(f"Token refresh failed: {e}")

        return False

    def validate_token(self) -> bool:
        """Verify that current JWT token is valid.

        Returns:
            True if token is valid, False otherwise
        """
        if not self._jwt_token:
            return False

        if not validate_jwt(self._jwt_token):
            self.logger.warning("Token format is invalid")
            return False

        # Check if token is expired
        if self.is_token_expired():
            self.logger.warning("Token is expired")
            return False

        return True

    def is_token_expired(self) -> bool:
        """Check if JWT token is expired or close to expiration.

        Returns:
            True if token is expired or will expire within threshold, False otherwise
        """
        if not self._token_expiry:
            # If no expiry info, assume not expired
            return False

        # Check if token will expire within threshold
        time_until_expiry = (self._token_expiry - datetime.now()).total_seconds()

        if time_until_expiry <= 0:
            return True

        # Auto-refresh if within threshold and auto_refresh is enabled
        if self.auto_refresh and time_until_expiry <= self.refresh_threshold:
            self.logger.info(
                f"Token will expire in {time_until_expiry}s, "
                f"triggering auto-refresh (threshold: {self.refresh_threshold}s)"
            )
            return True

        return False

    def get_headers(self) -> dict[str, str]:
        """Get HTTP headers with JWT token for authenticated requests.

        Returns:
            Dictionary of headers including Authorization header

        Raises:
            AuthenticationError: If no valid token available
        """
        if not self._jwt_token:
            raise AuthenticationError("No authentication token available")

        if not self.validate_token():
            if self.auto_refresh and self._refresh_token:
                self.logger.info("Token invalid, attempting refresh")
                if not self.refresh_token():
                    raise AuthenticationError("Token invalid and refresh failed")
            else:
                raise AuthenticationError("Token invalid and auto-refresh disabled")

        return {
            "Authorization": f"Bearer {self._jwt_token}",
            "guid": self.guid,
        }

    def set_token(self, jwt_token: str, refresh_token: Optional[str] = None) -> None:
        """Set JWT token manually (e.g., from configuration).

        Args:
            jwt_token: JWT token string
            refresh_token: Optional refresh token

        Raises:
            ValueError: If token format is invalid
        """
        if not validate_jwt(jwt_token):
            raise ValueError(f"Invalid JWT token format")

        self._jwt_token = jwt_token
        if refresh_token:
            self._refresh_token = refresh_token

        # Try to extract expiration from token
        try:
            # JWT payload is the second part (base64-encoded)
            parts = jwt_token.split(".")
            if len(parts) == 3:
                # Decode payload (add padding if needed)
                payload_b64 = parts[1]
                padding = 4 - (len(payload_b64) % 4)
                if padding != 4:
                    payload_b64 += "=" * padding

                payload = json.loads(base64.b64decode(payload_b64))

                # Extract expiration timestamp
                if "exp" in payload:
                    self._token_expiry = datetime.fromtimestamp(payload["exp"])
                    self.logger.debug(f"Token expires at {self._token_expiry}")

        except Exception as e:
            self.logger.warning(f"Could not extract token expiration: {e}")
            # Set default expiration (24 hours)
            self._token_expiry = datetime.now() + timedelta(hours=24)

        self.logger.info("JWT token set manually")

    def get_token(self) -> Optional[str]:
        """Get current JWT token.

        Returns:
            JWT token string or None if not authenticated
        """
        return self._jwt_token

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with valid token.

        Returns:
            True if authenticated with valid token, False otherwise
        """
        return self.validate_token()
