"""JWT authentication module for Motorola Firmware Downloader.

Handles authentication with Motorola/Lenovo servers using JWT tokens,
including token refresh, validation, and automatic renewal. The
authentication flow is modeled after the LMSA (Lenovo Moto Smart
Assistant) authentication pattern observed in web_crawler/auth/lmsa.py.
"""

import base64
import json
import time
import uuid
from typing import Any, Dict, Optional

from motorola_downloader.exceptions import AuthenticationError, TokenExpiredError
from motorola_downloader.settings import Settings
from motorola_downloader.utils.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger, mask_sensitive
from motorola_downloader.utils.validators import validate_guid, validate_jwt

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DELAY = 1.0  # seconds for exponential backoff
MAX_AUTH_RETRIES = 3
EXPIRATION_THRESHOLD = 300  # seconds before expiry to trigger refresh

# LMSA API endpoints (from web_crawler/auth/lmsa.py reference)
_EP_LOGIN = "/user/lenovoIdLogin.jhtml"
_EP_RSA_KEY = "/common/rsa.jhtml"
_EP_INIT_TOKEN = "/client/initToken.jhtml"
_EP_DELETE_TOKEN = "/client/deleteToken.jhtml"

# Standard success code from LMSA API
_CODE_OK = "0000"

# Base request headers matching LMSA client behavior
_AUTH_HEADERS: Dict[str, str] = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store,no-cache",
    "Pragma": "no-cache",
    "Request-Tag": "lmsa",
    "Connection": "Close",
}


class Authenticator:
    """Manages JWT authentication with Motorola servers.

    Implements the LMSA authentication flow including login, token
    refresh, validation, and automatic renewal with exponential backoff.

    Args:
        settings: Application settings instance.
        http_client: HTTP client for making API requests.
    """

    def __init__(
        self,
        settings: Settings,
        http_client: Optional[HTTPClient] = None,
    ) -> None:
        """Initialize the Authenticator.

        Args:
            settings: Application settings for server configuration.
            http_client: Optional HTTP client instance; creates one if not provided.
        """
        self._settings = settings
        self._http_client = http_client or HTTPClient(
            timeout=settings.get_int("download", "timeout", fallback=30)
        )
        self.logger = get_logger(__name__)

        self._jwt_token: Optional[str] = None
        self._refresh_token_value: Optional[str] = None
        self._token_expiry: float = 0.0
        self._guid: str = settings.get("motorola_server", "guid", fallback="")
        self._base_url: str = settings.get(
            "motorola_server", "base_url",
            fallback="https://lsa.lenovo.com/Interface",
        )
        self._client_version: str = settings.get(
            "motorola_server", "client_version", fallback="7.5.4.2"
        )

        # Load existing tokens from config
        stored_jwt = settings.get("motorola_server", "jwt_token", fallback="")
        if stored_jwt:
            self._jwt_token = stored_jwt
            self.logger.info("Loaded existing JWT from configuration")

        stored_refresh = settings.get("motorola_server", "refresh_token", fallback="")
        if stored_refresh:
            self._refresh_token_value = stored_refresh
            self.logger.info("Loaded existing refresh token from configuration")

    def authenticate(self, guid: str, password: str = "OSD") -> bool:
        """Authenticate with the Motorola server and obtain a JWT token.

        Sends login credentials to the LMSA API endpoint and stores the
        returned JWT token. Uses exponential backoff for retry attempts.

        Args:
            guid: Device unique identifier (UUID v4 format).
            password: Authentication password (default: OSD per LMSA convention).

        Returns:
            True if authentication was successful, False otherwise.

        Raises:
            AuthenticationError: If credentials are invalid after all retries.
            ConnectionError: If unable to connect to the server.
        """
        if not validate_guid(guid):
            raise AuthenticationError(f"Invalid GUID format: {mask_sensitive(guid)}")

        self._guid = guid
        self.logger.info("Authenticating with GUID %s", mask_sensitive(guid))

        for attempt in range(1, MAX_AUTH_RETRIES + 1):
            try:
                login_url = f"{self._base_url}{_EP_LOGIN}"

                request_body = {
                    "dparams": {
                        "wust": "",
                        "guid": guid,
                    },
                    "client": {
                        "version": self._client_version,
                    },
                    "author": False,
                }

                auth_headers = dict(_AUTH_HEADERS)
                auth_headers["clientVersion"] = self._client_version

                response = self._http_client.post(
                    login_url,
                    json_data=request_body,
                    headers=auth_headers,
                )

                response_data = response.json()
                response_code = response_data.get("code", "")

                if response_code == _CODE_OK:
                    jwt = response.headers.get("Authorization", "")
                    if jwt:
                        self._jwt_token = jwt
                        self._extract_expiry(jwt)
                        self._store_token(guid, jwt)
                        self.logger.info("Authentication successful")
                        return True

                self.logger.warning(
                    "Authentication attempt %d/%d failed: code=%s",
                    attempt, MAX_AUTH_RETRIES, response_code,
                )

            except Exception as exc:
                self.logger.warning(
                    "Authentication attempt %d/%d error: %s",
                    attempt, MAX_AUTH_RETRIES, exc,
                )

            if attempt < MAX_AUTH_RETRIES:
                delay = BASE_DELAY * (2 ** (attempt - 1))
                self.logger.info("Retrying in %.1f seconds...", delay)
                time.sleep(delay)

        raise AuthenticationError(
            "Authentication failed after all retry attempts"
        )

    def refresh_token(self) -> bool:
        """Refresh an expired JWT token using the refresh token.

        Attempts to obtain a new JWT token using the stored refresh token.
        Falls back to re-authentication if refresh fails.

        Returns:
            True if token was refreshed successfully.

        Raises:
            TokenExpiredError: If refresh fails and re-authentication is needed.
        """
        if not self._refresh_token_value:
            self.logger.warning("No refresh token available")
            raise TokenExpiredError("No refresh token available for renewal")

        self.logger.info("Attempting to refresh JWT token")

        for attempt in range(1, MAX_AUTH_RETRIES + 1):
            try:
                refresh_url = f"{self._base_url}{_EP_INIT_TOKEN}"

                request_body = {
                    "refreshToken": self._refresh_token_value,
                    "guid": self._guid,
                    "client": {"version": self._client_version},
                }

                auth_headers = dict(_AUTH_HEADERS)
                auth_headers["clientVersion"] = self._client_version
                if self._guid:
                    auth_headers["guid"] = self._guid

                response = self._http_client.post(
                    refresh_url,
                    json_data=request_body,
                    headers=auth_headers,
                )

                response_data = response.json()
                if response_data.get("code") == _CODE_OK:
                    new_jwt = response.headers.get("Authorization", "")
                    if new_jwt:
                        self._jwt_token = new_jwt
                        self._extract_expiry(new_jwt)
                        self._store_token(self._guid, new_jwt)
                        self.logger.info("Token refreshed successfully")
                        return True

                self.logger.warning(
                    "Token refresh attempt %d/%d failed", attempt, MAX_AUTH_RETRIES
                )

            except Exception as exc:
                self.logger.warning(
                    "Token refresh attempt %d/%d error: %s",
                    attempt, MAX_AUTH_RETRIES, exc,
                )

            if attempt < MAX_AUTH_RETRIES:
                delay = BASE_DELAY * (2 ** (attempt - 1))
                time.sleep(delay)

        raise TokenExpiredError("Token refresh failed after all retry attempts")

    def validate_token(self) -> bool:
        """Validate that the current JWT token is present and not expired.

        Returns:
            True if the token is valid, False otherwise.
        """
        if not self._jwt_token:
            self.logger.warning("No JWT token available")
            return False

        if self.is_token_expired():
            self.logger.warning("JWT token has expired")
            return False

        self.logger.info("JWT token is valid")
        return True

    def is_token_expired(self) -> bool:
        """Check if the current JWT token has expired or is near expiration.

        Returns:
            True if the token is expired or within the expiration threshold.
        """
        if not self._jwt_token:
            return True

        if self._token_expiry == 0.0:
            self._extract_expiry(self._jwt_token)

        threshold = self._settings.get_int(
            "authentication", "expiration_threshold_seconds",
            fallback=EXPIRATION_THRESHOLD,
        )
        current_time = time.time()
        is_expired = current_time >= (self._token_expiry - threshold)

        if is_expired:
            self.logger.info("Token is expired or near expiration")

        return is_expired

    def get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with the current JWT token for authenticated requests.

        Returns:
            Dictionary of headers including Authorization with Bearer token.

        Raises:
            AuthenticationError: If no valid token is available.
        """
        if not self._jwt_token:
            raise AuthenticationError("No JWT token available for request headers")

        headers = dict(_AUTH_HEADERS)
        headers["Authorization"] = (
            self._jwt_token
            if self._jwt_token.startswith("Bearer ")
            else f"Bearer {self._jwt_token}"
        )
        headers["clientVersion"] = self._client_version
        if self._guid:
            headers["guid"] = self._guid

        return headers

    def _extract_expiry(self, jwt_token: str) -> None:
        """Extract the expiration time from a JWT token payload.

        Args:
            jwt_token: The JWT token string.
        """
        try:
            token = jwt_token
            if token.startswith("Bearer "):
                token = token[7:]

            parts = token.split(".")
            if len(parts) != 3:
                self.logger.warning("Invalid JWT structure, cannot extract expiry")
                return

            # Decode the payload (second part)
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_json)

            exp = payload.get("exp", 0)
            if exp:
                self._token_expiry = float(exp)
                self.logger.info("Token expiry extracted successfully")
            else:
                # Default: assume 1 hour from now
                self._token_expiry = time.time() + 3600
                self.logger.info("No exp claim found, assuming 1 hour validity")

        except (ValueError, json.JSONDecodeError, KeyError) as exc:
            self.logger.warning("Failed to extract token expiry: %s", exc)
            self._token_expiry = time.time() + 3600

    def _store_token(self, guid: str, jwt_token: str) -> None:
        """Store authentication tokens in the configuration file.

        Args:
            guid: The device GUID.
            jwt_token: The JWT token to store.
        """
        try:
            self._settings.update("motorola_server", "guid", guid)
            self._settings.update("motorola_server", "jwt_token", jwt_token)
            self.logger.info("Tokens stored in configuration")
        except Exception as exc:
            self.logger.error("Failed to store tokens: %s", exc)

    @property
    def token(self) -> Optional[str]:
        """Get the current JWT token.

        Returns:
            The JWT token string, or None if not authenticated.
        """
        return self._jwt_token

    @property
    def guid(self) -> str:
        """Get the current device GUID.

        Returns:
            The GUID string.
        """
        return self._guid
