"""JWT authentication module for Motorola Firmware Downloader.

Handles authentication with Motorola/Lenovo servers using JWT tokens,
including token refresh, validation, and automatic renewal. The
authentication flow is modeled after the LMSA (Lenovo Moto Smart
Assistant) authentication pattern observed in web_crawler/auth/lmsa.py.

Key patterns from web_crawler analysis:
  - authenticate() in lmsa.py: RSA-encrypt GUID → initToken → JWT in
    Authorization response header (when Guid echo matches).
  - from_jwt(): create session from captured JWT + GUID (HAR/proxy).
  - _post(): every response rotates the JWT (server echoes Guid header
    + new Authorization header; old token becomes invalid).
  - _request_headers(author=True/False): login uses author=False.
"""

import base64
import json
import time
import uuid
from typing import Any, Dict, Optional

from motorola_downloader.exceptions import AuthenticationError, TokenExpiredError
from motorola_downloader.settings import Settings
from motorola_downloader.utils.headers import HeaderManager
from motorola_downloader.utils.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger, mask_sensitive
from motorola_downloader.utils.request_builder import RequestBuilder
from motorola_downloader.utils.validators import validate_guid, validate_jwt

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DELAY = 1.0  # seconds for exponential backoff
MAX_AUTH_RETRIES = 3
EXPIRATION_THRESHOLD = 300  # seconds before expiry to trigger refresh

# Production LMSA API base URL (hardcoded constant, NOT configurable).
# Confirmed live by curl: /Interface/common/rsa.jhtml → 200, code 0000.
LMSA_BASE_URL = "https://lsa.lenovo.com/Interface"

# LMSA API endpoints (from web_crawler/auth/lmsa.py lines 105-117)
_EP_RSA_KEY        = "/common/rsa.jhtml"
_EP_INIT_TOKEN     = "/client/initToken.jhtml"
_EP_DELETE_TOKEN   = "/client/deleteToken.jhtml"
_EP_LOGIN          = "/user/lenovoIdLogin.jhtml"

# Standard success code from LMSA API
_CODE_OK = "0000"


class Authenticator:
    """Manages JWT authentication with Motorola servers.

    Implements the LMSA authentication flow including login, token
    refresh, validation, and automatic renewal with exponential backoff.

    Uses HeaderManager for proper header construction (API vs download
    profiles) and RequestBuilder for LMSA RequestModel envelope construction.

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
        # Base URL is a hardcoded constant, NOT from config
        self._base_url: str = LMSA_BASE_URL
        self._client_version: str = settings.get(
            "motorola_server", "client_version", fallback="7.5.4.2"
        )

        # Initialize HeaderManager and RequestBuilder with server config
        self._header_manager = HeaderManager(
            client_version=self._client_version,
            guid=self._guid,
        )
        self._request_builder = RequestBuilder(
            guid=self._guid,
            client_version=self._client_version,
            language=settings.get("motorola_server", "language", fallback="en-US"),
            windows_info=settings.get(
                "motorola_server", "windows_info",
                fallback="Microsoft Windows 11 Pro, x64-based PC",
            ),
        )

        # Load existing tokens from config
        stored_jwt = settings.get("motorola_server", "jwt_token", fallback="")
        if stored_jwt:
            self._jwt_token = stored_jwt
            self._header_manager.set_jwt_token(stored_jwt)
            self.logger.info("Loaded existing JWT from configuration")

        stored_refresh = settings.get("motorola_server", "refresh_token", fallback="")
        if stored_refresh:
            self._refresh_token_value = stored_refresh
            self.logger.info("Loaded existing refresh token from configuration")

    def authenticate(self, guid: str, password: str = "OSD") -> bool:
        """Authenticate with the Motorola server and obtain a JWT token.

        Sends login credentials to the LMSA API endpoint and stores the
        returned JWT token. Uses exponential backoff for retry attempts.

        Login uses author=False (matching LMSA lenovoIdLogin.jhtml which
        sets author: false — no guid/Authorization in request headers).

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
        self._header_manager.set_guid(guid)
        self._request_builder.set_guid(guid)
        self.logger.info("Authenticating with GUID %s", mask_sensitive(guid))

        for attempt in range(1, MAX_AUTH_RETRIES + 1):
            try:
                login_url = f"{self._base_url}{_EP_LOGIN}"

                # Build RequestModel envelope (matching lmsa.py _build_request_model)
                request_body = self._request_builder.build_login(guid)

                # Login uses author=False (no guid/Authorization headers)
                # Matches lmsa.py: _post(_EP_LOGIN, params, author=False)
                auth_headers = self._header_manager.get_full_api_headers(author=False)

                response = self._http_client.post(
                    login_url,
                    json_data=request_body,
                    headers=auth_headers,
                )

                response_data = response.json()
                response_code = response_data.get("code", "")

                # Check for JWT token rotation in response headers
                # (matching lmsa.py _post() Guid echo + Authorization update)
                jwt_updated = self._header_manager.update_jwt_from_response(
                    dict(response.headers)
                )

                if response_code == _CODE_OK:
                    jwt = response.headers.get("Authorization", "")
                    if jwt:
                        self._jwt_token = jwt.removeprefix("Bearer ").strip()
                        self._header_manager.set_jwt_token(self._jwt_token)
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

                # Build RequestModel with refresh token
                request_body = self._request_builder.build({
                    "refreshToken": self._refresh_token_value,
                })

                # Refresh uses author=True (authenticated request)
                auth_headers = self._header_manager.get_full_api_headers(author=True)

                response = self._http_client.post(
                    refresh_url,
                    json_data=request_body,
                    headers=auth_headers,
                )

                response_data = response.json()

                # Check JWT rotation from response
                self._header_manager.update_jwt_from_response(dict(response.headers))

                if response_data.get("code") == _CODE_OK:
                    new_jwt = response.headers.get("Authorization", "")
                    if new_jwt:
                        self._jwt_token = new_jwt.removeprefix("Bearer ").strip()
                        self._header_manager.set_jwt_token(self._jwt_token)
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

        Uses the HeaderManager to build proper LMSA API headers with
        authentication overlay (guid + Authorization: Bearer).

        Returns:
            Dictionary of headers including Authorization with Bearer token.

        Raises:
            AuthenticationError: If no valid token is available.
        """
        if not self._jwt_token:
            raise AuthenticationError("No JWT token available for request headers")

        return self._header_manager.get_full_api_headers(author=True)

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

    @property
    def header_manager(self) -> HeaderManager:
        """Get the HeaderManager instance.

        Returns:
            The HeaderManager used for header construction.
        """
        return self._header_manager

    @property
    def request_builder(self) -> RequestBuilder:
        """Get the RequestBuilder instance.

        Returns:
            The RequestBuilder used for request envelope construction.
        """
        return self._request_builder
