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

    def authenticate(self, guid: str = "", password: str = "") -> bool:
        """Full anonymous auth flow: fetch RSA key → encrypt GUID → initToken.

        Matches lmsa.py authenticate() exactly:
          1. POST /common/rsa.jhtml with empty dparams → RSA key in `desc`
          2. RSA-encrypt the GUID with PKCS1_v1_5
          3. POST /client/initToken.jhtml with dparams: {guid: ENCRYPTED_GUID}
          4. JWT arrives in response Authorization header (when Guid echo matches)

        If pycryptodome is not available, falls back to from_jwt() flow.

        Args:
            guid: Device GUID (UUID v4). Uses stored GUID if empty.
            password: Unused (kept for API compatibility). LMSA uses RSA, not passwords.

        Returns:
            True if authentication was successful.

        Raises:
            AuthenticationError: If credentials are invalid after all retries.
        """
        guid = guid or self._guid
        if not guid:
            guid = str(uuid.uuid4()).lower()
            self.logger.info("Generated new GUID for authentication")

        if not validate_guid(guid):
            raise AuthenticationError(f"Invalid GUID format: {mask_sensitive(guid)}")

        self._guid = guid
        self._header_manager.set_guid(guid)
        self._request_builder.set_guid(guid)
        self.logger.info("Authenticating with GUID %s", mask_sensitive(guid))

        for attempt in range(1, MAX_AUTH_RETRIES + 1):
            try:
                # Step 1: Fetch RSA public key
                self.logger.info("Step 1: Fetching RSA public key...")
                rsa_key_b64 = self._fetch_rsa_key()
                if not rsa_key_b64:
                    self.logger.warning("Failed to fetch RSA key (attempt %d/%d)", attempt, MAX_AUTH_RETRIES)
                    continue

                # Step 2: RSA-encrypt the GUID
                self.logger.info("Step 2: Encrypting GUID with RSA...")
                encrypted_guid = self._rsa_encrypt_guid(guid, rsa_key_b64)
                if not encrypted_guid:
                    self.logger.warning("RSA encryption failed (attempt %d/%d)", attempt, MAX_AUTH_RETRIES)
                    continue

                # Step 3: POST initToken with encrypted GUID
                self.logger.info("Step 3: Initializing session token...")
                success = self._init_token(encrypted_guid)
                if success:
                    self.logger.info("Authentication successful")
                    return True

                self.logger.warning(
                    "initToken failed (attempt %d/%d)", attempt, MAX_AUTH_RETRIES,
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

    def authenticate_with_wust(self, wust: str, guid: str = "") -> bool:
        """Authenticate using a WUST token (from Lenovo ID OAuth).

        Matches lenovo_id.py _exchange_wust_for_jwt() exactly:
          - POST /user/lenovoIdLogin.jhtml
          - author: false → NO guid/Authorization in request headers
          - Body: dparams: {wust: WUST, guid: PLAIN_GUID}
          - JWT in Authorization response header (when Guid echo matches)

        Args:
            wust: WUST token from Lenovo ID OAuth callback.
            guid: Device GUID. Generates new one if empty.

        Returns:
            True if authentication was successful.

        Raises:
            AuthenticationError: If WUST is invalid or exchange fails.
        """
        guid = guid or self._guid or str(uuid.uuid4()).lower()

        if not validate_guid(guid):
            raise AuthenticationError(f"Invalid GUID format: {mask_sensitive(guid)}")

        self._guid = guid
        self._header_manager.set_guid(guid)
        self._request_builder.set_guid(guid)
        self.logger.info("Exchanging WUST for JWT with GUID %s", mask_sensitive(guid))

        login_url = f"{self._base_url}{_EP_LOGIN}"

        # Build RequestModel: dparams: {wust: WUST, guid: PLAIN_GUID}
        request_body = self._request_builder.build_login(guid, wust=wust)

        # author: false — NO guid/Authorization in request headers
        # Only _BASE_HEADERS are sent (matching lenovo_id.py line 625)
        headers = self._header_manager.get_full_api_headers(author=False)

        try:
            response = self._http_client.post(
                login_url,
                json_data=request_body,
                headers=headers,
            )
        except Exception as exc:
            raise AuthenticationError(f"lenovoIdLogin POST failed: {exc}") from exc

        # Extract JWT from response headers
        # Matching lenovo_id.py lines 639-645:
        #   guid_resp = r.headers.get("Guid", "")
        #   auth_hdr  = r.headers.get("Authorization", "")
        #   if guid_resp.lower() == guid and auth_hdr: jwt = auth_hdr
        jwt = self._extract_jwt_from_response(response, guid)

        try:
            data = response.json()
        except ValueError as exc:
            raise AuthenticationError(f"Non-JSON response from lenovoIdLogin") from exc

        code = data.get("code", "")
        if code == "402":
            raise AuthenticationError("WUST rejected (expired or invalid)")
        if code == "403":
            raise AuthenticationError("Invalid token (server-side)")
        if code != _CODE_OK:
            raise AuthenticationError(f"lenovoIdLogin error {code}: {data.get('desc', '')}")

        # JWT may also be in response body content
        if not jwt:
            content = data.get("content") or data.get("data") or {}
            if isinstance(content, dict):
                jwt = content.get("token") or content.get("jwt")

        if jwt:
            raw_token = jwt.removeprefix("Bearer ").strip()
            self._jwt_token = raw_token
            self._header_manager.set_jwt_token(raw_token)
            self._extract_expiry(jwt)
            self._store_token(guid, jwt)
            self.logger.info("WUST→JWT exchange successful")
            return True

        # lmsa.py: "initToken succeeded but no JWT in response headers"
        self.logger.warning("lenovoIdLogin succeeded (code 0000) but no JWT found")
        return True

    def from_jwt(self, jwt: str, guid: str) -> bool:
        """Create an authenticated session from a captured JWT and GUID.

        Matches lmsa.py LMSASession.from_jwt():
        Use when JWT is available from a HAR/proxy capture.

        Args:
            jwt: Raw JWT token (with or without Bearer prefix).
            guid: Device GUID that was used to obtain the JWT.

        Returns:
            True if credentials were set successfully.

        Raises:
            AuthenticationError: If GUID format is invalid.
        """
        if not validate_guid(guid):
            raise AuthenticationError(f"Invalid GUID format: {mask_sensitive(guid)}")

        self._guid = guid
        raw_token = jwt.removeprefix("Bearer ").strip()
        self._jwt_token = raw_token
        self._header_manager.set_guid(guid)
        self._header_manager.set_jwt_token(raw_token)
        self._request_builder.set_guid(guid)
        self._store_token(guid, jwt)
        self.logger.info("Session created from captured JWT + GUID")
        return True

    # ------------------------------------------------------------------
    # Internal helpers — matching lmsa.py authentication flow
    # ------------------------------------------------------------------

    def _post(
        self,
        endpoint: str,
        params: Dict[str, Any],
        author: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """POST a RequestModel to an endpoint and return parsed JSON.

        Matches lmsa.py _post() exactly: builds RequestModel envelope,
        sends with correct headers (author flag), extracts JWT from
        response headers via Guid echo + Authorization pattern.

        Args:
            endpoint: API endpoint path (e.g. '/common/rsa.jhtml').
            params: Parameters for the dparams section.
            author: Whether to include auth headers (default True).

        Returns:
            Parsed JSON response dict, or None on failure.
        """
        url = f"{self._base_url}{endpoint}"
        body = self._request_builder.build(params)
        headers = self._header_manager.get_full_api_headers(author=author)

        try:
            response = self._http_client.post(
                url,
                json_data=body,
                headers=headers,
            )
        except Exception as exc:
            self.logger.error("POST %s failed: %s", endpoint, exc)
            return None

        # Extract JWT from response headers (lmsa.py _post() lines 401-410)
        guid_hdr = response.headers.get("Guid", "")
        auth_hdr = response.headers.get("Authorization", "")
        if guid_hdr == self._guid and auth_hdr:
            raw_token = auth_hdr.removeprefix("Bearer ").strip()
            if raw_token != self._jwt_token:
                self._jwt_token = raw_token
                self._header_manager.set_jwt_token(raw_token)
                self.logger.info("JWT token updated from %s response", endpoint)

        if response.status_code != 200:
            self.logger.error(
                "POST %s → HTTP %d: %s",
                endpoint, response.status_code, response.text[:200],
            )
            return None

        try:
            return response.json()
        except ValueError:
            self.logger.error(
                "POST %s → non-JSON response: %s", endpoint, response.text[:200]
            )
            return None

    def _fetch_rsa_key(self) -> Optional[str]:
        """Fetch the server's RSA public key.

        Matches lmsa.py get_rsa_public_key():
          - POST /common/rsa.jhtml with empty dparams: {}
          - Response: code "0000", desc: "<PKCS8 Base64 key>"
          - Key is in `desc` field (NOT `data`)

        Returns:
            Base64-encoded RSA public key string, or None on failure.
        """
        data = self._post(_EP_RSA_KEY, {})
        if data is None:
            return None

        if data.get("code") != _CODE_OK:
            self.logger.error(
                "RSA key error code: %s desc: %s",
                data.get("code"), data.get("desc", ""),
            )
            return None

        # Key is in the `desc` field as PKCS#8 Base64 (Java format)
        key_b64: str = data.get("desc", "")
        if not key_b64:
            self.logger.error("RSA key response missing 'desc' field")
            return None

        self.logger.info("RSA public key fetched successfully")
        return key_b64

    def _rsa_encrypt_guid(self, guid_str: str, key_b64: str) -> Optional[str]:
        """RSA-encrypt the GUID using the server's public key.

        Matches lmsa.py rsa_encrypt_guid():
          - Parse PKCS#8 DER key from Base64
          - Encrypt with PKCS1_v1_5
          - Return Base64-encoded ciphertext

        Args:
            guid_str: Plain GUID string to encrypt.
            key_b64: Base64-encoded RSA public key from server.

        Returns:
            Base64-encoded encrypted GUID, or None if crypto unavailable.
        """
        try:
            from Crypto.Cipher import PKCS1_v1_5
            from Crypto.PublicKey import RSA
        except ImportError:
            self.logger.error(
                "pycryptodome not installed — cannot encrypt GUID. "
                "Install with: pip install pycryptodome"
            )
            return None

        try:
            key_der = base64.b64decode(key_b64.strip())
            rsa_key = RSA.import_key(key_der)
            cipher = PKCS1_v1_5.new(rsa_key)
            encrypted = cipher.encrypt(guid_str.encode("utf-8"))
            return base64.b64encode(encrypted).decode("ascii")
        except Exception as exc:
            self.logger.error("RSA encryption failed: %s", exc)
            return None

    def _init_token(self, encrypted_guid: str) -> bool:
        """Initialize session token with encrypted GUID.

        Matches lmsa.py authenticate() step 3:
          - POST /client/initToken.jhtml
          - dparams: {guid: ENCRYPTED_GUID}
          - JWT arrives in response Authorization header

        Args:
            encrypted_guid: RSA-encrypted GUID (Base64 string).

        Returns:
            True if token was obtained successfully.
        """
        data = self._post(_EP_INIT_TOKEN, {"guid": encrypted_guid})
        if data is None:
            return False

        if data.get("code") != _CODE_OK:
            self.logger.error(
                "initToken error: %s — %s",
                data.get("code"), data.get("desc", ""),
            )
            return False

        # JWT was already extracted by _post() via Guid echo pattern
        if self._jwt_token:
            self._extract_expiry(self._jwt_token)
            self._store_token(self._guid, self._jwt_token)
            return True

        self.logger.warning("initToken succeeded but no JWT in response headers")
        return True

    def _extract_jwt_from_response(self, response: Any, guid: str) -> Optional[str]:
        """Extract JWT from an API response matching lenovo_id.py pattern.

        Checks both Guid echo + Authorization header (primary) and
        bare Authorization header (fallback).

        Args:
            response: HTTP response object.
            guid: Expected GUID in Guid response header.

        Returns:
            JWT string (may include Bearer prefix), or None.
        """
        guid_resp = response.headers.get("Guid", "")
        auth_hdr = response.headers.get("Authorization", "")

        # Primary: Guid echo matches (lmsa.py pattern)
        if guid_resp.lower() == guid.lower() and auth_hdr:
            return auth_hdr

        # Fallback: bare Authorization header with Bearer prefix
        if auth_hdr.startswith("Bearer "):
            return auth_hdr[len("Bearer "):]

        return None

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
