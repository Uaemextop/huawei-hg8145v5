"""
JWT authentication module for the Motorola Firmware Downloader.

Handles authentication with Motorola firmware servers, JWT management,
automatic token refresh, and secure credential handling.

Modelled after ``web_crawler.auth.lmsa.LMSASession`` — uses the same
patterns for JWT rotation, Bearer token headers, and retry with backoff.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Optional

from motorola_firmware.config import (
    BACKOFF_BASE,
    EP_AUTH_LOGIN,
    EP_AUTH_REFRESH,
    MAX_AUTH_RETRIES,
    TOKEN_EXPIRY_MARGIN,
)
from motorola_firmware.exceptions import AuthenticationError
from motorola_firmware.http_client import HttpClient
from motorola_firmware.settings import Settings
from motorola_firmware.utils.logger import log


class Authenticator:
    """Manages JWT authentication with Motorola firmware servers.

    Handles initial authentication, token validation, automatic
    refresh, and provides authenticated HTTP headers.

    Follows the same JWT rotation pattern as ``LMSASession._post()``
    from the web_crawler reference — tokens can rotate on every API
    response and must be persisted immediately.

    Args:
        settings: Application settings instance.
        http_client: HTTP client for making authentication requests.
    """

    def __init__(self, settings: Settings, http_client: HttpClient) -> None:
        """Initialize the authenticator.

        Args:
            settings: Application settings instance.
            http_client: HTTP client for network operations.
        """
        self._settings = settings
        self._http_client = http_client
        self._jwt_token: Optional[str] = None
        self._refresh_token_value: Optional[str] = None
        self._token_expiry: float = 0.0

        self._load_stored_tokens()

    # ── Properties ─────────────────────────────────────────────────

    @property
    def is_authenticated(self) -> bool:
        """True if a JWT token is currently held (may still be expired)."""
        return self._jwt_token is not None

    # ── Token loading / persistence ────────────────────────────────

    def _load_stored_tokens(self) -> None:
        """Load previously stored tokens from configuration."""
        stored_jwt = self._settings.get("motorola_server", "jwt_token")
        stored_refresh = self._settings.get("motorola_server", "refresh_token")

        if stored_jwt:
            self._jwt_token = stored_jwt
            self._parse_token_expiry(stored_jwt)
            log.info("[AUTH] Loaded stored JWT token")

        if stored_refresh:
            self._refresh_token_value = stored_refresh

    def _store_tokens(self) -> None:
        """Persist current tokens to configuration file.

        Follows the LMSA pattern: write immediately after any token change.
        """
        if self._jwt_token:
            self._settings.update("motorola_server", "jwt_token", self._jwt_token)
        if self._refresh_token_value:
            self._settings.update("motorola_server", "refresh_token",
                                  self._refresh_token_value)

    # ── Authentication ─────────────────────────────────────────────

    def authenticate(self, guid: str, password: str) -> bool:
        """Authenticate with the Motorola server and obtain a JWT.

        Implements retry with exponential backoff on network failures,
        mirroring the ``web_crawler.auth.lmsa`` retry pattern.

        Args:
            guid: Unique device identifier (UUID format).
            password: Authentication password.

        Returns:
            True if authentication was successful.

        Raises:
            AuthenticationError: If authentication fails after all retries.
        """
        base_url = self._settings.get("motorola_server", "base_url")
        auth_url = f"{base_url}{EP_AUTH_LOGIN}"

        for attempt in range(MAX_AUTH_RETRIES):
            try:
                log.info("[AUTH] Authentication attempt %d/%d",
                         attempt + 1, MAX_AUTH_RETRIES)

                response = self._http_client.post(
                    auth_url,
                    json_data={"guid": guid, "password": password},
                )
                data = response.json()

                if "token" in data:
                    self._jwt_token = data["token"]
                    self._refresh_token_value = data.get("refresh_token")
                    self._parse_token_expiry(self._jwt_token)
                    self._store_tokens()
                    log.info("[AUTH] ✓ Authentication successful")
                    return True

                # Check for JWT in response headers (LMSA pattern)
                auth_header = response.headers.get("Authorization", "")
                if auth_header:
                    self._jwt_token = auth_header.removeprefix("Bearer ").strip()
                    self._parse_token_expiry(self._jwt_token)
                    self._store_tokens()
                    log.info("[AUTH] ✓ Authentication successful (header JWT)")
                    return True

                log.warning("[AUTH] Response missing token")
                raise AuthenticationError("Server response missing token")

            except AuthenticationError:
                raise
            except Exception as error:
                delay = BACKOFF_BASE * (2 ** attempt)
                log.warning("[AUTH] Attempt %d failed: %s. Retrying in %.1fs",
                            attempt + 1, type(error).__name__, delay)
                if attempt < MAX_AUTH_RETRIES - 1:
                    time.sleep(delay)

        raise AuthenticationError("Authentication failed after all retry attempts")

    def refresh_token(self) -> bool:
        """Refresh an expired JWT using the refresh token.

        Args: None.

        Returns:
            True if token was refreshed successfully.

        Raises:
            AuthenticationError: If refresh fails after all retries.
        """
        if not self._refresh_token_value:
            raise AuthenticationError("No refresh token available")

        base_url = self._settings.get("motorola_server", "base_url")
        refresh_url = f"{base_url}{EP_AUTH_REFRESH}"

        for attempt in range(MAX_AUTH_RETRIES):
            try:
                log.info("[AUTH] Token refresh attempt %d/%d",
                         attempt + 1, MAX_AUTH_RETRIES)

                response = self._http_client.post(
                    refresh_url,
                    json_data={"refresh_token": self._refresh_token_value},
                )
                data = response.json()

                if "token" in data:
                    self._jwt_token = data["token"]
                    if "refresh_token" in data:
                        self._refresh_token_value = data["refresh_token"]
                    self._parse_token_expiry(self._jwt_token)
                    self._store_tokens()
                    log.info("[AUTH] ✓ Token refreshed successfully")
                    return True

                raise AuthenticationError("Refresh response missing token")

            except AuthenticationError:
                raise
            except Exception as error:
                delay = BACKOFF_BASE * (2 ** attempt)
                log.warning("[AUTH] Refresh attempt %d failed: %s. Retrying in %.1fs",
                            attempt + 1, type(error).__name__, delay)
                if attempt < MAX_AUTH_RETRIES - 1:
                    time.sleep(delay)

        raise AuthenticationError("Token refresh failed after all retry attempts")

    # ── Token validation ───────────────────────────────────────────

    def validate_token(self) -> bool:
        """Validate the current JWT token structure and expiration.

        Returns:
            True if the token is valid and not expired.
        """
        if not self._jwt_token:
            log.warning("[AUTH] No token available for validation")
            return False

        if self.is_token_expired():
            log.warning("[AUTH] Token has expired")
            return False

        parts = self._jwt_token.split(".")
        if len(parts) != 3:
            log.warning("[AUTH] Invalid JWT structure")
            return False

        return True

    def is_token_expired(self) -> bool:
        """Check if the current JWT token has expired or is near expiry.

        Returns:
            True if the token is expired or within the expiry margin.
        """
        if self._token_expiry == 0.0:
            return True

        threshold = self._settings.get_int(
            "authentication", "expiry_threshold_seconds", TOKEN_EXPIRY_MARGIN
        )
        remaining = self._token_expiry - time.time()
        return remaining <= threshold

    def get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with the current JWT for authenticated requests.

        Automatically refreshes the token if it's near expiry and
        auto-refresh is enabled (mirroring LMSA's token rotation).

        Returns:
            Dictionary of HTTP headers including Authorization bearer token.

        Raises:
            AuthenticationError: If no valid token is available.
        """
        auto_refresh = self._settings.get_bool("authentication", "auto_refresh", True)

        if auto_refresh and self.is_token_expired():
            if self._refresh_token_value:
                log.info("[AUTH] Auto-refreshing expired token")
                self.refresh_token()
            else:
                raise AuthenticationError("Token expired and no refresh token available")

        if not self._jwt_token:
            raise AuthenticationError("No authentication token available")

        return {
            "Authorization": f"Bearer {self._jwt_token}",
            "Content-Type": "application/json",
        }

    # ── Internal helpers ───────────────────────────────────────────

    def _parse_token_expiry(self, token: str) -> None:
        """Parse the expiration time from a JWT token payload.

        Args:
            token: The JWT token string.
        """
        try:
            payload_segment = token.split(".")[1]
            padding = 4 - len(payload_segment) % 4
            if padding != 4:
                payload_segment += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_segment)
            payload = json.loads(payload_bytes)
            self._token_expiry = float(payload.get("exp", 0))
        except (IndexError, ValueError, json.JSONDecodeError) as error:
            log.debug("[AUTH] Could not parse token expiry: %s", error)
            self._token_expiry = 0.0
