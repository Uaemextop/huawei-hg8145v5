"""
JWT authentication and refresh handling.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from motorola_firmware.encryption import hash_password
from motorola_firmware.http_client import HttpClient
from motorola_firmware.logger import get_logger
from motorola_firmware.settings import Settings
from motorola_firmware.validators import validate_jwt


class AuthenticationError(RuntimeError):
    """Raised when authentication or refresh fails."""


class Authenticator:
    """Manage JWT authentication lifecycle."""

    def __init__(self, settings: Settings, http_client: HttpClient) -> None:
        self.settings = settings
        self.http_client = http_client
        self.logger = get_logger(__name__)
        self._token = settings.get("motorola_server", "jwt_token")
        self._refresh_token = settings.get("motorola_server", "refresh_token")
        self._token_expiry = self._load_expiry()

    def authenticate(self, guid: str, password: str) -> bool:
        """Authenticate with the Motorola server and persist JWT."""
        endpoint = self._auth_url("/auth/login")
        payload = {"guid": guid, "password": hash_password(password)}
        for delay in (1, 2, 4):
            try:
                response = self.http_client.post(endpoint, json_data=payload)
                data = response.json()
                self._update_tokens_from_response(data)
                self.logger.info("Authentication succeeded")
                return True
            except Exception as exc:  # noqa: BLE001
                self.logger.warning("Authentication attempt failed: %s", exc)
                time.sleep(delay)
        raise AuthenticationError("Unable to authenticate after retries")

    def refresh_token(self) -> str:
        """Refresh JWT using the stored refresh token."""
        if not self._refresh_token:
            raise AuthenticationError("Refresh token not available")
        endpoint = self._auth_url("/auth/refresh")
        payload = {"refresh_token": self._refresh_token}
        for delay in (1, 2, 4):
            try:
                response = self.http_client.post(endpoint, json_data=payload)
                data = response.json()
                self._update_tokens_from_response(data)
                self.logger.info("Token refreshed successfully")
                return self._token
            except Exception as exc:  # noqa: BLE001
                self.logger.warning("Token refresh failed: %s", exc)
                time.sleep(delay)
        raise AuthenticationError("Unable to refresh token after retries")

    def validate_token(self) -> bool:
        """Return True if current token is present and not expired."""
        if not self._token or not validate_jwt(self._token):
            return False
        return not self.is_token_expired()

    def is_token_expired(self) -> bool:
        """Check expiry using configured threshold."""
        threshold_seconds = self.settings.get_int(
            "authentication",
            "expiry_threshold_seconds",
            300,
        )
        if not self._token_expiry:
            return True
        now = datetime.now(timezone.utc)
        return now + timedelta(seconds=threshold_seconds) >= self._token_expiry

    def get_headers(self) -> Dict[str, str]:
        """Return authorization headers, refreshing if needed."""
        auto_refresh = self.settings.get_bool("authentication", "auto_refresh", True)
        if not self.validate_token():
            if auto_refresh:
                self.refresh_token()
            else:
                raise AuthenticationError("Token expired and auto-refresh disabled")
        return {"Authorization": f"Bearer {self._token}"}

    def _auth_url(self, path: str) -> str:
        base = self.settings.get("motorola_server", "base_url")
        return f"{base.rstrip('/')}{path}"

    def _update_tokens_from_response(self, data: Dict[str, object]) -> None:
        token = str(data.get("token") or data.get("jwt") or "")
        refresh = str(data.get("refresh_token") or self._refresh_token or "")
        expires_in = data.get("expires_in")
        expires_at = data.get("expires_at")

        if token and validate_jwt(token):
            self._token = token
            self.settings.update("motorola_server", "jwt_token", token)
        if refresh:
            self._refresh_token = refresh
            self.settings.update("motorola_server", "refresh_token", refresh)

        self._token_expiry = self._compute_expiry(expires_in, expires_at)
        if self._token_expiry:
            self.settings.update(
                "authentication",
                "token_expires_at",
                self._token_expiry.isoformat(),
            )

    def _compute_expiry(
        self,
        expires_in: object,
        expires_at: object,
    ) -> Optional[datetime]:
        now = datetime.now(timezone.utc)
        if isinstance(expires_in, int):
            return now + timedelta(seconds=expires_in)
        if isinstance(expires_in, str) and expires_in.isdigit():
            return now + timedelta(seconds=int(expires_in))
        if isinstance(expires_at, str):
            try:
                return datetime.fromisoformat(expires_at).astimezone(timezone.utc)
            except ValueError:
                return None
        return None

    def _load_expiry(self) -> Optional[datetime]:
        raw = self.settings.get("authentication", "token_expires_at", "")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw).astimezone(timezone.utc)
        except ValueError:
            return None
