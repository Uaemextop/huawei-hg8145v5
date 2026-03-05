"""HTTP headers management for Motorola Firmware Downloader.

Centralized module for constructing, rotating, and managing HTTP headers
used across all API requests. Patterns extracted from analysis of the
web_crawler/auth/lmsa.py LMSA authentication client and
web_crawler/session.py session builder.

Key patterns from web_crawler analysis:
  - _BASE_HEADERS in lmsa.py: fixed headers for all LMSA API calls
    (User-Agent, Content-Type, Cache-Control, Pragma, Request-Tag,
    clientVersion, Connection: Close).
  - _request_headers() in lmsa.py: per-request auth headers with author flag
    (guid + Authorization: Bearer <JWT> when author=True; empty when False).
  - build_session() in session.py: browser-like headers for general crawling
    (Sec-Fetch-*, Accept-Language, Accept-Encoding, Upgrade-Insecure-Requests).
  - DOWNLOAD_USER_AGENT in lmsa.py: IE8-style UA for S3 bucket downloads
    (different from the Chrome UA used for API calls).
  - random_headers() in session.py: randomised UA, Cache-Control, Sec-Fetch-Site
    for header rotation on retry (bypass 403/WAF).
  - JWT rotates on EVERY response: server echoes Guid header back and provides
    a new Authorization header that must replace the previous one.
"""

import random
from typing import Dict, Optional

from motorola_downloader.utils.logger import get_logger, mask_sensitive

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants — extracted from web_crawler/auth/lmsa.py HAR traffic capture
# ---------------------------------------------------------------------------

#: LMSA desktop client version (from HAR capture LMSA 7.5.4.2).
CLIENT_VERSION = "7.5.4.2"

#: User-Agent from WebApiHttpRequest.cs — used for all LMSA API calls.
API_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
)

#: User-Agent from GlobalVar.UserAgent in lenovo.mbg.service.common.utilities.dll
#: Used specifically for S3 firmware file downloads (HttpDownload.OpenRequest).
DOWNLOAD_USER_AGENT = (
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; "
    "SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; "
    "Media Center PC 6.0; .NET4.0C; .NET4.0E)"
)

#: Browser-like User-Agents for general HTTP requests and rotation.
#: Matches the pool in web_crawler/config.py USER_AGENTS.
BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
]

#: S3 download host patterns — use DOWNLOAD_USER_AGENT for these.
S3_DOWNLOAD_HOSTS = frozenset({
    "rsddownload-secure.lenovo.com",
    "moto-rsd-prod-secure.s3.us-east-1.amazonaws.com",
})

#: Public firmware hosts — no auth needed (HTTP 200 without signed headers).
PUBLIC_FIRMWARE_HOSTS = frozenset({
    "download.lenovo.com",
})


class HeaderManager:
    """Centralized HTTP header builder for LMSA API and download requests.

    Manages three distinct header profiles:
      1. **API headers**: For LMSA REST API calls (Content-Type: json,
         clientVersion, Request-Tag, cache directives).
      2. **Auth headers**: Per-request guid + Authorization overlays
         (with author=True/False flag matching LMSA behavior).
      3. **Download headers**: For S3/CDN firmware file downloads
         (IE8 User-Agent, Connection: Close, optional Range for resume).

    The JWT token is automatically rotated: after each API response the
    caller should invoke update_jwt_from_response() to capture the new
    token from the response Authorization header (matching the LMSA
    pattern in _post() where Guid header echo triggers JWT update).

    Args:
        client_version: LMSA client version string.
        guid: Device GUID for authenticated requests.
        jwt_token: Initial JWT token (without 'Bearer ' prefix).
    """

    def __init__(
        self,
        client_version: str = CLIENT_VERSION,
        guid: str = "",
        jwt_token: str = "",
    ) -> None:
        """Initialize the HeaderManager.

        Args:
            client_version: LMSA client version string.
            guid: Device GUID (UUID v4).
            jwt_token: Initial JWT token (raw, without Bearer prefix).
        """
        self._client_version = client_version
        self._guid = guid
        self._jwt_token = jwt_token
        self.logger = get_logger(__name__)

    # ------------------------------------------------------------------
    # Profile 1: LMSA API base headers
    # ------------------------------------------------------------------

    def get_api_base_headers(self) -> Dict[str, str]:
        """Build base headers for LMSA API calls.

        Replicates _BASE_HEADERS from web_crawler/auth/lmsa.py:
        - User-Agent: Chrome/51 (LMSA WebApiHttpRequest.cs)
        - Content-Type: application/json
        - Cache-Control: no-store,no-cache
        - Pragma: no-cache
        - Request-Tag: lmsa
        - clientVersion: 7.5.4.2
        - Connection: Close (KeepAlive = false)

        Note: 'ConnectionField' and 'Accept' are NOT sent by LMSA
        (confirmed absent in HAR traffic).

        Returns:
            Dictionary of base API headers.
        """
        return {
            "User-Agent": API_USER_AGENT,
            "Content-Type": "application/json",
            "Cache-Control": "no-store,no-cache",
            "Pragma": "no-cache",
            "Request-Tag": "lmsa",
            "clientVersion": self._client_version,
            "Connection": "Close",
        }

    # ------------------------------------------------------------------
    # Profile 2: Per-request auth overlay
    # ------------------------------------------------------------------

    def get_auth_headers(self, author: bool = True) -> Dict[str, str]:
        """Build per-request authentication headers.

        Replicates _request_headers(author=True/False) from lmsa.py:
        - When author=True: includes 'guid' and 'Authorization: Bearer <JWT>'
        - When author=False: returns empty dict (for lenovoIdLogin.jhtml)

        Args:
            author: Whether to include authentication headers.
                Set to False for endpoints that use ``author: false``
                (e.g. lenovoIdLogin.jhtml per ApiBaseService.RequestBase).

        Returns:
            Dictionary of auth headers (may be empty if author=False).
        """
        if not author:
            return {}

        headers: Dict[str, str] = {}
        if self._guid:
            headers["guid"] = self._guid
        if self._jwt_token:
            token = self._jwt_token
            if not token.startswith("Bearer "):
                token = f"Bearer {token}"
            headers["Authorization"] = token

        return headers

    def get_full_api_headers(self, author: bool = True) -> Dict[str, str]:
        """Build complete headers for an LMSA API request.

        Combines base API headers with per-request auth overlay.

        Args:
            author: Whether to include authentication headers.

        Returns:
            Complete dictionary of headers for an API request.
        """
        headers = self.get_api_base_headers()
        headers.update(self.get_auth_headers(author=author))
        return headers

    # ------------------------------------------------------------------
    # Profile 3: Download headers (S3 / CDN)
    # ------------------------------------------------------------------

    def get_download_headers(
        self,
        host: str = "",
        resume_byte: int = 0,
    ) -> Dict[str, str]:
        """Build headers for firmware file downloads.

        Uses the IE8-style User-Agent for S3 downloads (matching
        DOWNLOAD_USER_AGENT from lmsa.py / GlobalVar.UserAgent).
        Uses a regular browser UA for public CDN downloads.

        Args:
            host: Download host (used to select correct UA).
            resume_byte: If > 0, includes Range header for resume.

        Returns:
            Dictionary of download request headers.
        """
        # Select UA based on host
        if host and any(s3_host in host.lower() for s3_host in S3_DOWNLOAD_HOSTS):
            user_agent = DOWNLOAD_USER_AGENT
        else:
            user_agent = random.choice(BROWSER_USER_AGENTS)

        headers: Dict[str, str] = {
            "User-Agent": user_agent,
            "Connection": "Close",
        }

        # Add Range header for download resume
        if resume_byte > 0:
            headers["Range"] = f"bytes={resume_byte}-"

        # Add auth for S3 authenticated hosts (not public hosts)
        if host and host.lower() not in PUBLIC_FIRMWARE_HOSTS:
            if self._jwt_token:
                token = self._jwt_token
                if not token.startswith("Bearer "):
                    token = f"Bearer {token}"
                headers["Authorization"] = token
            if self._guid:
                headers["guid"] = self._guid
                headers["Request-Tag"] = "lmsa"

        return headers

    # ------------------------------------------------------------------
    # Profile 4: Browser-like headers (for retry / fallback)
    # ------------------------------------------------------------------

    def get_browser_headers(self, referer: str = "") -> Dict[str, str]:
        """Build randomised browser-like headers for retry attempts.

        Replicates random_headers() from web_crawler/session.py:
        randomised UA, Cache-Control, Sec-Fetch-Site for header
        rotation on retry (WAF bypass).

        Args:
            referer: Optional Referer/Origin URL.

        Returns:
            Dictionary of browser-like headers.
        """
        headers: Dict[str, str] = {
            "User-Agent": random.choice(BROWSER_USER_AGENTS),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-US,en;q=0.9,es;q=0.8",
                "es-MX,es;q=0.9,en;q=0.8",
                "en-GB,en;q=0.9",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": random.choice(["no-cache", "no-store", "max-age=0"]),
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
        }

        if referer:
            headers["Referer"] = referer
            headers["Origin"] = referer

        return headers

    # ------------------------------------------------------------------
    # JWT token rotation
    # ------------------------------------------------------------------

    def update_jwt_from_response(
        self,
        response_headers: Dict[str, str],
    ) -> bool:
        """Update the JWT token from an API response.

        LMSA pattern (from _post() in lmsa.py): the server echoes back
        the client's Guid in the 'Guid' response header. When the echoed
        Guid matches our stored guid AND a new Authorization header is
        present, the token is rotated.

        Args:
            response_headers: HTTP response headers dictionary.

        Returns:
            True if the token was updated, False otherwise.
        """
        guid_echo = response_headers.get("Guid", "")
        auth_header = response_headers.get("Authorization", "")

        if guid_echo == self._guid and auth_header:
            new_token = auth_header.removeprefix("Bearer ").strip()
            if new_token and new_token != self._jwt_token:
                self._jwt_token = new_token
                self.logger.info("JWT token rotated from API response")
                return True

        return False

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------

    def set_guid(self, guid: str) -> None:
        """Update the device GUID.

        Args:
            guid: New device GUID (UUID v4 format).
        """
        self._guid = guid
        self.logger.info("GUID updated to %s", mask_sensitive(guid, 8))

    def set_jwt_token(self, jwt_token: str) -> None:
        """Update the JWT token.

        Args:
            jwt_token: New JWT token (raw, without Bearer prefix).
        """
        self._jwt_token = jwt_token.removeprefix("Bearer ").strip()
        self.logger.info("JWT token updated")

    @property
    def guid(self) -> str:
        """Get the current device GUID.

        Returns:
            The GUID string.
        """
        return self._guid

    @property
    def jwt_token(self) -> str:
        """Get the current raw JWT token (without Bearer prefix).

        Returns:
            The JWT token string.
        """
        return self._jwt_token

    @property
    def has_credentials(self) -> bool:
        """Check if both GUID and JWT token are set.

        Returns:
            True if both credentials are available.
        """
        return bool(self._guid) and bool(self._jwt_token)
