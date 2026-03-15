"""Reusable HTTP client for Motorola Firmware Downloader.

Centralizes all HTTP operations with:
- Automatic retry with exponential backoff
- Configurable timeouts and headers
- HTTPS-only enforcement
- Request/response logging
- File download with progress support
"""

import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter, Retry

from motorola_downloader.exceptions import HTTPClientError
from motorola_downloader.utils.logger import get_logger, mask_sensitive
from motorola_downloader.utils.validators import validate_url

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 30
DEFAULT_CHUNK_SIZE = 8192
MAX_RETRIES = 3
BACKOFF_FACTOR = 1.0
RETRY_STATUS_CODES = (429, 500, 502, 503, 504)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class HTTPClient:
    """Centralized HTTP client with retry logic and HTTPS enforcement.

    Manages a persistent requests.Session with automatic retries,
    configurable headers, and safe logging of all operations.

    Args:
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.
        user_agent: User-Agent header value.
        verify_ssl: Whether to verify SSL certificates.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the HTTP client with a configured session.

        Args:
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts.
            user_agent: User-Agent header string.
            verify_ssl: Whether to verify SSL certificates.
        """
        self._timeout = timeout
        self._max_retries = max_retries
        self._verify_ssl = verify_ssl
        self.logger = get_logger(__name__)

        self._session = requests.Session()
        self._session.verify = verify_ssl
        # Keep session headers MINIMAL — LMSA API headers are set per-request
        # via HeaderManager.get_full_api_headers(). Setting them here would
        # cause conflicts or extra headers that lmsa.py does NOT send.
        # Confirmed from HAR: Accept and Accept-Encoding are NOT sent by LMSA.
        self._session.headers.update({
            "User-Agent": user_agent,
        })

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=list(RETRY_STATUS_CODES),
            allowed_methods=["GET", "POST", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("https://", adapter)

        self.logger.info("HTTP client initialized (timeout=%ds, retries=%d)",
                         timeout, max_retries)

    def _enforce_https(self, url: str) -> None:
        """Ensure the URL uses HTTPS scheme.

        Args:
            url: The URL to check.

        Raises:
            HTTPClientError: If the URL does not use HTTPS.
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise HTTPClientError(
                f"HTTPS required, got scheme '{parsed.scheme}' for: {url}"
            )

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> requests.Response:
        """Send an HTTP GET request.

        Args:
            url: The target URL (must be HTTPS).
            params: Optional query parameters.
            headers: Optional additional headers.

        Returns:
            The HTTP response object.

        Raises:
            HTTPClientError: If the request fails after all retries.
        """
        self._enforce_https(url)
        self.logger.info("GET %s", url)

        try:
            response = self._session.get(
                url,
                params=params,
                headers=headers,
                timeout=self._timeout,
            )
            self.logger.info("GET %s → %d", url, response.status_code)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as exc:
            self.logger.error("HTTP error for GET %s: %s", url, exc)
            raise HTTPClientError(f"HTTP error: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            self.logger.error("Connection error for GET %s: %s", url, exc)
            raise HTTPClientError(f"Connection error: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            self.logger.error("Timeout for GET %s: %s", url, exc)
            raise HTTPClientError(f"Request timeout: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            self.logger.error("Request failed for GET %s: %s", url, exc)
            raise HTTPClientError(f"Request failed: {exc}") from exc

    def post(
        self,
        url: str,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        raise_for_status: bool = False,
    ) -> requests.Response:
        """Send an HTTP POST request with JSON body.

        Args:
            url: The target URL (must be HTTPS).
            json_data: Optional JSON body data.
            headers: Optional additional headers.
            raise_for_status: If True, raise HTTPClientError on non-2xx.
                Default False — returns raw response for status inspection.

        Returns:
            The HTTP response object.

        Raises:
            HTTPClientError: If the request fails (connection/timeout error,
                or HTTP error when raise_for_status=True).
        """
        self._enforce_https(url)
        self.logger.info("POST %s", url)

        try:
            response = self._session.post(
                url,
                json=json_data,
                headers=headers,
                timeout=self._timeout,
            )
            self.logger.info("POST %s → %d", url, response.status_code)
            if raise_for_status:
                response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as exc:
            self.logger.error("HTTP error for POST %s: %s", url, exc)
            raise HTTPClientError(f"HTTP error: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            self.logger.error("Connection error for POST %s: %s", url, exc)
            raise HTTPClientError(f"Connection error: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            self.logger.error("Timeout for POST %s: %s", url, exc)
            raise HTTPClientError(f"Request timeout: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            self.logger.error("Request failed for POST %s: %s", url, exc)
            raise HTTPClientError(f"Request failed: {exc}") from exc

    def download(
        self,
        url: str,
        file_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        headers: Optional[Dict[str, str]] = None,
        resume_byte: int = 0,
    ) -> int:
        """Download a file from a URL with streaming and optional resume.

        Args:
            url: The download URL (must be HTTPS).
            file_path: Local path to save the downloaded file.
            chunk_size: Size of download chunks in bytes.
            headers: Optional additional headers.
            resume_byte: Byte offset to resume download from.

        Returns:
            Total number of bytes downloaded.

        Raises:
            HTTPClientError: If the download fails.
        """
        self._enforce_https(url)
        self.logger.info("Downloading %s → %s", url, file_path)

        request_headers = dict(headers or {})
        if resume_byte > 0:
            request_headers["Range"] = f"bytes={resume_byte}-"
            self.logger.info("Resuming download from byte %d", resume_byte)

        try:
            response = self._session.get(
                url,
                headers=request_headers,
                stream=True,
                timeout=self._timeout,
            )
            response.raise_for_status()

            total_size = int(response.headers.get("content-length", 0))
            downloaded = 0
            mode = "ab" if resume_byte > 0 else "wb"

            with open(file_path, mode) as output_file:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        output_file.write(chunk)
                        downloaded += len(chunk)

            self.logger.info(
                "Download complete: %s (%d bytes)", file_path, downloaded
            )
            return downloaded

        except requests.exceptions.HTTPError as exc:
            self.logger.error("Download HTTP error for %s: %s", url, exc)
            raise HTTPClientError(f"Download HTTP error: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            self.logger.error("Download connection error for %s: %s", url, exc)
            raise HTTPClientError(f"Download connection error: {exc}") from exc
        except requests.exceptions.Timeout as exc:
            self.logger.error("Download timeout for %s: %s", url, exc)
            raise HTTPClientError(f"Download timeout: {exc}") from exc
        except IOError as exc:
            self.logger.error("File I/O error writing to %s: %s", file_path, exc)
            raise HTTPClientError(f"File write error: {exc}") from exc

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Update session-level headers.

        Args:
            headers: Dictionary of header name-value pairs to set.
        """
        self._session.headers.update(headers)
        self.logger.info("Session headers updated")

    def close(self) -> None:
        """Close the underlying HTTP session and release resources."""
        self._session.close()
        self.logger.info("HTTP client session closed")
