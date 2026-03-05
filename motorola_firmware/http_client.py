"""
Reusable HTTP client for the Motorola Firmware Downloader.

Centralises all HTTP operations with automatic retry, timeout management,
HTTPS enforcement, and keep-alive connection pooling.

Modelled after ``web_crawler.session.build_session()``.
"""

import random
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from motorola_firmware.config import (
    DEFAULT_CHUNK_SIZE,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    USER_AGENTS,
)
from motorola_firmware.exceptions import HttpClientError
from motorola_firmware.utils.logger import log
from motorola_firmware.utils.validators import validate_url


def build_session(timeout: int = REQUEST_TIMEOUT) -> requests.Session:
    """Return a ``requests.Session`` with retry logic and keep-alive.

    Mirrors ``web_crawler.session.build_session()`` — provides automatic
    retry on 5xx errors, randomised User-Agent, and connection pooling.

    Args:
        timeout: Default request timeout in seconds.

    Returns:
        Configured requests.Session instance.
    """
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD"],
        connect=MAX_RETRIES,
        read=MAX_RETRIES,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json, text/html, */*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
    })
    return session


class HttpClient:
    """Centralised HTTP client with retry, timeout, and HTTPS enforcement.

    All network operations go through this client to ensure consistent
    error handling, logging, and security policies.

    Args:
        timeout: Default request timeout in seconds.
        headers: Optional default headers for all requests.
    """

    def __init__(
        self,
        timeout: int = REQUEST_TIMEOUT,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds.
            headers: Default HTTP headers to add.
        """
        self._timeout = timeout
        self._session = build_session(timeout)
        if headers:
            self._session.headers.update(headers)

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Update the default session headers.

        Args:
            headers: Dictionary of HTTP headers to set.
        """
        self._session.headers.update(headers)

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """Send an HTTP GET request.

        Args:
            url: The target URL (must be HTTPS).
            params: Optional query parameters.
            timeout: Optional timeout override.

        Returns:
            The HTTP response object.

        Raises:
            HttpClientError: If the request fails.
        """
        if not validate_url(url, require_https=True):
            raise HttpClientError(f"Invalid or non-HTTPS URL: {url}")

        try:
            response = self._session.get(
                url, params=params, timeout=timeout or self._timeout
            )
            response.raise_for_status()
            log.debug("[HTTP] GET %s → %d", url, response.status_code)
            return response
        except requests.exceptions.HTTPError as error:
            status = error.response.status_code if error.response is not None else "?"
            log.error("[HTTP] HTTP error on GET %s: %s", url, status)
            raise HttpClientError(f"HTTP error {status}: {error}") from error
        except requests.exceptions.ConnectionError as error:
            log.error("[HTTP] Connection error on GET %s: %s", url, error)
            raise HttpClientError(f"Connection failed for {url}") from error
        except requests.exceptions.Timeout as error:
            log.error("[HTTP] Timeout on GET %s", url)
            raise HttpClientError(f"Request timed out for {url}") from error
        except requests.exceptions.RequestException as error:
            log.error("[HTTP] Request error on GET %s: %s", url, error)
            raise HttpClientError(f"Request failed for {url}: {error}") from error

    def post(
        self,
        url: str,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """Send an HTTP POST request with JSON body.

        Args:
            url: The target URL (must be HTTPS).
            json_data: Optional JSON payload.
            timeout: Optional timeout override.

        Returns:
            The HTTP response object.

        Raises:
            HttpClientError: If the request fails.
        """
        if not validate_url(url, require_https=True):
            raise HttpClientError(f"Invalid or non-HTTPS URL: {url}")

        try:
            response = self._session.post(
                url, json=json_data, timeout=timeout or self._timeout
            )
            response.raise_for_status()
            log.debug("[HTTP] POST %s → %d", url, response.status_code)
            return response
        except requests.exceptions.HTTPError as error:
            status = error.response.status_code if error.response is not None else "?"
            log.error("[HTTP] HTTP error on POST %s: %s", url, status)
            raise HttpClientError(f"HTTP error {status}: {error}") from error
        except requests.exceptions.ConnectionError as error:
            log.error("[HTTP] Connection error on POST %s: %s", url, error)
            raise HttpClientError(f"Connection failed for {url}") from error
        except requests.exceptions.Timeout as error:
            log.error("[HTTP] Timeout on POST %s", url)
            raise HttpClientError(f"Request timed out for {url}") from error
        except requests.exceptions.RequestException as error:
            log.error("[HTTP] Request error on POST %s: %s", url, error)
            raise HttpClientError(f"Request failed for {url}: {error}") from error

    def download(
        self,
        url: str,
        file_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        resume: bool = True,
        timeout: Optional[int] = None,
    ) -> bool:
        """Download a file from a URL with optional resume support.

        Args:
            url: The file download URL (must be HTTPS).
            file_path: Local path to save the downloaded file.
            chunk_size: Download chunk size in bytes.
            resume: If True, attempt to resume partial downloads.
            timeout: Optional timeout override.

        Returns:
            True if download completed successfully.

        Raises:
            HttpClientError: If the download fails.
        """
        import os

        if not validate_url(url, require_https=True):
            raise HttpClientError(f"Invalid or non-HTTPS URL: {url}")

        headers: Dict[str, str] = {}
        mode = "wb"
        downloaded_bytes = 0

        if resume and os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
            downloaded_bytes = os.path.getsize(file_path)
            headers["Range"] = f"bytes={downloaded_bytes}-"
            mode = "ab"
            log.info("[DOWNLOAD] Resuming from byte %d", downloaded_bytes)

        try:
            response = self._session.get(
                url, headers=headers, stream=True,
                timeout=timeout or self._timeout,
            )
            response.raise_for_status()

            with open(file_path, mode) as output_file:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        output_file.write(chunk)

            log.info("[SAVE] Download complete: %s", file_path)
            return True

        except requests.exceptions.RequestException as error:
            log.error("[DOWNLOAD] Download failed for %s: %s", url, error)
            raise HttpClientError(f"Download failed for {url}: {error}") from error
        except OSError as error:
            log.error("[DOWNLOAD] File write error for %s: %s", file_path, error)
            raise HttpClientError(f"Cannot write to {file_path}: {error}") from error

    def close(self) -> None:
        """Close the HTTP session and release resources."""
        self._session.close()
        log.debug("[HTTP] Session closed")
