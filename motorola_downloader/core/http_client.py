"""Centralized HTTP client for Motorola Firmware Downloader.

Provides unified interface for all HTTP operations with retry logic,
timeout handling, and proper header management.
"""

import time
from pathlib import Path
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from motorola_downloader.utils.logger import get_logger


# Default configuration
DEFAULT_TIMEOUT = 30
DEFAULT_CHUNK_SIZE = 8192
MAX_RETRIES = 3
BACKOFF_FACTOR = 1.0
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
)


class HTTPClient:
    """Centralized HTTP client with retry logic and timeout handling.

    Manages all HTTP requests with automatic retries, proper timeouts,
    and customizable headers.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        backoff_factor: float = BACKOFF_FACTOR,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize HTTP client.

        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            backoff_factor: Backoff multiplier for retries (1s, 2s, 4s, ...)
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.verify_ssl = verify_ssl
        self.logger = get_logger(__name__)

        # Create session with retry strategy
        self.session = self._create_session()

        # Default headers
        self._headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy.

        Returns:
            Configured requests.Session instance
        """
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )

        # Mount adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set SSL verification
        session.verify = self.verify_ssl

        return session

    def set_headers(self, headers: dict[str, str]) -> None:
        """Update default headers.

        Args:
            headers: Dictionary of headers to set/update
        """
        self._headers.update(headers)
        self.logger.debug(f"Updated HTTP headers: {list(headers.keys())}")

    def get_headers(self) -> dict[str, str]:
        """Get current default headers.

        Returns:
            Dictionary of current headers
        """
        return self._headers.copy()

    def get(
        self,
        url: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        """Perform HTTP GET request.

        Args:
            url: URL to request
            params: Optional query parameters
            headers: Optional additional headers
            timeout: Optional timeout override

        Returns:
            Response object if successful, None if failed

        Raises:
            requests.RequestException: If request fails after all retries
        """
        request_headers = self._headers.copy()
        if headers:
            request_headers.update(headers)

        request_timeout = timeout if timeout is not None else self.timeout

        try:
            self.logger.debug(f"GET {url}")
            response = self.session.get(
                url,
                params=params,
                headers=request_headers,
                timeout=request_timeout
            )
            response.raise_for_status()
            self.logger.debug(f"GET {url} -> {response.status_code}")
            return response

        except requests.exceptions.Timeout:
            self.logger.error(f"GET {url} timed out after {request_timeout}s")
            return None
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"GET {url} connection failed: {e}")
            return None
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"GET {url} HTTP error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"GET {url} failed: {e}")
            return None

    def post(
        self,
        url: str,
        json_data: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        """Perform HTTP POST request.

        Args:
            url: URL to request
            json_data: Optional JSON data to send
            data: Optional form data to send
            headers: Optional additional headers
            timeout: Optional timeout override

        Returns:
            Response object if successful, None if failed

        Raises:
            requests.RequestException: If request fails after all retries
        """
        request_headers = self._headers.copy()
        if headers:
            request_headers.update(headers)

        request_timeout = timeout if timeout is not None else self.timeout

        try:
            self.logger.debug(f"POST {url}")
            response = self.session.post(
                url,
                json=json_data,
                data=data,
                headers=request_headers,
                timeout=request_timeout
            )
            response.raise_for_status()
            self.logger.debug(f"POST {url} -> {response.status_code}")
            return response

        except requests.exceptions.Timeout:
            self.logger.error(f"POST {url} timed out after {request_timeout}s")
            return None
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"POST {url} connection failed: {e}")
            return None
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"POST {url} HTTP error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"POST {url} failed: {e}")
            return None

    def download(
        self,
        url: str,
        file_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        headers: Optional[dict[str, str]] = None,
        progress_callback: Optional[callable] = None,
    ) -> bool:
        """Download file from URL to local path.

        Args:
            url: URL to download from
            file_path: Local path to save file
            chunk_size: Size of chunks to download (bytes)
            headers: Optional additional headers
            progress_callback: Optional callback function(bytes_downloaded, total_bytes)

        Returns:
            True if download successful, False otherwise
        """
        request_headers = self._headers.copy()
        if headers:
            request_headers.update(headers)

        try:
            self.logger.info(f"Downloading {url} to {file_path}")

            # Create parent directory if it doesn't exist
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)

            # Stream download
            response = self.session.get(
                url,
                headers=request_headers,
                stream=True,
                timeout=self.timeout
            )
            response.raise_for_status()

            # Get total file size if available
            total_size = int(response.headers.get("content-length", 0))
            bytes_downloaded = 0

            # Download in chunks
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        bytes_downloaded += len(chunk)

                        # Call progress callback if provided
                        if progress_callback:
                            progress_callback(bytes_downloaded, total_size)

            self.logger.info(f"Download complete: {file_path} ({bytes_downloaded} bytes)")
            return True

        except requests.exceptions.Timeout:
            self.logger.error(f"Download {url} timed out")
            return False
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Download {url} connection failed: {e}")
            return False
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"Download {url} HTTP error: {e}")
            return False
        except IOError as e:
            self.logger.error(f"Failed to write file {file_path}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Download {url} failed: {e}")
            return False

    def close(self) -> None:
        """Close HTTP session and cleanup resources."""
        if self.session:
            self.session.close()
            self.logger.debug("HTTP session closed")
