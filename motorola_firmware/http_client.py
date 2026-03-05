"""
Reusable HTTP client with retry and HTTPS enforcement.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from motorola_firmware.logger import get_logger
from motorola_firmware.validators import validate_url


class HttpClient:
    """Thin wrapper around :mod:`requests` with sensible defaults."""

    def __init__(
        self,
        timeout: int = 30,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.logger = get_logger(__name__)
        self.timeout = timeout
        self._session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset({"GET", "POST"}),
        )
        adapter = HTTPAdapter(max_retries=retries)
        self._session.mount("https://", adapter)
        self._session.headers.update(
            {
                "User-Agent": "MotorolaFirmwareDownloader/0.1",
                "Accept": "application/json",
                "Connection": "keep-alive",
            },
        )
        if headers:
            self._session.headers.update(headers)

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Update default headers for subsequent requests."""
        self._session.headers.update(headers)

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Response:
        """Perform a GET request with HTTPS enforcement."""
        self._assert_https(url)
        try:
            response = self._session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            self.logger.error("GET request failed: %s", exc)
            raise

    def post(self, url: str, json_data: Optional[Dict[str, Any]] = None) -> Response:
        """Perform a POST request with HTTPS enforcement."""
        self._assert_https(url)
        try:
            response = self._session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            self.logger.error("POST request failed: %s", exc)
            raise

    def download(self, url: str, file_path: Path, chunk_size: int = 8192) -> Path:
        """Download a file with support for resume."""
        self._assert_https(url)
        headers: Dict[str, str] = {}
        existing_bytes = file_path.stat().st_size if file_path.exists() else 0
        if existing_bytes:
            headers["Range"] = f"bytes={existing_bytes}-"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._session.get(
                url,
                stream=True,
                headers=headers,
                timeout=self.timeout,
            ) as response:
                response.raise_for_status()
                mode = "ab" if existing_bytes else "wb"
                with open(file_path, mode) as fh:
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if chunk:
                            fh.write(chunk)
            return file_path
        except requests.RequestException as exc:
            self.logger.error("Download failed for %s: %s", url, exc)
            raise

    def close(self) -> None:
        """Close the underlying session."""
        self._session.close()

    def _assert_https(self, url: str) -> None:
        if not validate_url(url, allow_http=False):
            raise ValueError("Only HTTPS URLs are permitted")
