"""Concurrent download manager for Motorola Firmware Downloader.

Provides reliable, concurrent file downloads with:
- ThreadPoolExecutor for parallel downloads
- Configurable concurrency (1-5 workers)
- Download resume support
- Progress tracking with speed and ETA
- Automatic retry with exponential backoff

Key patterns from web_crawler analysis:
  - Streaming mode for large binary files (not buffered in RAM)
  - S3 downloads use DOWNLOAD_USER_AGENT (IE8-style) via HeaderManager
  - Public CDN downloads (download.lenovo.com) need no auth
  - Range header for resume (matching session.py pattern)
  - Conditional requests with ETag/If-None-Match for cache validation
"""

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from motorola_downloader.exceptions import DownloadError
from motorola_downloader.settings import Settings
from motorola_downloader.utils.headers import HeaderManager
from motorola_downloader.utils.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.url_utils import get_host, classify_download_url, extract_filename
from motorola_downloader.utils.validators import validate_file_path, validate_url

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_CONCURRENT = 3
MIN_CONCURRENT = 1
MAX_CONCURRENT = 5
DEFAULT_CHUNK_SIZE = 8192
DEFAULT_MAX_RETRIES = 3
BACKOFF_BASE = 1.0

# Try to import tqdm for progress bars
try:
    from tqdm import tqdm
    _TQDM_AVAILABLE = True
except ImportError:
    _TQDM_AVAILABLE = False


class DownloadItem:
    """Represents a single download task.

    Attributes:
        url: Download URL.
        filepath: Local destination path.
        filename: Display name for the file.
        file_size: Expected file size in bytes (0 if unknown).
        checksum: Expected file checksum for verification.
    """

    def __init__(
        self,
        url: str,
        filepath: str,
        filename: str = "",
        file_size: int = 0,
        checksum: str = "",
    ) -> None:
        """Initialize a DownloadItem.

        Args:
            url: Download URL (must be HTTPS).
            filepath: Local file path to save to.
            filename: Human-readable filename for display.
            file_size: Expected file size in bytes.
            checksum: Expected checksum for integrity verification.
        """
        self.url = url
        self.filepath = filepath
        self.filename = filename or os.path.basename(filepath)
        self.file_size = file_size
        self.checksum = checksum


class DownloadProgress:
    """Tracks download progress for a single file.

    Thread-safe progress tracker that calculates download speed
    and estimated time remaining.
    """

    def __init__(self, total_size: int = 0) -> None:
        """Initialize DownloadProgress.

        Args:
            total_size: Total expected file size in bytes.
        """
        self.total_size = total_size
        self.downloaded = 0
        self.start_time = time.time()
        self.speed = 0.0
        self.eta_seconds = 0.0
        self.completed = False
        self.failed = False
        self.error_message = ""
        self._lock = threading.Lock()

    def update(self, bytes_downloaded: int) -> None:
        """Update the download progress.

        Args:
            bytes_downloaded: Total bytes downloaded so far.
        """
        with self._lock:
            self.downloaded = bytes_downloaded
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                self.speed = self.downloaded / elapsed
            if self.speed > 0 and self.total_size > 0:
                remaining = self.total_size - self.downloaded
                self.eta_seconds = remaining / self.speed

    def get_speed_str(self) -> str:
        """Get human-readable download speed string.

        Returns:
            Formatted speed string (e.g., '1.5 MB/s').
        """
        if self.speed < 1024:
            return f"{self.speed:.0f} B/s"
        elif self.speed < 1024 * 1024:
            return f"{self.speed / 1024:.1f} KB/s"
        else:
            return f"{self.speed / (1024 * 1024):.1f} MB/s"

    def get_eta_str(self) -> str:
        """Get human-readable ETA string.

        Returns:
            Formatted ETA string (e.g., '2m 30s').
        """
        if self.eta_seconds <= 0:
            return "calculating..."
        minutes = int(self.eta_seconds // 60)
        seconds = int(self.eta_seconds % 60)
        if minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    def get_percent(self) -> float:
        """Get download completion percentage.

        Returns:
            Completion percentage (0.0 to 100.0).
        """
        if self.total_size <= 0:
            return 0.0
        return min(100.0, (self.downloaded / self.total_size) * 100)


class DownloadManager:
    """Manages concurrent file downloads with retry and progress tracking.

    Uses ThreadPoolExecutor to download multiple files simultaneously
    with configurable concurrency, automatic retry, and resume support.

    Args:
        settings: Application settings instance.
        http_client: Optional shared HTTP client.
    """

    def __init__(
        self,
        settings: Settings,
        http_client: Optional[HTTPClient] = None,
        header_manager: Optional[HeaderManager] = None,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize the DownloadManager.

        Args:
            settings: Application settings for download configuration.
            http_client: Optional shared HTTP client instance.
            header_manager: Optional HeaderManager for download-specific headers.
            auth_headers: Optional fallback authentication headers.
        """
        self._settings = settings
        self._http_client = http_client or HTTPClient(
            timeout=settings.get_int("download", "timeout", fallback=60)
        )
        self._header_manager = header_manager or HeaderManager(
            client_version=settings.get("motorola_server", "client_version", fallback="7.5.4.2"),
            guid=settings.get("motorola_server", "guid", fallback=""),
        )
        self._auth_headers = auth_headers or {}
        self.logger = get_logger(__name__)

        self._max_concurrent: int = min(
            MAX_CONCURRENT,
            max(MIN_CONCURRENT,
                settings.get_int("download", "max_concurrent_downloads",
                                 fallback=DEFAULT_MAX_CONCURRENT)),
        )
        self._chunk_size: int = settings.get_int(
            "download", "chunk_size", fallback=DEFAULT_CHUNK_SIZE
        )
        self._max_retries: int = settings.get_int(
            "download", "max_retries", fallback=DEFAULT_MAX_RETRIES
        )
        self._output_dir: str = settings.get(
            "download", "output_directory", fallback="downloads"
        )

        self._paused = threading.Event()
        self._paused.set()  # Not paused by default
        self._progress: Dict[str, DownloadProgress] = {}

        # Ensure output directory exists
        Path(self._output_dir).mkdir(parents=True, exist_ok=True)

    def download_single(
        self,
        url: str,
        filepath: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Download a single file with retry support.

        Uses HeaderManager to select the correct User-Agent per host:
        - S3 hosts (rsddownload-secure.lenovo.com): IE8 DOWNLOAD_USER_AGENT
        - Public hosts (download.lenovo.com): browser UA, no auth
        - Other hosts: browser UA with auth headers

        Args:
            url: Download URL (must be HTTPS).
            filepath: Local file path to save to.
            headers: Optional additional HTTP headers.

        Returns:
            True if download was successful.

        Raises:
            DownloadError: If the download fails after all retries.
        """
        if not validate_url(url):
            raise DownloadError(f"Invalid download URL: {url}")

        if not validate_file_path(filepath):
            raise DownloadError(f"Invalid file path: {filepath}")

        filename = os.path.basename(filepath)
        host = get_host(url)
        url_class = classify_download_url(url)
        self.logger.info("Starting download: %s (host=%s, type=%s)", filename, host, url_class)

        # Create parent directory
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        progress = DownloadProgress()
        self._progress[filename] = progress

        for attempt in range(1, self._max_retries + 1):
            try:
                # Check for partial download to resume
                resume_byte = 0
                if os.path.exists(filepath):
                    resume_byte = os.path.getsize(filepath)
                    if resume_byte > 0:
                        self.logger.info(
                            "Resuming %s from byte %d", filename, resume_byte
                        )

                # Use HeaderManager to build proper download headers per host
                download_headers = self._header_manager.get_download_headers(
                    host=host,
                    resume_byte=resume_byte,
                )

                # Override with any caller-provided headers
                if headers:
                    download_headers.update(headers)

                bytes_downloaded = self._http_client.download(
                    url=url,
                    file_path=filepath,
                    chunk_size=self._chunk_size,
                    headers=download_headers,
                    resume_byte=resume_byte,
                )

                progress.downloaded = resume_byte + bytes_downloaded
                progress.completed = True
                self.logger.info(
                    "Download complete: %s (%d bytes)", filename, progress.downloaded
                )
                return True

            except Exception as exc:
                self.logger.warning(
                    "Download attempt %d/%d failed for %s: %s",
                    attempt, self._max_retries, filename, exc,
                )

                if attempt < self._max_retries:
                    delay = BACKOFF_BASE * (2 ** (attempt - 1))
                    self.logger.info("Retrying in %.1f seconds...", delay)
                    time.sleep(delay)

        progress.failed = True
        progress.error_message = "Download failed after all retry attempts"
        raise DownloadError(
            f"Download failed for {filename} after {self._max_retries} attempts"
        )

    def download_multiple(
        self,
        items: List[DownloadItem],
        output_dir: Optional[str] = None,
    ) -> Dict[str, bool]:
        """Download multiple files concurrently.

        Args:
            items: List of DownloadItem objects to download.
            output_dir: Optional override for the output directory.

        Returns:
            Dictionary mapping filenames to success status (True/False).
        """
        download_dir = output_dir or self._output_dir
        Path(download_dir).mkdir(parents=True, exist_ok=True)

        results: Dict[str, bool] = {}
        self.logger.info(
            "Starting batch download: %d files (max %d concurrent)",
            len(items), self._max_concurrent,
        )

        with ThreadPoolExecutor(max_workers=self._max_concurrent) as executor:
            future_to_item: Dict[Future[bool], DownloadItem] = {}

            for item in items:
                filepath = item.filepath
                if not os.path.isabs(filepath):
                    filepath = os.path.join(download_dir, os.path.basename(filepath))

                future = executor.submit(
                    self._download_with_pause, item.url, filepath
                )
                future_to_item[future] = item

            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    success = future.result()
                    results[item.filename] = success
                except Exception as exc:
                    self.logger.error(
                        "Download failed for %s: %s", item.filename, exc
                    )
                    results[item.filename] = False

        successful = sum(1 for v in results.values() if v)
        failed = sum(1 for v in results.values() if not v)
        self.logger.info(
            "Batch download complete: %d succeeded, %d failed",
            successful, failed,
        )

        return results

    def _download_with_pause(self, url: str, filepath: str) -> bool:
        """Download a file with pause support.

        Waits for the pause event before proceeding with the download.

        Args:
            url: Download URL.
            filepath: Destination file path.

        Returns:
            True if download was successful.
        """
        self._paused.wait()  # Block if paused
        return self.download_single(url, filepath)

    def set_max_concurrent(self, workers: int) -> None:
        """Set the maximum number of concurrent downloads.

        Args:
            workers: Number of concurrent workers (1-5).
        """
        clamped = min(MAX_CONCURRENT, max(MIN_CONCURRENT, workers))
        self._max_concurrent = clamped
        self.logger.info("Max concurrent downloads set to %d", clamped)

    def pause_downloads(self) -> None:
        """Pause all active downloads.

        Downloads in progress will complete their current chunk
        before pausing.
        """
        self._paused.clear()
        self.logger.info("Downloads paused")

    def resume_downloads(self) -> None:
        """Resume paused downloads."""
        self._paused.set()
        self.logger.info("Downloads resumed")

    def get_progress(self, filename: str) -> Optional[DownloadProgress]:
        """Get the progress tracker for a specific download.

        Args:
            filename: Name of the file being downloaded.

        Returns:
            DownloadProgress object, or None if not found.
        """
        return self._progress.get(filename)

    def get_all_progress(self) -> Dict[str, DownloadProgress]:
        """Get progress trackers for all downloads.

        Returns:
            Dictionary mapping filenames to DownloadProgress objects.
        """
        return dict(self._progress)

    @property
    def output_directory(self) -> str:
        """Get the current output directory.

        Returns:
            Output directory path string.
        """
        return self._output_dir
