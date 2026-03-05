"""
Concurrent download manager for the Motorola Firmware Downloader.

Manages concurrent file downloads using ``ThreadPoolExecutor`` with
progress tracking, pause/resume, and automatic retry.

Modelled after the web_crawler's concurrent download approach using
``ThreadPoolExecutor`` in ``crawler.py``.
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from motorola_firmware.config import (
    DEFAULT_CONCURRENT_DOWNLOADS,
    MAX_CONCURRENT_DOWNLOADS,
    MAX_DOWNLOAD_RETRIES,
    MIN_CONCURRENT_DOWNLOADS,
    RETRY_BASE_DELAY,
)
from motorola_firmware.exceptions import DownloadError
from motorola_firmware.http_client import HttpClient
from motorola_firmware.session_manager import SessionManager
from motorola_firmware.settings import Settings
from motorola_firmware.utils.logger import log
from motorola_firmware.utils.validators import validate_file_path, validate_url


class DownloadItem:
    """Represents a single file to be downloaded.

    Attributes:
        url: Download URL.
        filename: Target filename.
        size_bytes: Expected file size.
        checksum: Expected file checksum.
        status: Current status (pending, downloading, completed, failed).
    """

    def __init__(
        self,
        url: str,
        filename: str,
        size_bytes: int = 0,
        checksum: str = "",
    ) -> None:
        """Initialize a download item.

        Args:
            url: Download URL.
            filename: Target filename.
            size_bytes: Expected file size in bytes.
            checksum: Expected file checksum.
        """
        self.url = url
        self.filename = filename
        self.size_bytes = size_bytes
        self.checksum = checksum
        self.downloaded_bytes = 0
        self.status = "pending"
        self.error_message = ""
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def get_speed(self) -> float:
        """Calculate current download speed in bytes per second.

        Returns:
            Download speed in bytes/second, or 0 if not downloading.
        """
        if not self.start_time or self.downloaded_bytes == 0:
            return 0.0
        elapsed = (self.end_time or time.time()) - self.start_time
        if elapsed <= 0:
            return 0.0
        return self.downloaded_bytes / elapsed

    def get_eta(self) -> float:
        """Estimate time remaining for the download.

        Returns:
            Estimated seconds remaining, or 0 if unknown.
        """
        speed = self.get_speed()
        if speed <= 0 or self.size_bytes <= 0:
            return 0.0
        remaining = self.size_bytes - self.downloaded_bytes
        return max(0.0, remaining / speed)


class DownloadProgress:
    """Thread-safe download progress tracker."""

    def __init__(self) -> None:
        """Initialize the progress tracker."""
        self._lock = threading.Lock()
        self._items: Dict[str, DownloadItem] = {}

    def register(self, item: DownloadItem) -> None:
        """Register a download item for tracking.

        Args:
            item: The download item to track.
        """
        with self._lock:
            self._items[item.url] = item

    def set_status(self, url: str, status: str) -> None:
        """Update the status of a download.

        Args:
            url: The download URL.
            status: New status string.
        """
        with self._lock:
            if url in self._items:
                self._items[url].status = status

    def get_summary(self) -> Dict[str, Any]:
        """Get aggregate download progress summary.

        Returns:
            Dictionary with total, completed, failed, and in-progress counts.
        """
        with self._lock:
            total = len(self._items)
            completed = sum(1 for i in self._items.values() if i.status == "completed")
            failed = sum(1 for i in self._items.values() if i.status == "failed")
            in_progress = sum(1 for i in self._items.values() if i.status == "downloading")
            return {
                "total": total,
                "completed": completed,
                "failed": failed,
                "in_progress": in_progress,
                "pending": total - completed - failed - in_progress,
            }


class DownloadManager:
    """Manages concurrent file downloads with progress tracking.

    Uses ``ThreadPoolExecutor`` (as in ``web_crawler.core.crawler``) for
    concurrent downloads with configurable worker count, automatic retry,
    and pause/resume support.

    Args:
        settings: Application settings instance.
        session_manager: Session manager for authenticated requests.
        http_client: HTTP client for download operations.
    """

    def __init__(
        self,
        settings: Settings,
        session_manager: SessionManager,
        http_client: HttpClient,
    ) -> None:
        """Initialize the download manager.

        Args:
            settings: Application settings.
            session_manager: Authenticated session manager.
            http_client: HTTP client for downloads.
        """
        self._settings = settings
        self._session_manager = session_manager
        self._http_client = http_client
        self._max_workers = self._get_configured_workers()
        self._progress = DownloadProgress()
        self._paused = threading.Event()
        self._paused.set()  # Not paused by default
        self._executor: Optional[ThreadPoolExecutor] = None

    def _get_configured_workers(self) -> int:
        """Get the configured number of concurrent workers (clamped 1–5)."""
        workers = self._settings.get_int(
            "download", "max_concurrent_downloads", DEFAULT_CONCURRENT_DOWNLOADS
        )
        return max(MIN_CONCURRENT_DOWNLOADS, min(MAX_CONCURRENT_DOWNLOADS, workers))

    def set_max_concurrent(self, workers: int) -> None:
        """Set the maximum number of concurrent downloads.

        Args:
            workers: Number of concurrent workers (1–5).

        Raises:
            ValueError: If workers is outside the allowed range.
        """
        if workers < MIN_CONCURRENT_DOWNLOADS or workers > MAX_CONCURRENT_DOWNLOADS:
            raise ValueError(
                f"Workers must be between {MIN_CONCURRENT_DOWNLOADS} and "
                f"{MAX_CONCURRENT_DOWNLOADS}"
            )
        self._max_workers = workers
        log.info("[DOWNLOAD] Max concurrent downloads set to %d", workers)

    def download_single(self, url: str, filepath: str) -> bool:
        """Download a single file with retry support.

        Args:
            url: The download URL (HTTPS).
            filepath: Local path to save the file.

        Returns:
            True if download completed successfully.

        Raises:
            DownloadError: If download fails after all retries.
        """
        if not validate_url(url, require_https=True):
            raise DownloadError(f"Invalid download URL: {url}")
        if not validate_file_path(filepath):
            raise DownloadError(f"Invalid file path: {filepath}")

        output_dir = os.path.dirname(filepath)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        item = DownloadItem(url=url, filename=os.path.basename(filepath))
        self._progress.register(item)

        for attempt in range(MAX_DOWNLOAD_RETRIES):
            try:
                self._paused.wait()  # Block if paused

                item.status = "downloading"
                item.start_time = time.time()
                self._progress.set_status(url, "downloading")

                log.info("[DOWNLOAD] %s (attempt %d/%d)",
                         item.filename, attempt + 1, MAX_DOWNLOAD_RETRIES)

                headers = self._session_manager.get_authenticated_headers()
                self._http_client.set_headers(headers)

                success = self._http_client.download(url, filepath)
                if success:
                    item.status = "completed"
                    item.end_time = time.time()
                    self._progress.set_status(url, "completed")
                    speed = item.get_speed()
                    log.info("[SAVE] Downloaded %s (%.1f KB/s)",
                             item.filename, speed / 1024 if speed else 0)
                    return True

            except Exception as error:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                log.warning(
                    "[RETRY] Download attempt %d failed for %s: %s. "
                    "Retrying in %.1fs",
                    attempt + 1, item.filename, error, delay,
                )
                if attempt < MAX_DOWNLOAD_RETRIES - 1:
                    time.sleep(delay)

        item.status = "failed"
        item.error_message = "All download attempts failed"
        self._progress.set_status(url, "failed")
        raise DownloadError(
            f"Download failed for {item.filename} after {MAX_DOWNLOAD_RETRIES} attempts"
        )

    def download_multiple(
        self,
        items: List[Dict[str, str]],
        output_dir: str,
    ) -> Dict[str, bool]:
        """Download multiple files concurrently.

        Args:
            items: List of dicts with ``url`` and ``filename`` keys.
            output_dir: Directory to save downloaded files.

        Returns:
            Dictionary mapping filenames to download success status.
        """
        if not validate_file_path(output_dir):
            raise DownloadError(f"Invalid output directory: {output_dir}")

        os.makedirs(output_dir, exist_ok=True)
        results: Dict[str, bool] = {}

        log.info("[DOWNLOAD] Starting batch: %d files (%d concurrent)",
                 len(items), self._max_workers)

        self._executor = ThreadPoolExecutor(max_workers=self._max_workers)
        futures: Dict[Future, Dict[str, str]] = {}

        try:
            for item_info in items:
                url = item_info.get("url", "")
                filename = item_info.get("filename", "")
                if not url or not filename:
                    log.warning("[SKIP] Item missing url or filename")
                    continue
                filepath = os.path.join(output_dir, filename)
                future = self._executor.submit(self.download_single, url, filepath)
                futures[future] = item_info

            for future in as_completed(futures):
                item_info = futures[future]
                filename = item_info.get("filename", "unknown")
                try:
                    results[filename] = future.result()
                except DownloadError as error:
                    results[filename] = False
                    log.error("[ERR] Download failed for %s: %s", filename, error)
                except Exception as error:
                    results[filename] = False
                    log.error("[ERR] Unexpected error for %s: %s", filename, error)
        finally:
            self._executor.shutdown(wait=True)
            self._executor = None

        successful = sum(1 for v in results.values() if v)
        failed_count = sum(1 for v in results.values() if not v)
        log.info("[DOWNLOAD] Batch complete: %d OK, %d failed", successful, failed_count)
        return results

    def pause_downloads(self) -> None:
        """Pause all active downloads."""
        self._paused.clear()
        log.info("[DOWNLOAD] Downloads paused")

    def resume_downloads(self) -> None:
        """Resume paused downloads."""
        self._paused.set()
        log.info("[DOWNLOAD] Downloads resumed")

    def get_progress(self) -> Dict[str, Any]:
        """Get the current download progress summary.

        Returns:
            Dictionary with download progress statistics.
        """
        return self._progress.get_summary()
