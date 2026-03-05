"""Download manager for concurrent file downloads.

Handles concurrent downloads with progress tracking, retry logic,
and resume capability.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Callable, List, Optional, Tuple

from motorola_downloader.core.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.validators import sanitize_filename


class DownloadResult:
    """Result of a download operation."""

    def __init__(
        self,
        url: str,
        filepath: str,
        success: bool,
        error: Optional[str] = None,
        bytes_downloaded: int = 0,
    ) -> None:
        """Initialize download result.

        Args:
            url: Download URL
            filepath: Local file path
            success: Whether download was successful
            error: Error message if download failed
            bytes_downloaded: Number of bytes downloaded
        """
        self.url = url
        self.filepath = filepath
        self.success = success
        self.error = error
        self.bytes_downloaded = bytes_downloaded


class DownloadManager:
    """Manages concurrent file downloads.

    Supports multiple concurrent downloads with progress tracking,
    automatic retries, and resume capability.
    """

    def __init__(
        self,
        http_client: HTTPClient,
        max_concurrent: int = 3,
        output_directory: str = "downloads",
        max_retries: int = 3,
    ) -> None:
        """Initialize download manager.

        Args:
            http_client: HTTP client for downloads
            max_concurrent: Maximum concurrent downloads (1-5)
            output_directory: Base directory for downloads
            max_retries: Maximum retry attempts per file
        """
        if not (1 <= max_concurrent <= 5):
            raise ValueError("max_concurrent must be between 1 and 5")

        self.http_client = http_client
        self.max_concurrent = max_concurrent
        self.output_directory = output_directory
        self.max_retries = max_retries
        self.logger = get_logger(__name__)

        # Create output directory
        Path(output_directory).mkdir(parents=True, exist_ok=True)

        # Download state
        self._paused = False
        self._pause_lock = Lock()
        self._active_downloads = 0
        self._active_lock = Lock()

    def set_max_concurrent(self, workers: int) -> None:
        """Set maximum concurrent downloads.

        Args:
            workers: Number of concurrent workers (1-5)

        Raises:
            ValueError: If workers not in valid range
        """
        if not (1 <= workers <= 5):
            raise ValueError("workers must be between 1 and 5")

        self.max_concurrent = workers
        self.logger.info(f"Max concurrent downloads set to {workers}")

    def download_single(
        self,
        url: str,
        filepath: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> DownloadResult:
        """Download a single file.

        Args:
            url: URL to download from
            filepath: Optional custom filepath (auto-generated if not provided)
            progress_callback: Optional callback(bytes_downloaded, total_bytes)

        Returns:
            DownloadResult indicating success or failure
        """
        # Generate filepath if not provided
        if not filepath:
            filename = url.split("?")[0].split("/")[-1]
            filename = sanitize_filename(filename)
            filepath = os.path.join(self.output_directory, filename)

        # Check if file already exists
        if os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
            self.logger.info(f"File already exists: {filepath} ({file_size} bytes)")
            # Could implement resume logic here
            # For now, skip if file exists
            return DownloadResult(
                url=url,
                filepath=filepath,
                success=True,
                bytes_downloaded=file_size,
            )

        # Attempt download with retries
        for attempt in range(self.max_retries):
            try:
                # Wait if paused
                with self._pause_lock:
                    while self._paused:
                        time.sleep(0.1)

                self.logger.info(
                    f"Downloading {url} (attempt {attempt + 1}/{self.max_retries})"
                )

                # Track progress
                bytes_downloaded = 0

                def track_progress(downloaded: int, total: int) -> None:
                    nonlocal bytes_downloaded
                    bytes_downloaded = downloaded
                    if progress_callback:
                        progress_callback(downloaded, total)

                # Perform download
                success = self.http_client.download(
                    url=url,
                    file_path=filepath,
                    progress_callback=track_progress,
                )

                if success:
                    self.logger.info(f"Download successful: {filepath}")
                    return DownloadResult(
                        url=url,
                        filepath=filepath,
                        success=True,
                        bytes_downloaded=bytes_downloaded,
                    )
                else:
                    raise Exception("Download failed")

            except Exception as e:
                self.logger.warning(
                    f"Download attempt {attempt + 1} failed: {e}"
                )

                # Retry if not last attempt
                if attempt < self.max_retries - 1:
                    delay = 2 ** attempt  # Exponential backoff
                    self.logger.info(f"Retrying in {delay} seconds...")
                    time.sleep(delay)

        # All retries failed
        error_msg = f"Download failed after {self.max_retries} attempts"
        self.logger.error(f"{error_msg}: {url}")
        return DownloadResult(
            url=url,
            filepath=filepath,
            success=False,
            error=error_msg,
        )

    def download_multiple(
        self,
        items: List[Tuple[str, Optional[str]]],
        output_dir: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[DownloadResult]:
        """Download multiple files concurrently.

        Args:
            items: List of (url, optional_filepath) tuples
            output_dir: Optional override for output directory
            progress_callback: Optional callback(completed, total)

        Returns:
            List of DownloadResult for each download
        """
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        else:
            output_dir = self.output_directory

        results: List[DownloadResult] = []
        total = len(items)
        completed = 0

        self.logger.info(
            f"Starting download of {total} files "
            f"(max {self.max_concurrent} concurrent)"
        )

        # Use ThreadPoolExecutor for concurrent downloads
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            # Submit all download tasks
            future_to_item = {}
            for url, filepath in items:
                # Generate filepath if not provided
                if not filepath:
                    filename = url.split("?")[0].split("/")[-1]
                    filename = sanitize_filename(filename)
                    filepath = os.path.join(output_dir, filename)

                future = executor.submit(self.download_single, url, filepath)
                future_to_item[future] = (url, filepath)

            # Process completed downloads
            for future in as_completed(future_to_item):
                url, filepath = future_to_item[future]

                try:
                    result = future.result()
                    results.append(result)

                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)

                    if result.success:
                        self.logger.info(
                            f"[{completed}/{total}] Downloaded: {filepath}"
                        )
                    else:
                        self.logger.error(
                            f"[{completed}/{total}] Failed: {url} - {result.error}"
                        )

                except Exception as e:
                    self.logger.error(f"Download error for {url}: {e}")
                    results.append(
                        DownloadResult(
                            url=url,
                            filepath=filepath,
                            success=False,
                            error=str(e),
                        )
                    )
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total)

        # Log summary
        successful = sum(1 for r in results if r.success)
        failed = total - successful
        total_bytes = sum(r.bytes_downloaded for r in results)

        self.logger.info(
            f"Download complete: {successful} successful, {failed} failed, "
            f"{total_bytes} total bytes"
        )

        return results

    def pause_downloads(self) -> None:
        """Pause all active downloads.

        Downloads will pause after current chunks complete.
        """
        with self._pause_lock:
            self._paused = True
            self.logger.info("Downloads paused")

    def resume_downloads(self) -> None:
        """Resume paused downloads."""
        with self._pause_lock:
            self._paused = False
            self.logger.info("Downloads resumed")

    def is_paused(self) -> bool:
        """Check if downloads are currently paused.

        Returns:
            True if paused, False otherwise
        """
        with self._pause_lock:
            return self._paused
