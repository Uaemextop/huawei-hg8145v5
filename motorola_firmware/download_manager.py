"""
Concurrent and resumable download management.
"""

from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from tqdm import tqdm

from motorola_firmware.http_client import HttpClient
from motorola_firmware.logger import get_logger
from motorola_firmware.settings import Settings
from motorola_firmware.validators import validate_url

MAX_RETRIES = 3


class DownloadManager:
    """Handle concurrent downloads with retry and pause/resume support."""

    def __init__(self, settings: Settings, http_client: HttpClient) -> None:
        self.settings = settings
        self.http_client = http_client
        self.logger = get_logger(__name__)
        self._paused = False
        self._max_workers = self._clamp_workers(
            settings.get_int("download", "max_concurrent_downloads", 3),
        )
        self._chunk_size = settings.get_int("download", "chunk_size", 8192)
        self._output_dir = Path(settings.get("download", "output_directory"))
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def set_max_concurrent(self, workers: int) -> None:
        """Update the worker pool size within the allowed bounds."""
        self._max_workers = self._clamp_workers(workers)
        self.logger.info("Max concurrent downloads set to %d", self._max_workers)

    def pause_downloads(self) -> None:
        """Pause ongoing downloads."""
        self._paused = True
        self.logger.warning("Downloads paused")

    def resume_downloads(self) -> None:
        """Resume paused downloads."""
        self._paused = False
        self.logger.info("Downloads resumed")

    def download_single(self, url: str, filepath: Path) -> Path:
        """Download a single file with retry logic."""
        if not validate_url(url, allow_http=False):
            raise ValueError("Invalid download URL")
        last_exc: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            if self._paused:
                self._wait_until_resumed()
            start = time.perf_counter()
            try:
                path = self.http_client.download(url, filepath, chunk_size=self._chunk_size)
                elapsed = time.perf_counter() - start
                size = path.stat().st_size if path.exists() else 0
                speed = (size / 1024 / 1024) / elapsed if elapsed > 0 else 0
                self.logger.info(
                    "Downloaded %s in %.2fs (%.2f MB/s)",
                    path.name,
                    elapsed,
                    speed,
                )
                return path
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                self.logger.warning(
                    "Download attempt %d failed for %s: %s",
                    attempt,
                    filepath.name,
                    exc,
                )
                time.sleep(2**attempt)
        if last_exc:
            raise last_exc
        raise RuntimeError("Download failed for unknown reason")

    def download_multiple(
        self,
        items: Iterable[Dict[str, str]],
        output_dir: Optional[Path] = None,
    ) -> List[Tuple[str, bool]]:
        """Download multiple files concurrently.

        Args:
            items: Iterable of mapping objects containing ``url`` and optional
                ``filename`` keys.
            output_dir: Destination directory; defaults to config value.

        Returns:
            List of tuples ``(url, success)``.
        """
        dest_dir = output_dir or self._output_dir
        dest_dir.mkdir(parents=True, exist_ok=True)
        results: List[Tuple[str, bool]] = []

        tasks = []
        for item in items:
            url = item.get("url", "")
            name = item.get("filename") or Path(url).name or "download.bin"
            tasks.append((url, dest_dir / name))

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers,
        ) as executor:
            futures = {
                executor.submit(self.download_single, url, path): url
                for url, path in tasks
            }
            with tqdm(total=len(futures), desc="Downloads", unit="file") as bar:
                for future in concurrent.futures.as_completed(futures):
                    url = futures[future]
                    try:
                        future.result()
                        results.append((url, True))
                    except Exception as exc:  # noqa: BLE001
                        self.logger.error("Download failed for %s: %s", url, exc)
                        results.append((url, False))
                    bar.update(1)
        return results

    def _wait_until_resumed(self) -> None:
        while self._paused:
            time.sleep(0.2)

    @staticmethod
    def _clamp_workers(workers: int) -> int:
        return max(1, min(5, workers))
