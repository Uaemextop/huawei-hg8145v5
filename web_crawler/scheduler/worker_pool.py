"""Concurrent worker pool and URL scheduler."""

from __future__ import annotations

import logging
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

from web_crawler.config import MAX_QUEUE_SIZE

log = logging.getLogger(__name__)


class URLQueue:
    """Thread-safe URL queue with depth tracking and deduplication."""

    def __init__(self, max_size: int = MAX_QUEUE_SIZE) -> None:
        self._queue: deque[tuple[str, int]] = deque()
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._max_size = max_size

    def push(self, url: str, depth: int, *, priority: bool = False) -> bool:
        """Add URL to queue.  Returns True if actually enqueued."""
        with self._lock:
            if url in self._seen:
                return False
            if len(self._queue) >= self._max_size:
                return False
            self._seen.add(url)
            if priority:
                self._queue.appendleft((url, depth))
            else:
                self._queue.append((url, depth))
            return True

    def pop(self) -> Optional[tuple[str, int]]:
        """Remove and return the next (url, depth) or None."""
        with self._lock:
            return self._queue.popleft() if self._queue else None

    def pop_batch(self, n: int) -> list[tuple[str, int]]:
        """Remove and return up to *n* items."""
        with self._lock:
            batch = []
            for _ in range(min(n, len(self._queue))):
                batch.append(self._queue.popleft())
            return batch

    def mark_visited(self, url: str) -> None:
        """Mark URL as visited without enqueueing."""
        with self._lock:
            self._seen.add(url)

    @property
    def visited_count(self) -> int:
        with self._lock:
            return len(self._seen)

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._queue)


class CrawlScheduler:
    """Manages a URL queue and dispatches work to concurrent workers."""

    def __init__(
        self,
        worker_fn: Callable[[str, int], None],
        concurrency: int = 4,
        max_queue_size: int = MAX_QUEUE_SIZE,
    ) -> None:
        self._worker_fn = worker_fn
        self._concurrency = concurrency
        self.queue = URLQueue(max_size=max_queue_size)
        self._stats: dict[str, int] = {"processed": 0, "errors": 0}
        self._lock = threading.Lock()

    def enqueue(self, url: str, depth: int, *, priority: bool = False) -> bool:
        """Add a URL to the work queue."""
        return self.queue.push(url, depth, priority=priority)

    def run(self, progress_callback: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        """Process the queue using a thread pool."""
        if self._concurrency <= 1:
            self._run_serial(progress_callback)
        else:
            self._run_concurrent(progress_callback)

    def _run_serial(self, progress_callback: Optional[Callable] = None) -> None:
        while self.queue:
            item = self.queue.pop()
            if item is None:
                break
            url, depth = item
            try:
                self._worker_fn(url, depth)
                with self._lock:
                    self._stats["processed"] += 1
            except Exception:
                log.warning("Worker error on %s", url, exc_info=True)
                with self._lock:
                    self._stats["errors"] += 1
            if progress_callback:
                progress_callback(self._stats)

    def _run_concurrent(self, progress_callback: Optional[Callable] = None) -> None:
        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            while self.queue:
                batch = self.queue.pop_batch(self._concurrency * 2)
                if not batch:
                    break
                futures = {
                    pool.submit(self._worker_fn, url, depth): url
                    for url, depth in batch
                }
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        future.result()
                        with self._lock:
                            self._stats["processed"] += 1
                    except Exception:
                        log.warning("Worker error on %s", url, exc_info=True)
                        with self._lock:
                            self._stats["errors"] += 1
                if progress_callback:
                    progress_callback(self._stats)

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)
