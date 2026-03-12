"""
URL scheduler and crawl-queue management.

Provides a thread-safe URL queue with deduplication, depth tracking,
priority support, and configurable rate limiting.  The scheduler
coordinates with concurrent workers in the main crawler.
"""

from __future__ import annotations

import threading
import time
import urllib.parse
from collections import deque
from typing import NamedTuple

from web_crawler.utils.url import url_key


class CrawlTask(NamedTuple):
    """A single unit of work for a crawler worker."""
    url: str
    depth: int
    priority: bool = False


class Scheduler:
    """Thread-safe URL scheduler with deduplication and rate control.

    Parameters
    ----------
    delay : float
        Minimum seconds between issuing tasks (rate limit).
    max_depth : int
        Maximum allowed crawl depth (0 = unlimited).
    max_queue : int
        Hard cap on queue size to prevent memory exhaustion.
    """

    def __init__(
        self,
        delay: float = 0.25,
        max_depth: int = 0,
        max_queue: int = 500_000,
    ) -> None:
        self._queue: deque[CrawlTask] = deque()
        self._visited: set[str] = set()
        self._lock = threading.Lock()
        self._delay = delay
        self._max_depth = max_depth
        self._max_queue = max_queue
        self._last_issue = 0.0

    @property
    def visited_count(self) -> int:
        with self._lock:
            return len(self._visited)

    @property
    def queue_size(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def is_empty(self) -> bool:
        with self._lock:
            return len(self._queue) == 0

    def enqueue(
        self,
        url: str,
        depth: int,
        *,
        priority: bool = False,
    ) -> bool:
        """Add *url* to the queue if not already visited/queued.

        Returns True if the URL was actually enqueued.
        """
        if self._max_depth and depth > self._max_depth:
            return False

        key = url_key(url)
        with self._lock:
            if key in self._visited:
                return False
            if len(self._queue) >= self._max_queue:
                return False
            self._visited.add(key)
            task = CrawlTask(url=url, depth=depth, priority=priority)
            if priority:
                self._queue.appendleft(task)
            else:
                self._queue.append(task)
            return True

    def mark_visited(self, url: str) -> None:
        """Mark a URL as visited without enqueuing it."""
        key = url_key(url)
        with self._lock:
            self._visited.add(key)

    def is_visited(self, url: str) -> bool:
        key = url_key(url)
        with self._lock:
            return key in self._visited

    def next_task(self) -> CrawlTask | None:
        """Pop the next task from the queue, respecting rate limits.

        Returns None when the queue is empty.
        """
        with self._lock:
            if not self._queue:
                return None
            # Rate limiting
            now = time.monotonic()
            elapsed = now - self._last_issue
            if elapsed < self._delay:
                time.sleep(self._delay - elapsed)
            self._last_issue = time.monotonic()
            return self._queue.popleft()

    def bulk_enqueue(
        self,
        urls: list[str],
        depth: int,
        *,
        priority: bool = False,
    ) -> int:
        """Enqueue multiple URLs, returning how many were actually added."""
        added = 0
        for url in urls:
            if self.enqueue(url, depth, priority=priority):
                added += 1
        return added
