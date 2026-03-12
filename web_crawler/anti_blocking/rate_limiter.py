"""Request rate limiter with adaptive delay."""

from __future__ import annotations

import logging
import random
import threading
import time

log = logging.getLogger(__name__)


class RateLimiter:
    """Thread-safe rate limiter with adaptive delay and jitter."""

    def __init__(self, base_delay: float = 0.25, max_delay: float = 60.0) -> None:
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._current_delay = base_delay
        self._consecutive_blocks = 0
        self._lock = threading.Lock()
        self._last_request: float = 0.0

    def wait(self) -> None:
        """Block until the next request is allowed."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            delay = self._current_delay
            sleep_time = (delay - elapsed + random.uniform(0, 0.1)) if elapsed < delay else 0.0
            self._last_request = time.monotonic() + max(sleep_time, 0.0)

        if sleep_time > 0:
            time.sleep(sleep_time)

    def report_success(self) -> None:
        """Signal a successful request to reduce delay."""
        with self._lock:
            self._consecutive_blocks = 0
            self._current_delay = self._base_delay

    def report_block(self, retry_after: float = 0) -> None:
        """Signal a blocked/429 response to increase delay."""
        with self._lock:
            self._consecutive_blocks += 1
            if retry_after > 0:
                self._current_delay = min(retry_after, self._max_delay)
            else:
                self._current_delay = min(
                    self._base_delay * (2 ** self._consecutive_blocks),
                    self._max_delay,
                )
            log.debug("Rate limiter delay increased to %.1fs", self._current_delay)

    @property
    def current_delay(self) -> float:
        with self._lock:
            return self._current_delay
