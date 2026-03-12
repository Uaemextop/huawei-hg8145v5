"""Block and protection detection utilities."""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


class BlockDetector:
    """Analyse HTTP responses for signs of blocking or rate limiting."""

    # Status codes that typically indicate blocking
    BLOCK_STATUS_CODES = frozenset({403, 429, 503, 520, 521, 522, 523, 524})

    def is_blocked(self, status_code: int, headers: dict[str, str], body: str = "") -> bool:
        """Return True if the response appears to be a block page."""
        if status_code == 429:
            return True
        if status_code in self.BLOCK_STATUS_CODES:
            snippet = body[:2048].lower()
            block_indicators = [
                "access denied", "rate limit", "too many requests",
                "blocked", "forbidden", "captcha",
            ]
            if any(ind in snippet for ind in block_indicators):
                return True
        return False

    def get_retry_after(self, headers: dict[str, str]) -> float:
        """Extract Retry-After delay from response headers."""
        val = headers.get("Retry-After", headers.get("retry-after", ""))
        if val:
            try:
                return float(val)
            except ValueError:
                pass
        return 0.0
