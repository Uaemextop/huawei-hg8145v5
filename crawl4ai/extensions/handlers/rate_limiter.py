"""Rate limiter handler – calculates optimal request delays from response headers."""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["RateLimiterHandler"]

# Default fallback delay (seconds) when a 429 is received but no headers exist
_DEFAULT_429_DELAY = 30
# Minimum delay we'll recommend
_MIN_DELAY = 0.5


class RateLimiterHandler(BaseHandler):
    """Analyse rate-limit response headers and recommend optimal delays.

    Trigger with detection type ``"rate_limit"``.
    """

    name = "rate_limiter"

    def can_handle(self, detection: dict) -> bool:
        """Return True for rate-limit detections."""
        return detection.get("type", "") == "rate_limit"

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Calculate an optimal delay and concurrency from response headers."""
        actions: list[str] = []
        config: dict = {}

        try:
            headers = _headers(response)
            status = _status(response)

            delay: float | None = None
            max_concurrent: int | None = None

            # 1. Retry-After (most authoritative)
            retry_after = headers.get("Retry-After") or headers.get("retry-after")
            if retry_after:
                delay = _parse_retry_after(retry_after)
                actions.append(f"Retry-After header → {delay} s")

            # 2. X-RateLimit-* / X-Rate-Limit-* family
            remaining = _int_header(headers, "X-RateLimit-Remaining", "X-Rate-Limit-Remaining")
            limit = _int_header(headers, "X-RateLimit-Limit", "X-Rate-Limit-Limit")
            reset_ts = _int_header(headers, "X-RateLimit-Reset", "X-Rate-Limit-Reset")

            if remaining is not None and remaining == 0 and reset_ts is not None:
                wait = max(0, reset_ts - int(time.time()))
                if delay is None or wait > delay:
                    delay = float(wait)
                actions.append(
                    f"Rate limit exhausted; reset in {wait} s"
                )

            if limit is not None and limit > 0 and delay is None:
                # Spread requests across the window (assume 60 s if no
                # window header is present – most APIs use per-minute limits)
                window = _int_header(
                    headers,
                    "X-RateLimit-Window", "X-Rate-Limit-Window",
                ) or 60
                delay = max(_MIN_DELAY, float(window) / limit)
                actions.append(
                    f"Rate limit {limit}/window → {delay:.1f} s between requests"
                )

            # 3. 429 fallback
            if status == 429 and delay is None:
                delay = float(_DEFAULT_429_DELAY)
                actions.append(
                    f"HTTP 429 with no headers → default {delay} s delay"
                )

            # Build recommended config
            if delay is not None:
                config["delay"] = max(_MIN_DELAY, delay)
            if max_concurrent is not None:
                config["max_concurrent"] = max_concurrent
            elif delay is not None and delay >= 5:
                config["max_concurrent"] = 1
                actions.append("High delay → max_concurrent set to 1")

            if not actions:
                actions.append("No rate-limit signals found in response")

        except Exception:
            log.debug("RateLimiterHandler error for %s", url, exc_info=True)
            actions.append("Error analysing rate-limit headers")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=[],
            extra_headers={},
            recommended_config=config,
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _headers(response: "requests.Response | None") -> dict:
    if response is None:
        return {}
    try:
        return dict(response.headers)
    except Exception:
        return {}


def _status(response: "requests.Response | None") -> int:
    if response is None:
        return 0
    try:
        return response.status_code
    except Exception:
        return 0


def _int_header(headers: dict, *names: str) -> int | None:
    """Return the first matching header value parsed as int, or None."""
    for name in names:
        val = headers.get(name)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
    return None


def _parse_retry_after(value: str) -> float:
    """Parse a Retry-After header (seconds or HTTP-date)."""
    try:
        return float(value)
    except ValueError:
        pass
    # Try HTTP-date (e.g. "Wed, 21 Oct 2015 07:28:00 GMT")
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(value)
        delta = dt.timestamp() - time.time()
        return max(0.0, delta)
    except Exception:
        return float(_DEFAULT_429_DELAY)
