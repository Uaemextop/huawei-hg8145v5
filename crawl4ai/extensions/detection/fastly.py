"""
Fastly CDN detection.

Identifies Fastly-served responses by inspecting ``x-served-by``,
``x-cache``, ``x-fastly-request-id``, and ``via`` headers.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["FastlyDetector"]


class FastlyDetector(BaseDetector):
    """Detect Fastly CDN."""

    name = "fastly"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        served_by = headers.get("x-served-by", "").lower()
        if "cache-" in served_by:
            return {"type": "fastly", "method": "header",
                    "signature": "x-served-by"}

        if headers.get("x-fastly-request-id"):
            return {"type": "fastly", "method": "header",
                    "signature": "x-fastly-request-id"}

        x_cache = headers.get("x-cache", "").lower()
        if x_cache and ("hit" in x_cache or "miss" in x_cache):
            via = headers.get("via", "").lower()
            if "varnish" in via:
                return {"type": "fastly", "method": "header",
                        "signature": "x-cache+via"}

        via = headers.get("via", "").lower()
        if "varnish" in via and served_by:
            return {"type": "fastly", "method": "header",
                    "signature": "via"}

        return None
