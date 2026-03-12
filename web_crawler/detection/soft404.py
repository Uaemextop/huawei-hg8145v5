"""Soft-404 page detection."""

import hashlib
import re

from web_crawler.detection.base import BaseDetector

# Keywords commonly found in custom 404 pages
_SOFT404_KEYWORDS = (
    "page not found", "404 not found", "not found",
    "does not exist", "no longer available",
    "we couldn't find", "could not be found",
    "page you requested", "page you are looking for",
    "nothing here", "oops",
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)


class Soft404Detector(BaseDetector):
    """Detect soft-404 pages (200 status but actually a 'not found' page)."""

    name = "soft404"

    def __init__(self) -> None:
        self._baseline_hash: str | None = None
        self._baseline_size: int | None = None

    def set_baseline(self, body: str) -> None:
        """Set the baseline fingerprint from a known-404 page."""
        data = body.encode("utf-8", errors="replace")
        self._baseline_hash = hashlib.sha256(data).hexdigest()[:16]
        self._baseline_size = len(data)

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if status_code != 200 or not body:
            return None

        data = body.encode("utf-8", errors="replace")
        h = hashlib.sha256(data).hexdigest()[:16]

        # Layer 1: exact hash match with baseline
        if self._baseline_hash and h == self._baseline_hash:
            return {"type": "soft404", "method": "hash_match"}

        # Layer 2: size similarity + keyword check
        if self._baseline_size:
            size_ratio = len(data) / max(self._baseline_size, 1)
            if 0.8 < size_ratio < 1.2:
                body_lower = body.lower()
                for kw in _SOFT404_KEYWORDS:
                    if kw in body_lower:
                        return {"type": "soft404", "method": "size_keyword",
                                "keyword": kw}

        # Layer 3: title keyword check
        title_match = _TITLE_RE.search(body)
        if title_match:
            title = title_match.group(1).lower().strip()
            for kw in ("404", "not found", "page not found"):
                if kw in title:
                    return {"type": "soft404", "method": "title", "keyword": kw}

        return None
