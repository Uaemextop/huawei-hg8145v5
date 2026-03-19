"""
Bootstrap detection.

Identifies websites using Bootstrap by checking for Bootstrap CDN
references in response headers, as well as ``bootstrap.min.css``,
``bootstrap.min.js``, ``bootstrap.bundle``, and common Bootstrap
CSS class patterns in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["BootstrapDetector"]


class BootstrapDetector(BaseDetector):
    """Detect Bootstrap CSS/JS framework usage on websites."""

    name = "bootstrap"

    _SIGNATURES = (
        "bootstrap.min.css",
        "bootstrap.min.js",
        "bootstrap.css",
        "bootstrap.js",
        "bootstrap.bundle",
        'class="btn btn-',
        'class="container',
        'class="navbar',
    )

    _CDN_MARKERS = (
        "bootstrapcdn.com",
        "bootstrap.min.css",
        "bootstrap.min.js",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers for Bootstrap CDN references (e.g. Link header)
        link_header = headers.get("link", "")
        for marker in self._CDN_MARKERS:
            if marker in link_header:
                return {"type": "bootstrap", "method": "header",
                        "signature": marker}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "bootstrap", "method": "body",
                            "signature": sig}

        return None
