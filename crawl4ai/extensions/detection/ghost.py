"""
Ghost CMS detection.

Identifies Ghost-powered websites by checking for ``x-powered-by: Ghost``
in response headers and body signatures such as ``ghost-url``,
``content/themes/``, ``ghost-portal``, and ``@tryghost``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["GhostDetector"]


class GhostDetector(BaseDetector):
    """Detect Ghost-powered websites."""

    name = "ghost"

    _SIGNATURES = (
        "ghost-url",
        "content/themes/",
        "ghost.org",
        "ghost-portal",
        "ghost/portal",
        "@tryghost",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers
        powered_by = headers.get("x-powered-by", "")
        if "Ghost" in powered_by:
            return {"type": "ghost", "method": "header",
                    "signature": "x-powered-by: Ghost"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "ghost", "method": "body",
                            "signature": sig}

        return None
