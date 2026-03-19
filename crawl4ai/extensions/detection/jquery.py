"""
jQuery detection.

Identifies websites using jQuery by checking for ``jquery.min.js``,
``jquery.js``, ``jquery-migrate``, ``jQuery.fn.jquery``, ``jquery-ui``,
and ``jquery.ui`` references in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["JQueryDetector"]


class JQueryDetector(BaseDetector):
    """Detect jQuery usage on websites."""

    name = "jquery"

    _SIGNATURES = (
        "jquery.min.js",
        "jquery.js",
        "jquery-migrate",
        "jQuery.fn.jquery",
        "jquery-ui",
        "jquery.ui",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if not body:
            return None
        for sig in self._SIGNATURES:
            if sig in body:
                return {"type": "jquery", "method": "body", "signature": sig}
        return None
