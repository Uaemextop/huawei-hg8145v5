"""
React.js detection.

Identifies React-powered websites by checking for ``data-reactroot``,
``data-reactid``, ``__NEXT_DATA__``, ``_reactRootContainer``, and
React library script references in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["ReactDetector"]


class ReactDetector(BaseDetector):
    """Detect React.js-powered websites."""

    name = "react"

    _SIGNATURES = (
        "data-reactroot",
        "data-reactid",
        "__NEXT_DATA__",
        "_reactRootContainer",
        "react.production.min.js",
        "react-dom.production.min.js",
        "react.development.js",
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
                return {"type": "react", "method": "body", "signature": sig}
        return None
