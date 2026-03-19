"""
Squarespace detection.

Identifies Squarespace-powered websites by checking body signatures such as
``squarespace.com``, ``sqsp.com``, ``Static.SQUARESPACE_CONTEXT``,
``squarespace-cdn.com``, and ``data-squarespace-`` attributes.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["SquarespaceDetector"]


class SquarespaceDetector(BaseDetector):
    """Detect Squarespace-powered websites."""

    name = "squarespace"

    _SIGNATURES = (
        "squarespace.com",
        "sqsp.com",
        "Static.SQUARESPACE_CONTEXT",
        "squarespace-cdn.com",
        "data-squarespace-",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check server header
        server = headers.get("server", "").lower()
        if "squarespace" in server:
            return {"type": "squarespace", "method": "header",
                    "signature": "server"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "squarespace", "method": "body",
                            "signature": sig}

        return None
