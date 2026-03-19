"""
Facebook / Meta Pixel detection.

Identifies the Meta (Facebook) tracking pixel by searching for
``connect.facebook.net``, ``fbq(`` calls, and related SDK markers.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["FacebookPixelDetector"]


class FacebookPixelDetector(BaseDetector):
    """Detect Facebook / Meta Pixel integration."""

    name = "facebook_pixel"

    _BODY_SIGNATURES = (
        "connect.facebook.net",
        "fbq(",
        "facebook-jssdk",
        "fb-root",
        "facebook.com/tr",
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

        for sig in self._BODY_SIGNATURES:
            if sig in body:
                return {"type": "facebook_pixel", "method": "body",
                        "signature": sig}

        return None
