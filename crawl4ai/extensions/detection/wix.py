"""
Wix detection.

Identifies Wix-powered websites by checking body signatures such as
``wix.com``, ``parastorage.com``, ``wixstatic.com``, ``X-Wix-``,
``wix-code-``, and ``_wix_browser_sess``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["WixDetector"]


class WixDetector(BaseDetector):
    """Detect Wix-powered websites."""

    name = "wix"

    _SIGNATURES = (
        "wix.com",
        "parastorage.com",
        "wixstatic.com",
        "X-Wix-",
        "wix-code-",
        "_wix_browser_sess",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check for X-Wix-* headers
        for key in headers:
            if key.lower().startswith("x-wix-"):
                return {"type": "wix", "method": "header", "signature": key}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "wix", "method": "body",
                            "signature": sig}

        return None
