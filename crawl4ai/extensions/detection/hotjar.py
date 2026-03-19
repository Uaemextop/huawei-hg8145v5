"""
Hotjar analytics detection.

Identifies Hotjar integration by searching for ``static.hotjar.com``,
``_hjSettings``, ``hj(`` calls, and related markers in the body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["HotjarDetector"]


class HotjarDetector(BaseDetector):
    """Detect Hotjar analytics integration."""

    name = "hotjar"

    _BODY_SIGNATURES = (
        "static.hotjar.com",
        "hotjar.com",
        "_hjSettings",
        "hj(",
        "hjid",
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
                return {"type": "hotjar", "method": "body",
                        "signature": sig}

        return None
