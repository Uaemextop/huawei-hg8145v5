"""
Google AMP (Accelerated Mobile Pages) detection.

Identifies AMP pages by checking for ``<html amp``, ``<html ⚡``,
``cdn.ampproject.org``, and ``<amp-`` component tags in the body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["AMPDetector"]


class AMPDetector(BaseDetector):
    """Detect Google AMP pages."""

    name = "amp"

    _BODY_SIGNATURES = (
        "<html amp",
        "<html ⚡",
        "cdn.ampproject.org",
        "<amp-",
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

        body_lower = body.lower()
        for sig in self._BODY_SIGNATURES:
            if sig.lower() in body_lower:
                return {"type": "amp", "method": "body",
                        "signature": sig}

        return None
