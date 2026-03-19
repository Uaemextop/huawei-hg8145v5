"""
Progressive Web App (PWA) detection.

Identifies PWAs by searching for ``manifest.json``, Service Worker
registration (``navigator.serviceWorker``), and common SW filenames.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["PWADetector"]


class PWADetector(BaseDetector):
    """Detect Progressive Web App features."""

    name = "pwa"

    _BODY_SIGNATURES = (
        "manifest.json",
        "navigator.serviceWorker",
        "serviceWorker",
        "service-worker.js",
        "sw.js",
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
                return {"type": "pwa", "method": "body",
                        "signature": sig}

        return None
