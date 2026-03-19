"""
Google Analytics / Google Tag Manager detection.

Identifies Google Analytics by searching for GA/GTM script references,
tracking IDs (``G-``, ``UA-``), and tag manager snippets in the body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["GoogleAnalyticsDetector"]


class GoogleAnalyticsDetector(BaseDetector):
    """Detect Google Analytics / GTM integration."""

    name = "google_analytics"

    _BODY_SIGNATURES = (
        "google-analytics.com",
        "googletagmanager.com",
        "gtag.js",
        "ga.js",
        "analytics.js",
        "gtm.js",
    )

    _TRACKING_ID_PREFIXES = (
        "G-",
        "UA-",
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
                return {"type": "google_analytics", "method": "body",
                        "signature": sig}

        for prefix in self._TRACKING_ID_PREFIXES:
            if prefix in body:
                return {"type": "google_analytics", "method": "body",
                        "signature": prefix}

        return None
