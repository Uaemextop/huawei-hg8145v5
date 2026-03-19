"""
Drupal CMS detection.

Identifies Drupal-powered websites by checking for ``X-Drupal-Cache``,
``X-Drupal-Dynamic-Cache``, and ``X-Generator: Drupal`` response headers,
as well as ``Drupal.settings``, ``drupal.js``, and ``data-drupal-`` body
signatures.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["DrupalDetector"]


class DrupalDetector(BaseDetector):
    """Detect Drupal-powered websites."""

    name = "drupal"

    _SIGNATURES = (
        "Drupal.settings",
        "/sites/default/files/",
        "drupal.js",
        "/misc/drupal.js",
        "data-drupal-",
        "/core/misc/drupal.js",
    )

    _HEADER_KEYS = (
        "x-drupal-cache",
        "x-drupal-dynamic-cache",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers first (cheapest)
        for key in self._HEADER_KEYS:
            if key in headers:
                return {"type": "drupal", "method": "header", "signature": key}

        generator = headers.get("x-generator", "")
        if "Drupal" in generator:
            return {"type": "drupal", "method": "header",
                    "signature": "X-Generator: Drupal"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "drupal", "method": "body",
                            "signature": sig}

        return None
