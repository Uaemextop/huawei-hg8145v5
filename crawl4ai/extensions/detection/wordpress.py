"""
WordPress detection.

Identifies WordPress-powered websites by checking for:
* ``wp-json`` / ``xmlrpc.php`` in the ``Link`` response header
* ``/wp-content/``, ``/wp-includes/``, ``/wp-json/``, generator meta tag,
  and ``wp-emoji-release.min.js`` in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["WordPressDetector"]


class WordPressDetector(BaseDetector):
    """Detect WordPress-powered websites."""

    name = "wordpress"

    _WP_SIGNATURES = (
        "/wp-content/",
        "/wp-includes/",
        "/wp-json/",
        "wp-emoji-release.min.js",
        'name="generator" content="WordPress',
    )

    _WP_HEADER_LINKS = (
        "wp-json",
        "xmlrpc.php",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check Link header
        link_header = headers.get("link", "")
        for sig in self._WP_HEADER_LINKS:
            if sig in link_header:
                return {"type": "wordpress", "method": "header"}

        # Check body signatures
        if body:
            for sig in self._WP_SIGNATURES:
                if sig in body:
                    return {"type": "wordpress", "method": "body",
                            "signature": sig}

        return None
