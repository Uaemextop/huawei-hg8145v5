"""WordPress CMS detection."""

import re

from web_crawler.detection.base import BaseDetector


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
