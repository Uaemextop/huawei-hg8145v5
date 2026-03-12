"""
WordPress detection and discovery plugin.

Extracts all WordPress-specific logic that was previously hardcoded
in the main Crawler class — detection, REST API enumeration, plugin
/ theme probing, WooCommerce discovery, and nonce extraction.
"""

from __future__ import annotations

import re
from typing import Any

from web_crawler.plugins.base import BasePlugin


# ── WordPress detection signatures ─────────────────────────────────

_WP_INDICATORS: list[str] = [
    "wp-content/",
    "wp-includes/",
    'name="generator" content="wordpress',
    "/wp-json/",
    "wp-emoji-release.min.js",
]

_WP_NONCE_RE = re.compile(
    r"""(?:wp_rest_nonce|wpApiSettings[^}]*nonce)\W*[=:]\s*['"]([a-f0-9]+)['"]""",
    re.I,
)


class WordPressDetectorPlugin(BasePlugin):
    """Detect WordPress sites from HTML indicators."""

    name = "wordpress_detector"
    kind = "tech_detector"
    priority = 15

    def detect(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        lower = body[:65536].lower()
        is_wp = any(ind in lower for ind in _WP_INDICATORS)
        if not is_wp:
            # Also check Link header for WP REST API
            link_header = headers.get("Link", "") + headers.get("link", "")
            if "wp-json" in link_header.lower():
                is_wp = True
        if is_wp:
            result: dict[str, Any] = {
                "technologies": [{"name": "WordPress", "category": "cms"}],
                "wordpress": True,
            }
            # Try to extract nonce
            m = _WP_NONCE_RE.search(body[:65536])
            if m:
                result["wp_nonce"] = m.group(1)
            return result
        return {}


class WordPressEndpointPlugin(BasePlugin):
    """Discover WordPress-specific endpoints and links from page
    content — plugin/theme slugs, REST API paths, author pages."""

    name = "wordpress_endpoints"
    kind = "endpoint_discovery"
    priority = 30

    _PLUGIN_SLUG_RE = re.compile(
        r"/wp-content/plugins/([a-z0-9_-]+)/", re.I,
    )
    _THEME_SLUG_RE = re.compile(
        r"/wp-content/themes/([a-z0-9_-]+)/", re.I,
    )

    def extract_links(
        self,
        *,
        url: str,
        body: str,
        base: str,
        **kwargs: Any,
    ) -> set[str]:
        found: set[str] = set()
        # Discover plugin slugs referenced in the page
        for m in self._PLUGIN_SLUG_RE.finditer(body):
            slug = m.group(1)
            found.add(f"{base}/wp-content/plugins/{slug}/readme.txt")
        # Discover theme slugs
        for m in self._THEME_SLUG_RE.finditer(body):
            slug = m.group(1)
            found.add(f"{base}/wp-content/themes/{slug}/style.css")
        return found
