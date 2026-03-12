"""WordPress-specific crawling strategy plugin."""

from __future__ import annotations

from typing import Any

from web_crawler.config import (
    WP_DISCOVERY_PATHS,
    WP_PLUGIN_PROBES,
    WP_THEME_PROBES,
)
from web_crawler.plugins.registry import BasePlugin, PluginRegistry


class WordPressStrategy(BasePlugin):
    """Provide WordPress-specific discovery URLs when WP is detected."""

    @property
    def name(self) -> str:
        return "wordpress"

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        """Return WordPress discovery URLs to enqueue.

        *context* keys:
            ``base_url``      – site base URL (e.g. ``https://example.com``)
            ``technologies``  – list of detected tech dicts

        Returns dict with ``urls`` list of (url, priority) tuples.
        """
        techs = [t["name"] for t in context.get("technologies", [])]
        if "WordPress" not in techs:
            return {"urls": []}

        base = context.get("base_url", "").rstrip("/")
        urls: list[tuple[str, bool]] = []

        for path in WP_DISCOVERY_PATHS:
            urls.append((f"{base}{path}", False))
        for slug in WP_PLUGIN_PROBES:
            urls.append((f"{base}/wp-content/plugins/{slug}/", False))
        for slug in WP_THEME_PROBES:
            urls.append((f"{base}/wp-content/themes/{slug}/", False))

        return {"urls": urls}


def register(registry: PluginRegistry) -> None:
    registry.register_strategy(WordPressStrategy())
