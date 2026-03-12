"""WAF / anti-bot protection detection plugin."""

from __future__ import annotations

from typing import Any

from web_crawler.config import WAF_SIGNATURES
from web_crawler.plugins.registry import BasePlugin, PluginRegistry


class WAFDetectorPlugin(BasePlugin):
    """Detect WAF and anti-bot protections from HTTP headers and body."""

    @property
    def name(self) -> str:
        return "waf_detector"

    def run(self, context: dict[str, Any]) -> dict[str, list[str]]:
        """Analyse response headers and body for WAF signatures.

        *context* keys:
            ``headers`` – dict of HTTP response headers
            ``body``    – first 8 KiB of response body (str)

        Returns dict with ``protections`` key listing detected names.
        """
        headers = context.get("headers", {})
        body = context.get("body", "")[:8192]

        # Build a single searchable string from headers + body, matching
        # the approach used by the existing Crawler.detect_protection().
        filtered = {k: v for k, v in headers.items()
                    if k.lower() != "permissions-policy"}
        combined = " ".join(f"{k}: {v}" for k, v in filtered.items()).lower()
        combined += " " + body.lower()

        detected: list[str] = []
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(s in combined for s in sigs):
                detected.append(waf_name)

        return {"protections": detected}


def register(registry: PluginRegistry) -> None:
    registry.register_detector(WAFDetectorPlugin())
