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
        body = context.get("body", "")[:8192].lower()
        detected: list[str] = []

        for waf_name, sigs in WAF_SIGNATURES.items():
            header_sigs = sigs.get("headers", {})
            body_sigs = sigs.get("body", [])
            for hdr, pattern in header_sigs.items():
                val = headers.get(hdr, "")
                if val and pattern.lower() in val.lower():
                    detected.append(waf_name)
                    break
            else:
                if any(sig.lower() in body for sig in body_sigs):
                    detected.append(waf_name)

        return {"protections": detected}


def register(registry: PluginRegistry) -> None:
    registry.register_detector(WAFDetectorPlugin())
