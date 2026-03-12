"""
WAF / protection detection plugin.

Consolidates WAF signature detection from config.WAF_SIGNATURES into
the plugin system, extending it with header and cookie analysis.
"""

from __future__ import annotations

from typing import Any

from web_crawler.config import WAF_SIGNATURES
from web_crawler.plugins.base import BasePlugin


class WAFDetectorPlugin(BasePlugin):
    """Detect WAFs, firewalls, and anti-bot protections from HTTP
    response headers and body content."""

    name = "waf_detector"
    kind = "waf_detector"
    priority = 20

    def detect(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        # Exclude Permissions-Policy (declares allowed origins, not WAF)
        filtered = {
            k: v for k, v in headers.items()
            if k.lower() != "permissions-policy"
        }
        combined = " ".join(f"{k}: {v}" for k, v in filtered.items()).lower()
        combined += " " + body[:8192].lower()

        detected: list[str] = []
        for name, sigs in WAF_SIGNATURES.items():
            if any(s in combined for s in sigs):
                detected.append(name)

        return {"protections": detected} if detected else {}
