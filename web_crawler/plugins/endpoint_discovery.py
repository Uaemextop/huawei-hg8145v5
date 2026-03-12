"""
Endpoint discovery plugin.

Scans page content (HTML and JavaScript) for hidden endpoints,
internal routes, API paths, iframes, redirections, and dynamically
constructed URLs.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from web_crawler.plugins.base import BasePlugin


# ── Patterns for hidden endpoints ──────────────────────────────────

_API_PATH_RE = re.compile(
    r"""(?:["'])(/(?:api|graphql|rest|v[0-9]+|_next/data|wp-json)"""
    r"""(?:/[a-zA-Z0-9_.~:@!$&'()*+,;=/-]*)?)(?:["'])""",
)

_FETCH_URL_RE = re.compile(
    r"""(?:fetch|axios\.\w+|\.ajax|\.get|\.post|XMLHttpRequest)\s*\(\s*"""
    r"""['"`]([^'"`\s]+)['"`]""",
    re.I,
)

_REDIRECT_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.replace|location\.assign)"""
    r"""\s*[=(]\s*['"`]([^'"`]+)['"`]""",
    re.I,
)

_IFRAME_RE = re.compile(
    r"""<iframe[^>]+src\s*=\s*["']([^"']+)["']""",
    re.I,
)

_DATA_URL_RE = re.compile(
    r"""(?:data-(?:url|href|src|endpoint|action))\s*=\s*["']([^"']+)["']""",
    re.I,
)


class EndpointDiscoveryPlugin(BasePlugin):
    """Discover hidden endpoints from page content and scripts."""

    name = "endpoint_discovery"
    kind = "endpoint_discovery"
    priority = 40

    def extract_links(
        self,
        *,
        url: str,
        body: str,
        base: str,
        **kwargs: Any,
    ) -> set[str]:
        found: set[str] = set()

        for pattern in (_API_PATH_RE, _FETCH_URL_RE, _REDIRECT_RE,
                        _IFRAME_RE, _DATA_URL_RE):
            for m in pattern.finditer(body):
                raw = m.group(1).strip()
                if not raw or raw.startswith(("data:", "javascript:", "#")):
                    continue
                absolute = urllib.parse.urljoin(url, raw)
                parsed = urllib.parse.urlparse(absolute)
                # Keep only HTTP(S) URLs
                if parsed.scheme in ("http", "https"):
                    found.add(absolute)

        return found
