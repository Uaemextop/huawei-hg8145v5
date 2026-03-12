"""
External link extraction and classification plugin.

Detects and classifies links to cloud storage services, download
platforms, and other external resources found in page content.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from web_crawler.config import CLOUD_STORAGE_HOSTS
from web_crawler.plugins.base import BasePlugin

# ── Classification rules ───────────────────────────────────────────

_SERVICE_PATTERNS: dict[str, list[str]] = {
    "google_drive": [
        r"drive\.google\.com",
        r"docs\.google\.com",
    ],
    "onedrive": [
        r"1drv\.ms",
        r"onedrive\.live\.com",
    ],
    "dropbox": [
        r"dropbox\.com",
        r"dl\.dropboxusercontent\.com",
    ],
    "mega": [
        r"mega\.nz",
        r"mega\.co\.nz",
    ],
    "github": [
        r"github\.com/.+/releases",
        r"raw\.githubusercontent\.com",
        r"github\.com/.+/archive",
    ],
    "mediafire": [
        r"mediafire\.com",
    ],
    "archive_org": [
        r"archive\.org/download",
    ],
    "s3_bucket": [
        r"\.s3\.amazonaws\.com",
        r"s3\..*\.amazonaws\.com",
    ],
    "azure_blob": [
        r"\.blob\.core\.windows\.net",
    ],
    "gcs_bucket": [
        r"storage\.googleapis\.com",
    ],
}

_EXTERNAL_URL_RE = re.compile(
    r"""https?://[^\s"'<>]+""", re.I,
)


class ExternalLinkPlugin(BasePlugin):
    """Detect and classify external download links and cloud storage
    references in page content."""

    name = "external_links"
    kind = "content_analyzer"
    priority = 50

    def analyze(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: str,
        base: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        base_host = urllib.parse.urlparse(base or url).netloc
        classified: list[dict[str, str]] = []

        for m in _EXTERNAL_URL_RE.finditer(body[:262144]):  # 256 KB
            link = m.group(0).rstrip(".,;:!?)]}>")
            parsed = urllib.parse.urlparse(link)
            if not parsed.netloc or parsed.netloc == base_host:
                continue

            service = _classify_service(link, parsed.netloc)
            if service:
                classified.append({
                    "url": link,
                    "service": service,
                    "host": parsed.netloc,
                })
            elif parsed.netloc in CLOUD_STORAGE_HOSTS:
                classified.append({
                    "url": link,
                    "service": "cloud_storage",
                    "host": parsed.netloc,
                })

        return {"external_links": classified} if classified else {}


def _classify_service(url: str, host: str) -> str:
    """Classify a URL into a known service category."""
    for service, patterns in _SERVICE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, url, re.I):
                return service
    return ""
