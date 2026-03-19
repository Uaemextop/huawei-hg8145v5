"""File finder handler – discovers downloadable file links on any page."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["FileFinderHandler"]

# Extensions to look for (case-insensitive)
_FILE_EXTENSIONS = (
    ".zip", ".exe", ".bin", ".iso", ".dmg", ".msi", ".deb", ".rpm",
    ".tar", ".gz", ".7z", ".rar", ".pdf", ".doc", ".docx", ".xls",
    ".xlsx", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".cab",
    ".apk", ".jar", ".img",
)

# Regex matching href/src attributes pointing to downloadable files
_EXT_PATTERN = "|".join(
    re.escape(ext) for ext in sorted(_FILE_EXTENSIONS, key=len, reverse=True)
)
_FILE_LINK_RE = re.compile(
    rf'(?:href|src)\s*=\s*["\']([^"\']*?(?:{_EXT_PATTERN})(?:\?[^"\']*)?)["\']',
    re.IGNORECASE,
)

# Direct download / CDN URL pattern in text content
_DIRECT_URL_RE = re.compile(
    rf'(https?://[^\s"\'<>]+?(?:{_EXT_PATTERN})(?:\?[^\s"\'<>]*)?)',
    re.IGNORECASE,
)

# Common download page path patterns
_DOWNLOAD_PATH_PATTERNS = (
    "/download/", "/downloads/", "/releases/",
    "/files/", "/dist/",
)


class FileFinderHandler(BaseHandler):
    """Scan pages for downloadable file links.

    This handler does not map to a specific technology detection but can
    be invoked with detection type ``"file_scan"`` or called explicitly.
    It discovers links to ZIP, EXE, ISO, PDF, and many other file types.
    """

    name = "file_finder"

    def can_handle(self, detection: dict) -> bool:
        """Return True when called for a file scan."""
        return detection.get("type", "") == "file_scan"

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Scan the response body for downloadable file links."""
        actions: list[str] = []
        extra_urls: list[str] = []
        seen: set[str] = set()

        try:
            body = _body(response)

            # 1. Scan href/src attributes
            for match in _FILE_LINK_RE.finditer(body):
                resolved = urljoin(url, match.group(1))
                if resolved not in seen:
                    seen.add(resolved)
                    extra_urls.append(resolved)

            # 2. Scan for direct download URLs in text
            for match in _DIRECT_URL_RE.finditer(body):
                resolved = match.group(1)
                if resolved not in seen:
                    seen.add(resolved)
                    extra_urls.append(resolved)

            if extra_urls:
                actions.append(
                    f"Discovered {len(extra_urls)} downloadable file link(s)"
                )

            # 3. Probe common download directories
            probe_urls: list[str] = []
            for path in _DOWNLOAD_PATH_PATTERNS:
                probe = urljoin(url, path)
                if probe not in seen:
                    seen.add(probe)
                    probe_urls.append(probe)
            if probe_urls:
                extra_urls.extend(probe_urls)
                actions.append(
                    f"Probing {len(probe_urls)} common download path(s)"
                )

        except Exception:
            log.debug("FileFinderHandler error for %s", url, exc_info=True)
            actions.append("Error scanning for downloadable files")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={},
            recommended_config={},
        )


def _body(response: "requests.Response | None") -> str:
    if response is None:
        return ""
    try:
        return response.text or ""
    except Exception:
        return ""
