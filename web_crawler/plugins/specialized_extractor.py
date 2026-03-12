"""
Specialized link extraction plugin.

Discovers links that standard HTML parsing might miss:
Google Drive links, embedded iframes, redirections, links hidden
in JavaScript, and data URIs.
"""

from __future__ import annotations

import re
import urllib.parse

from web_crawler.plugins.base import CrawlerPlugin


# Google Drive patterns
_GDRIVE_PATTERNS = [
    re.compile(r'https?://drive\.google\.com/file/d/([a-zA-Z0-9_-]+)', re.I),
    re.compile(r'https?://drive\.google\.com/open\?id=([a-zA-Z0-9_-]+)', re.I),
    re.compile(r'https?://docs\.google\.com/(?:document|spreadsheets|presentation)/d/([a-zA-Z0-9_-]+)', re.I),
    re.compile(r'https?://drive\.google\.com/uc\?(?:export=download&)?id=([a-zA-Z0-9_-]+)', re.I),
]

# iframe src extraction
_IFRAME_RE = re.compile(
    r'<iframe[^>]+src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# meta refresh redirect
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)',
    re.IGNORECASE,
)

# JavaScript redirect patterns
_JS_REDIRECT_PATTERNS = [
    re.compile(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'location\.replace\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'location\.assign\s*\(\s*["\']([^"\']+)["\']', re.I),
]

# Hidden links in onclick/data attributes
_ONCLICK_URL_RE = re.compile(
    r'''(?:onclick|data-href|data-url|data-link|data-redirect)\s*=\s*["'](?:[^"']*(?:href|url|link|location)\s*[=:]\s*)?["']?([^"'\s>]+)''',
    re.IGNORECASE,
)

# data-src and similar lazy-load attributes
_DATA_SRC_RE = re.compile(
    r'''(?:data-src|data-lazy-src|data-original|data-srcset)\s*=\s*["']([^"']+)["']''',
    re.IGNORECASE,
)

# Base64 encoded URLs in scripts
_B64_URL_RE = re.compile(
    r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']',
)


def _resolve_url(base: str, href: str) -> str:
    """Resolve *href* against *base*, returning an absolute URL."""
    try:
        return urllib.parse.urljoin(base, href.strip())
    except Exception:
        return ""


class SpecializedExtractorPlugin(CrawlerPlugin):
    """Discovers links in iframes, redirects, Google Drive, hidden
    scripts, and lazy-load attributes."""

    name = "specialized_extractor"
    priority = 50

    def extract_links(
        self,
        url: str,
        body: str,
        content_type: str,
    ) -> set[str]:
        if "html" not in content_type and "javascript" not in content_type:
            return set()

        found: set[str] = set()

        # Google Drive links
        for pattern in _GDRIVE_PATTERNS:
            for match in pattern.finditer(body):
                found.add(match.group(0))

        # iframe src
        for match in _IFRAME_RE.finditer(body):
            resolved = _resolve_url(url, match.group(1))
            if resolved:
                found.add(resolved)

        # meta refresh redirect
        for match in _META_REFRESH_RE.finditer(body):
            resolved = _resolve_url(url, match.group(1))
            if resolved:
                found.add(resolved)

        # JS redirects
        for pattern in _JS_REDIRECT_PATTERNS:
            for match in pattern.finditer(body):
                resolved = _resolve_url(url, match.group(1))
                if resolved:
                    found.add(resolved)

        # data-src / lazy-load
        for match in _DATA_SRC_RE.finditer(body):
            resolved = _resolve_url(url, match.group(1))
            if resolved:
                found.add(resolved)

        # Base64-encoded URLs in scripts
        import base64
        for match in _B64_URL_RE.finditer(body):
            try:
                decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="ignore")
                if decoded.startswith(("http://", "https://", "/")):
                    resolved = _resolve_url(url, decoded)
                    if resolved:
                        found.add(resolved)
            except Exception:
                pass

        return found
