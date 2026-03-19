"""Sitemap & robots.txt handler – extracts all URLs from sitemaps and robots rules."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["SitemapRobotsHandler"]

_SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)
_SITEMAP_INDEX_RE = re.compile(
    r"<sitemap>\s*<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL
)
_CRAWL_DELAY_RE = re.compile(r"Crawl-delay:\s*(\d+)", re.IGNORECASE)
_SITEMAP_DIRECTIVE_RE = re.compile(r"Sitemap:\s*(\S+)", re.IGNORECASE)

# Maximum child sitemaps to follow from a sitemap index
_MAX_CHILD_SITEMAPS = 50
# Maximum number of URLs to collect from all sitemaps combined
_MAX_SITEMAP_URLS = 5000


class SitemapRobotsHandler(BaseHandler):
    """Fetch and parse ``robots.txt`` and sitemaps to discover all site URLs.

    Trigger with detection type ``"sitemap_scan"``.
    """

    name = "sitemap_robots"

    def can_handle(self, detection: dict) -> bool:
        """Return True for sitemap-scan requests."""
        return detection.get("type", "") == "sitemap_scan"

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Fetch robots.txt and sitemaps, returning discovered URLs."""
        actions: list[str] = []
        extra_urls: list[str] = []
        config: dict = {}

        try:
            origin = _origin(url)

            # --- robots.txt --------------------------------------------------
            robots_url = urljoin(origin, "/robots.txt")
            robots_text = _fetch_text(session, robots_url)
            sitemap_urls_from_robots: list[str] = []

            if robots_text:
                actions.append("Fetched robots.txt")
                # Crawl-delay
                m = _CRAWL_DELAY_RE.search(robots_text)
                if m:
                    delay = int(m.group(1))
                    config["delay"] = delay
                    actions.append(
                        f"robots.txt Crawl-delay: {delay} s"
                    )
                # Sitemap directives
                for sm in _SITEMAP_DIRECTIVE_RE.finditer(robots_text):
                    sitemap_urls_from_robots.append(sm.group(1))

            # --- Sitemaps -----------------------------------------------------
            sitemap_candidates = list(dict.fromkeys(
                sitemap_urls_from_robots
                + [
                    urljoin(origin, "/sitemap.xml"),
                    urljoin(origin, "/sitemap_index.xml"),
                ]
            ))

            collected: list[str] = []
            visited_sitemaps: set[str] = set()

            for sm_url in sitemap_candidates:
                if len(collected) >= _MAX_SITEMAP_URLS:
                    break
                _parse_sitemap(
                    session, sm_url, collected, visited_sitemaps
                )

            if collected:
                extra_urls.extend(collected)
                actions.append(
                    f"Extracted {len(collected)} URL(s) from "
                    f"{len(visited_sitemaps)} sitemap(s)"
                )

        except Exception:
            log.debug(
                "SitemapRobotsHandler error for %s", url, exc_info=True
            )
            actions.append("Error processing sitemaps/robots.txt")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={},
            recommended_config=config,
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _origin(url: str) -> str:
    """Return scheme + netloc (e.g. https://example.com)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _fetch_text(session: "requests.Session", url: str) -> str:
    """GET a URL and return its body text, or empty string on failure."""
    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        if resp.status_code == 200:
            return resp.text or ""
    except Exception:
        log.debug("Failed to fetch %s", url, exc_info=True)
    return ""


def _parse_sitemap(
    session: "requests.Session",
    sitemap_url: str,
    collected: list[str],
    visited: set[str],
) -> None:
    """Recursively parse sitemaps and sitemap indices."""
    if sitemap_url in visited:
        return
    if len(visited) >= _MAX_CHILD_SITEMAPS:
        return
    visited.add(sitemap_url)

    text = _fetch_text(session, sitemap_url)
    if not text:
        return

    # Check if this is a sitemap index
    children = _SITEMAP_INDEX_RE.findall(text)
    if children:
        for child_url in children:
            if len(collected) >= _MAX_SITEMAP_URLS:
                return
            _parse_sitemap(session, child_url.strip(), collected, visited)
        return

    # Regular sitemap – extract <loc> entries
    for loc in _SITEMAP_LOC_RE.findall(text):
        loc = loc.strip()
        if loc and len(collected) < _MAX_SITEMAP_URLS:
            collected.append(loc)
