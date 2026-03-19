"""Static site generator handler – discovers feeds, sitemaps, and asset paths."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["StaticSiteHandler"]

_SSG_TYPES = frozenset({"hugo", "jekyll", "gatsby"})

_SSG_PATHS: dict[str, list[str]] = {
    "hugo": [
        "/index.xml",
        "/sitemap.xml",
        "/categories/",
        "/tags/",
    ],
    "jekyll": [
        "/feed.xml",
        "/sitemap.xml",
        "/assets/",
    ],
    "gatsby": [
        "/page-data/index/page-data.json",
        "/static/",
        "/sitemap.xml",
    ],
}


class StaticSiteHandler(BaseHandler):
    """Discover feeds, sitemaps, and asset directories for static site generators.

    Supports Hugo, Jekyll, and Gatsby.
    """

    name = "static_site"

    def can_handle(self, detection: dict) -> bool:
        """Return True for any known static-site-generator detection."""
        return detection.get("type", "") in _SSG_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Return extra URLs for RSS feeds, sitemaps, and asset paths."""
        ssg = detection.get("type", "")
        actions: list[str] = []
        extra_urls: list[str] = []

        try:
            paths = _SSG_PATHS.get(ssg, [])
            for p in paths:
                extra_urls.append(urljoin(url, p))
            actions.append(
                f"Queued {len(extra_urls)} {ssg.title()} endpoint(s): "
                + ", ".join(paths)
            )
        except Exception:
            log.debug("StaticSiteHandler error for %s", url, exc_info=True)
            actions.append(f"Error processing {ssg} detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={},
            recommended_config={},
        )
