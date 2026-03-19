"""CMS API handler – discovers REST API and sitemap endpoints for CMS platforms."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["CMSAPIHandler"]

_CMS_TYPES = frozenset({
    "wordpress", "drupal", "joomla", "ghost",
    "shopify", "magento", "wix", "squarespace",
})

# CMS → list of path suffixes to probe
_CMS_PATHS: dict[str, list[str]] = {
    "wordpress": [
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/categories",
        "/sitemap.xml",
        "/wp-sitemap.xml",
    ],
    "drupal": [
        "/jsonapi/node/article",
        "/jsonapi/node/page",
        "/sitemap.xml",
    ],
    "joomla": [
        "/administrator/",
        "/index.php?option=com_content&view=article",
        "/component/content/",
    ],
    "ghost": [
        "/ghost/api/v3/content/posts/",
        "/ghost/api/v3/content/pages/",
        "/sitemap.xml",
    ],
    "shopify": [
        "/products.json",
        "/collections.json",
        "/sitemap.xml",
        "/pages.json",
    ],
    "magento": [
        "/rest/V1/products",
        "/sitemap.xml",
        "/catalogsearch/",
    ],
    "wix": [
        "/_api/",
    ],
    "squarespace": [
        "/api/",
    ],
}


class CMSAPIHandler(BaseHandler):
    """Discover CMS-specific REST API and sitemap endpoints.

    Supports WordPress, Drupal, Joomla, Ghost, Shopify, Magento,
    Wix, and Squarespace.
    """

    name = "cms_api"

    def can_handle(self, detection: dict) -> bool:
        """Return True for any known CMS detection."""
        return detection.get("type", "") in _CMS_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Generate CMS-specific API and sitemap URLs."""
        cms = detection.get("type", "")
        actions: list[str] = []
        extra_urls: list[str] = []

        try:
            paths = _CMS_PATHS.get(cms, [])
            for path in paths:
                extra_urls.append(urljoin(url, path))

            actions.append(
                f"Queued {len(extra_urls)} {cms.title()} endpoint(s): "
                + ", ".join(paths)
            )
        except Exception:
            log.debug("CMSAPIHandler error for %s", url, exc_info=True)
            actions.append(f"Error generating {cms} API URLs")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={},
            recommended_config={},
        )
