"""Analytics stripper handler – blocks tracking domains to speed up crawling."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["AnalyticsStripperHandler"]

_ANALYTICS_TYPES = frozenset({
    "google_analytics", "facebook_pixel", "hotjar",
    "analytics", "tracking",
})

# Comprehensive list of tracking / analytics domains to block
_TRACKING_DOMAINS: dict[str, list[str]] = {
    "google_analytics": [
        "www.google-analytics.com",
        "ssl.google-analytics.com",
        "analytics.google.com",
        "www.googletagmanager.com",
        "tagmanager.google.com",
        "stats.g.doubleclick.net",
    ],
    "facebook_pixel": [
        "connect.facebook.net",
        "www.facebook.com",
        "pixel.facebook.com",
    ],
    "hotjar": [
        "static.hotjar.com",
        "script.hotjar.com",
        "vars.hotjar.com",
    ],
    "_common": [
        "bat.bing.com",
        "snap.licdn.com",
        "analytics.tiktok.com",
        "sc-static.net",
        "cdn.segment.com",
        "cdn.mxpnl.com",
        "cdn.heapanalytics.com",
        "js.intercomcdn.com",
        "widget.intercom.io",
        "rum-static.pingdom.net",
        "d2wy8f7a9ursnm.cloudfront.net",
        "js.hs-analytics.net",
        "track.hubspot.com",
    ],
}


class AnalyticsStripperHandler(BaseHandler):
    """Recommend blocking tracking/analytics domains during browser crawling.

    This saves bandwidth and speeds up headless-browser crawling by
    preventing analytics scripts from loading.
    """

    name = "analytics_stripper"

    def can_handle(self, detection: dict) -> bool:
        """Return True for analytics / tracking detections."""
        return detection.get("type", "") in _ANALYTICS_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Return a list of tracking domains to block."""
        atype = detection.get("type", "")
        actions: list[str] = []
        block_domains: list[str] = []

        try:
            # Always include common tracking domains
            block_domains.extend(_TRACKING_DOMAINS["_common"])

            # Add type-specific domains
            specific = _TRACKING_DOMAINS.get(atype, [])
            block_domains.extend(specific)

            # Deduplicate while preserving order
            block_domains = list(dict.fromkeys(block_domains))

            actions.append(
                f"Identified {len(block_domains)} tracking domain(s) to block "
                f"(type: {atype})"
            )
        except Exception:
            log.debug(
                "AnalyticsStripperHandler error for %s", url, exc_info=True
            )
            actions.append("Error identifying tracking domains")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=[],
            extra_headers={},
            recommended_config={"block_domains": block_domains},
        )
