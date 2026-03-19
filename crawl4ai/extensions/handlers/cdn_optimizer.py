"""CDN optimizer handler – adjusts headers and caching for CDN-served responses."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["CDNOptimizerHandler"]

# Detection types that indicate a CDN is in front of the origin
_CDN_TYPES = frozenset({
    "cloudfront", "fastly", "akamai_cdn", "cloudflare_cdn",
    "keycdn", "stackpath", "cdn",
})

# CDN-specific Via / X-Cache header patterns → friendly name
_CDN_SIGNATURES: dict[str, str] = {
    "cloudfront": "Amazon CloudFront",
    "fastly": "Fastly",
    "akamai": "Akamai CDN",
    "cloudflare": "Cloudflare CDN",
    "keycdn": "KeyCDN",
    "stackpath": "StackPath",
    "varnish": "Varnish",
}


class CDNOptimizerHandler(BaseHandler):
    """Optimise requests for CDN-fronted origins.

    Identifies the CDN provider, adjusts caching / encoding headers,
    and attempts to discover the origin server.
    """

    name = "cdn_optimizer"

    def can_handle(self, detection: dict) -> bool:
        """Return True for CDN-related detections."""
        return detection.get("type", "") in _CDN_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Return CDN-aware headers and origin discovery hints."""
        actions: list[str] = []
        extra_headers: dict = {}
        config: dict = {}

        try:
            headers = _resp_headers(response)
            cdn_name = _identify_cdn(headers)
            if cdn_name:
                actions.append(f"Identified CDN: {cdn_name}")

            # Add encoding headers
            extra_headers["Accept-Encoding"] = "gzip, deflate, br"
            actions.append("Set Accept-Encoding for CDN compression")

            # Bypass CDN cache when needed
            extra_headers["Cache-Control"] = "no-cache"
            extra_headers["Pragma"] = "no-cache"
            actions.append("Set Cache-Control: no-cache to bypass CDN cache")

            # Try to discover origin from response headers
            origin = _discover_origin(headers)
            if origin:
                config["origin_server"] = origin
                actions.append(f"Possible origin server: {origin}")

        except Exception:
            log.debug("CDNOptimizerHandler error for %s", url, exc_info=True)
            actions.append("Error processing CDN detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=[],
            extra_headers=extra_headers,
            recommended_config=config,
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _resp_headers(response: "requests.Response | None") -> dict:
    if response is None:
        return {}
    try:
        return {k.lower(): v for k, v in response.headers.items()}
    except Exception:
        return {}


def _identify_cdn(headers: dict) -> str | None:
    """Identify the CDN from response headers."""
    via = headers.get("via", "").lower()
    x_cache = headers.get("x-cache", "").lower()
    server = headers.get("server", "").lower()
    combined = f"{via} {x_cache} {server}"

    for sig, name in _CDN_SIGNATURES.items():
        if sig in combined:
            return name
    return None


def _discover_origin(headers: dict) -> str | None:
    """Attempt to find the origin server from CDN headers."""
    # X-Origin-Server, X-Backend-Server, X-Served-By sometimes leak origin
    for key in ("x-origin-server", "x-backend-server", "x-served-by",
                "x-amz-cf-id"):
        value = headers.get(key)
        if value:
            return value
    return None
