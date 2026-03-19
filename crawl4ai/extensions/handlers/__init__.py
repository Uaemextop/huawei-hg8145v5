"""
crawl4ai.extensions.handlers – technology-specific crawling corrections.

Each handler responds to detections produced by
:mod:`crawl4ai.extensions.detection` and applies an appropriate crawling
strategy (extra URLs, headers, config changes, etc.).

Handler modules:

* :mod:`.spa_renderer`      – SPA framework rendering (React, Angular, Vue, …)
* :mod:`.cms_api`           – CMS REST-API discovery (WordPress, Drupal, …)
* :mod:`.server_optimizer`  – Web-server tuning (Nginx, Apache, IIS, Express)
* :mod:`.backend_framework` – Backend-framework probes (Django, Flask, Rails, …)
* :mod:`.static_site`       – Static-site-generator discovery (Hugo, Jekyll, Gatsby)
* :mod:`.css_framework`     – CSS / JS framework logging (Bootstrap, Tailwind, jQuery)
* :mod:`.protection_bypass` – WAF / protection bypass (Cloudflare, Akamai, …)
* :mod:`.file_finder`       – Downloadable-file link scanner
* :mod:`.sitemap_robots`    – Sitemap & robots.txt parser
* :mod:`.rate_limiter`      – Rate-limit header analyser
* :mod:`.cdn_optimizer`     – CDN detection & header optimisation
* :mod:`.analytics_stripper`– Analytics / tracking domain blocker
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import BaseHandler, HandlerResult
from .spa_renderer import SPARendererHandler
from .cms_api import CMSAPIHandler
from .server_optimizer import ServerOptimizerHandler
from .backend_framework import BackendFrameworkHandler
from .static_site import StaticSiteHandler
from .css_framework import CSSFrameworkHandler
from .protection_bypass import ProtectionBypassHandler
from .file_finder import FileFinderHandler
from .sitemap_robots import SitemapRobotsHandler
from .rate_limiter import RateLimiterHandler
from .cdn_optimizer import CDNOptimizerHandler
from .analytics_stripper import AnalyticsStripperHandler

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Handler instances
# ------------------------------------------------------------------

_ALL_HANDLERS: list[BaseHandler] = [
    SPARendererHandler(),
    CMSAPIHandler(),
    ServerOptimizerHandler(),
    BackendFrameworkHandler(),
    StaticSiteHandler(),
    CSSFrameworkHandler(),
    ProtectionBypassHandler(),
    FileFinderHandler(),
    SitemapRobotsHandler(),
    RateLimiterHandler(),
    CDNOptimizerHandler(),
    AnalyticsStripperHandler(),
]

# ------------------------------------------------------------------
# Registry – maps detection type names → handler instances
# ------------------------------------------------------------------

_HANDLER_REGISTRY: dict[str, BaseHandler] = {}

for _h in _ALL_HANDLERS:
    # Each handler may cover multiple detection types.  We register the
    # handler under its own ``name`` so callers can look it up directly,
    # and we also rely on ``can_handle()`` for dynamic dispatch.
    if _h.name:
        _HANDLER_REGISTRY[_h.name] = _h


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def get_handler(detection_type: str) -> BaseHandler | None:
    """Return the handler registered for *detection_type*, or ``None``."""
    # Fast path: exact match on handler name
    handler = _HANDLER_REGISTRY.get(detection_type)
    if handler is not None:
        return handler
    # Slow path: ask every handler whether it can handle this type
    dummy = {"type": detection_type}
    for h in _ALL_HANDLERS:
        if h.can_handle(dummy):
            return h
    return None


def dispatch(
    url: str,
    session: "requests.Session",
    response: "requests.Response | None",
    detections: list[dict],
) -> list[HandlerResult]:
    """Iterate *detections*, find matching handlers, and collect results.

    Parameters
    ----------
    url:
        The URL that was fetched.
    session:
        The ``requests.Session`` used for fetching.
    response:
        The HTTP response object (may be ``None``).
    detections:
        List of detection dicts (each must contain at least ``{"type": …}``).

    Returns
    -------
    list[HandlerResult]
        One :class:`HandlerResult` per matching handler invocation.
    """
    results: list[HandlerResult] = []
    for detection in detections:
        dtype = detection.get("type", "")
        if not dtype:
            continue
        for handler in _ALL_HANDLERS:
            try:
                if handler.can_handle(detection):
                    result = handler.apply(url, session, response, detection)
                    results.append(result)
            except Exception:
                log.debug(
                    "Handler %s failed for detection %s on %s",
                    handler.name,
                    dtype,
                    url,
                    exc_info=True,
                )
    return results


__all__ = [
    # Public API
    "dispatch",
    "get_handler",
    # Base
    "BaseHandler",
    "HandlerResult",
    # Handler classes
    "SPARendererHandler",
    "CMSAPIHandler",
    "ServerOptimizerHandler",
    "BackendFrameworkHandler",
    "StaticSiteHandler",
    "CSSFrameworkHandler",
    "ProtectionBypassHandler",
    "FileFinderHandler",
    "SitemapRobotsHandler",
    "RateLimiterHandler",
    "CDNOptimizerHandler",
    "AnalyticsStripperHandler",
    # Internal (useful for testing)
    "_HANDLER_REGISTRY",
    "_ALL_HANDLERS",
]
