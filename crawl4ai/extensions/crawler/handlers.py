"""Handler dispatch for the BFS crawler.

Re-exports from :mod:`crawl4ai.extensions.handlers` which provides 16
technology-specific handlers (SPA rendering, CMS API discovery, WAF
bypass, CDN optimization, etc.).

The :func:`dispatch` function is the main entry point: given a list of
detections from :func:`crawl4ai.extensions.detection.detect_all`, it
finds matching handlers and returns structured results with extra URLs
to crawl, headers to inject, and configuration recommendations.
"""

from crawl4ai.extensions.handlers import (  # noqa: F401
    BaseHandler,
    HandlerResult,
    dispatch,
    get_handler,
)

__all__ = ["BaseHandler", "HandlerResult", "dispatch", "get_handler"]
