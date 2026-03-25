"""Cloudflare managed challenge detection.

Delegates to :mod:`crawl4ai.extensions.detection.cloudflare`.
"""

from crawl4ai.extensions.detection.cloudflare import CloudflareDetector  # noqa: F401

__all__ = ["CloudflareDetector"]
