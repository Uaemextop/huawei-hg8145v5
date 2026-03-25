"""
Detection registry — runs all detectors against a page response.

Delegates to :mod:`crawl4ai.extensions.detection`, which provides 50+
technology detectors (frameworks, CDNs, WAFs, CMSs, etc.).  The
original five detectors are re-exported for backward compatibility.

Usage::

    from web_crawler.detection import detect_all

    detections = detect_all(url, status_code, headers_dict, body_text)
    for d in detections:
        print(d["type"])   # "cloudflare", "siteground", "waf", ...
"""

from crawl4ai.extensions.detection import (  # noqa: F401
    ALL_DETECTORS,
    BaseDetector,
    CloudflareDetector,
    SiteGroundDetector,
    WAFDetector,
    Soft404Detector,
    WordPressDetector,
    detect_all,
)

__all__ = [
    "detect_all",
    "BaseDetector",
    "CloudflareDetector",
    "SiteGroundDetector",
    "WAFDetector",
    "Soft404Detector",
    "WordPressDetector",
    "ALL_DETECTORS",
]
