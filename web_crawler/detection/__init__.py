"""
Detection registry — runs all detectors against a page response.

Usage::

    from web_crawler.detection import detect_all

    detections = detect_all(url, status_code, headers_dict, body_text)
    for d in detections:
        print(d["type"])   # "cloudflare", "siteground", "waf", ...
"""

from web_crawler.detection.base import BaseDetector
from web_crawler.detection.cloudflare import CloudflareDetector
from web_crawler.detection.siteground import SiteGroundDetector
from web_crawler.detection.waf import WAFDetector
from web_crawler.detection.soft404 import Soft404Detector
from web_crawler.detection.wordpress import WordPressDetector

ALL_DETECTORS: list[BaseDetector] = [
    CloudflareDetector(),
    SiteGroundDetector(),
    WAFDetector(),
    Soft404Detector(),
    WordPressDetector(),
]


def detect_all(
    url: str,
    status_code: int,
    headers: dict,
    body: str,
) -> list[dict]:
    """Run every registered detector and return a list of matches."""
    results: list[dict] = []
    for detector in ALL_DETECTORS:
        try:
            result = detector.detect(url, status_code, headers, body)
            if result is not None:
                results.append(result)
        except Exception:
            pass
    return results


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
