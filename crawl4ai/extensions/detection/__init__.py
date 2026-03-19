"""
crawl4ai.extensions.detection – WAF / CAPTCHA / soft-404 / WordPress detection.

Individual detector modules:

* :mod:`.cloudflare` – Cloudflare Managed Challenge / Turnstile
* :mod:`.siteground` – SiteGround Security CAPTCHA (PoW)
* :mod:`.waf` – Generic WAF signature scanner (Wordfence, Sucuri, Imperva, …)
* :mod:`.soft404` – Soft-404 page detection
* :mod:`.wordpress` – WordPress fingerprinting
* :mod:`.captcha` – CAPTCHA embed detection (reCAPTCHA, hCAPTCHA, Turnstile, …)
"""

from __future__ import annotations

from .base import BaseDetector
from .cloudflare import CloudflareDetector
from .siteground import SiteGroundDetector
from .waf import WAFDetector, WAF_SIGNATURES
from .soft404 import Soft404Detector
from .wordpress import WordPressDetector
from .captcha import CaptchaDetector

ALL_DETECTORS: list[BaseDetector] = [
    CloudflareDetector(),
    SiteGroundDetector(),
    WAFDetector(),
    Soft404Detector(),
    WordPressDetector(),
    CaptchaDetector(),
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
    "CaptchaDetector",
    "ALL_DETECTORS",
    "WAF_SIGNATURES",
]
