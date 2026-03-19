"""
crawl4ai.extensions.detection – technology / framework detection.

Individual detector modules:

* :mod:`.cloudflare` – Cloudflare Managed Challenge / Turnstile
* :mod:`.siteground` – SiteGround Security CAPTCHA (PoW)
* :mod:`.waf` – Generic WAF signature scanner (Wordfence, Sucuri, Imperva, …)
* :mod:`.soft404` – Soft-404 page detection
* :mod:`.wordpress` – WordPress fingerprinting
* :mod:`.captcha` – CAPTCHA embed detection (reCAPTCHA, hCAPTCHA, Turnstile, …)
* :mod:`.react` – React.js detection
* :mod:`.angular` – Angular detection
* :mod:`.vue` – Vue.js detection
* :mod:`.nextjs` – Next.js detection
* :mod:`.nuxt` – Nuxt.js detection
* :mod:`.svelte` – Svelte / SvelteKit detection
* :mod:`.ember` – Ember.js detection
* :mod:`.jquery` – jQuery detection
* :mod:`.bootstrap` – Bootstrap detection
* :mod:`.tailwind` – Tailwind CSS detection
* :mod:`.gatsby` – Gatsby detection
* :mod:`.backbone` – Backbone.js detection
* :mod:`.typescript` – TypeScript build-artifact detection
"""

from __future__ import annotations

from .base import BaseDetector
from .cloudflare import CloudflareDetector
from .siteground import SiteGroundDetector
from .waf import WAFDetector, WAF_SIGNATURES
from .soft404 import Soft404Detector
from .wordpress import WordPressDetector
from .captcha import CaptchaDetector
from .react import ReactDetector
from .angular import AngularDetector
from .vue import VueDetector
from .nextjs import NextjsDetector
from .nuxt import NuxtDetector
from .svelte import SvelteDetector
from .ember import EmberDetector
from .jquery import JQueryDetector
from .bootstrap import BootstrapDetector
from .tailwind import TailwindDetector
from .gatsby import GatsbyDetector
from .backbone import BackboneDetector
from .typescript import TypeScriptDetector

ALL_DETECTORS: list[BaseDetector] = [
    CloudflareDetector(),
    SiteGroundDetector(),
    WAFDetector(),
    Soft404Detector(),
    WordPressDetector(),
    CaptchaDetector(),
    ReactDetector(),
    AngularDetector(),
    VueDetector(),
    NextjsDetector(),
    NuxtDetector(),
    SvelteDetector(),
    EmberDetector(),
    JQueryDetector(),
    BootstrapDetector(),
    TailwindDetector(),
    GatsbyDetector(),
    BackboneDetector(),
    TypeScriptDetector(),
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
    "ReactDetector",
    "AngularDetector",
    "VueDetector",
    "NextjsDetector",
    "NuxtDetector",
    "SvelteDetector",
    "EmberDetector",
    "JQueryDetector",
    "BootstrapDetector",
    "TailwindDetector",
    "GatsbyDetector",
    "BackboneDetector",
    "TypeScriptDetector",
    "ALL_DETECTORS",
    "WAF_SIGNATURES",
]
