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
* :mod:`.drupal` – Drupal CMS detection
* :mod:`.joomla` – Joomla CMS detection
* :mod:`.shopify` – Shopify detection
* :mod:`.magento` – Magento / Adobe Commerce detection
* :mod:`.ghost` – Ghost CMS detection
* :mod:`.squarespace` – Squarespace detection
* :mod:`.wix` – Wix detection
* :mod:`.nginx` – Nginx server detection
* :mod:`.apache` – Apache HTTP Server detection
* :mod:`.iis` – Microsoft IIS detection
* :mod:`.django` – Django framework detection
* :mod:`.flask` – Flask / Werkzeug detection
* :mod:`.rails` – Ruby on Rails detection
* :mod:`.laravel` – Laravel PHP framework detection
* :mod:`.aspnet` – ASP.NET detection
* :mod:`.express` – Express.js (Node) detection
* :mod:`.hugo` – Hugo static site generator detection
* :mod:`.jekyll` – Jekyll static site generator detection
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
from .drupal import DrupalDetector
from .joomla import JoomlaDetector
from .shopify import ShopifyDetector
from .magento import MagentoDetector
from .ghost import GhostDetector
from .squarespace import SquarespaceDetector
from .wix import WixDetector
from .nginx import NginxDetector
from .apache import ApacheDetector
from .iis import IISDetector
from .django import DjangoDetector
from .flask import FlaskDetector
from .rails import RailsDetector
from .laravel import LaravelDetector
from .aspnet import AspNetDetector
from .express import ExpressDetector
from .hugo import HugoDetector
from .jekyll import JekyllDetector

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
    DrupalDetector(),
    JoomlaDetector(),
    ShopifyDetector(),
    MagentoDetector(),
    GhostDetector(),
    SquarespaceDetector(),
    WixDetector(),
    NginxDetector(),
    ApacheDetector(),
    IISDetector(),
    DjangoDetector(),
    FlaskDetector(),
    RailsDetector(),
    LaravelDetector(),
    AspNetDetector(),
    ExpressDetector(),
    HugoDetector(),
    JekyllDetector(),
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
    "DrupalDetector",
    "JoomlaDetector",
    "ShopifyDetector",
    "MagentoDetector",
    "GhostDetector",
    "SquarespaceDetector",
    "WixDetector",
    "NginxDetector",
    "ApacheDetector",
    "IISDetector",
    "DjangoDetector",
    "FlaskDetector",
    "RailsDetector",
    "LaravelDetector",
    "AspNetDetector",
    "ExpressDetector",
    "HugoDetector",
    "JekyllDetector",
    "ALL_DETECTORS",
    "WAF_SIGNATURES",
]
