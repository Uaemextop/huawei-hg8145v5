"""
WAF / protection detection plugin.

Detects Web Application Firewalls, CAPTCHA challenges, and anti-bot
protections by analysing HTTP response headers and body content.
"""

from __future__ import annotations

import re

from web_crawler.plugins.base import CrawlerPlugin

# WAF / protection signatures.
# Each key is the protection identifier; the value is a list of
# strings or compiled patterns searched in headers + body.
_WAF_HEADER_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": [
        "cf-ray",
        "cf-cache-status",
        "cf-mitigated",
        "server: cloudflare",
    ],
    "sucuri": [
        "x-sucuri-id",
        "sucuri",
        "sucuri-cloudproxy",
    ],
    "wordfence": [
        "x-wf-",
        "wordfence",
    ],
    "imperva": [
        "x-iinfo",
        "incapsula",
        "imperva",
        "visid_incap",
    ],
    "akamai": [
        "akamai",
        "akamaighost",
        "x-akamai-transformed",
        "ak_bmsc",
    ],
    "shield_security": [
        "icwp-wpsf",
    ],
    "siteground": [
        "sg-captcha",
        "sgcaptcha",
    ],
    "aws_waf": [
        "x-amzn-waf",
        "awswaf",
    ],
    "mod_security": [
        "mod_security",
        "modsecurity",
    ],
}

_WAF_BODY_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": [
        "cf-browser-verification",
        "cloudflare ray id",
        "cf_chl_opt",
        "perform a captcha check",
    ],
    "captcha": [
        "g-recaptcha",
        "h-captcha",
        "cf-turnstile",
        "captcha-container",
        "funcaptcha",
        "geetest",
        "please verify you are a human",
        "complete the security check",
    ],
    "siteground": [
        ".well-known/sgcaptcha",
        "sg-captcha",
    ],
    "bot_detection": [
        "are you a robot",
        "bot detection",
        "automated access",
        "unusual traffic",
        "access denied",
    ],
}


class WAFDetectorPlugin(CrawlerPlugin):
    """Detects WAFs, CAPTCHAs, and anti-bot protections."""

    name = "waf_detector"
    priority = 5

    def detect_protection(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> list[str]:
        detected: list[str] = []
        headers_str = " ".join(
            f"{k}: {v}" for k, v in headers.items()
        ).lower()
        body_lower = body[:50_000].lower()

        # Check header-based signatures
        for waf_name, patterns in _WAF_HEADER_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in headers_str:
                    detected.append(waf_name)
                    break

        # Check body-based signatures
        for waf_name, patterns in _WAF_BODY_SIGNATURES.items():
            if waf_name in detected:
                continue
            for pattern in patterns:
                if pattern.lower() in body_lower:
                    detected.append(waf_name)
                    break

        return detected
