"""Technology detection plugin (Wappalyzer-like)."""

from __future__ import annotations

import re
from typing import Any

from web_crawler.plugins.registry import BasePlugin, PluginRegistry

# ── Technology signatures ────────────────────────────────────────
# Each entry: {name, category, indicators}
# indicators can check: headers, meta_tags, scripts, cookies, html_patterns

_TECH_DB: list[dict[str, Any]] = [
    # ── CMS ──────────────────────────────────────────────────────
    {
        "name": "WordPress",
        "category": "cms",
        "indicators": {
            "html_patterns": [
                r"/wp-content/", r"/wp-includes/", r"wp-json",
                r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress',
            ],
            "headers": {"x-powered-by": "WordPress", "link": "wp-json"},
        },
    },
    {
        "name": "Joomla",
        "category": "cms",
        "indicators": {
            "html_patterns": [
                r"/media/jui/", r"/components/com_",
                r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla',
            ],
        },
    },
    {
        "name": "Drupal",
        "category": "cms",
        "indicators": {
            "html_patterns": [r"/sites/default/files/", r"Drupal\.settings"],
            "headers": {"x-generator": "Drupal", "x-drupal-cache": ""},
        },
    },
    # ── Frontend frameworks ──────────────────────────────────────
    {
        "name": "React",
        "category": "frontend_framework",
        "indicators": {
            "html_patterns": [r"data-reactroot", r"_reactRootContainer", r"__NEXT_DATA__"],
            "scripts": ["react.production.min.js", "react-dom"],
        },
    },
    {
        "name": "Vue.js",
        "category": "frontend_framework",
        "indicators": {
            "html_patterns": [r"data-v-[a-f0-9]", r"__vue__"],
            "scripts": ["vue.min.js", "vue.global"],
        },
    },
    {
        "name": "Angular",
        "category": "frontend_framework",
        "indicators": {
            "html_patterns": [r"ng-version=", r"ng-app=", r"\bng-\w+="],
            "scripts": ["angular.min.js", "zone.js", "polyfills"],
        },
    },
    {
        "name": "jQuery",
        "category": "js_library",
        "indicators": {
            "scripts": ["jquery.min.js", "jquery-migrate"],
        },
    },
    # ── Backend ──────────────────────────────────────────────────
    {
        "name": "Nginx",
        "category": "web_server",
        "indicators": {"headers": {"server": "nginx"}},
    },
    {
        "name": "Apache",
        "category": "web_server",
        "indicators": {"headers": {"server": "Apache"}},
    },
    {
        "name": "PHP",
        "category": "language",
        "indicators": {
            "headers": {"x-powered-by": "PHP"},
            "cookies": ["PHPSESSID"],
        },
    },
    {
        "name": "ASP.NET",
        "category": "language",
        "indicators": {
            "headers": {"x-powered-by": "ASP.NET", "x-aspnet-version": ""},
            "cookies": ["ASP.NET_SessionId"],
        },
    },
    # ── CDN / Hosting ────────────────────────────────────────────
    {
        "name": "Cloudflare",
        "category": "cdn",
        "indicators": {
            "headers": {"server": "cloudflare", "cf-ray": ""},
            "cookies": ["__cflb", "__cfuid"],
        },
    },
    {
        "name": "AWS CloudFront",
        "category": "cdn",
        "indicators": {"headers": {"x-amz-cf-id": "", "via": "CloudFront"}},
    },
    {
        "name": "Vercel",
        "category": "hosting",
        "indicators": {"headers": {"x-vercel-id": "", "server": "Vercel"}},
    },
    # ── Security ─────────────────────────────────────────────────
    {
        "name": "reCAPTCHA",
        "category": "captcha",
        "indicators": {
            "scripts": ["google.com/recaptcha", "gstatic.com/recaptcha"],
            "html_patterns": [r"g-recaptcha", r"grecaptcha"],
        },
    },
    {
        "name": "hCaptcha",
        "category": "captcha",
        "indicators": {
            "scripts": ["hcaptcha.com/1/api.js"],
            "html_patterns": [r"h-captcha"],
        },
    },
    {
        "name": "Cloudflare Turnstile",
        "category": "captcha",
        "indicators": {
            "scripts": ["challenges.cloudflare.com/turnstile"],
            "html_patterns": [r"cf-turnstile"],
        },
    },
]


class TechDetectorPlugin(BasePlugin):
    """Detect technologies used by a web page."""

    @property
    def name(self) -> str:
        return "tech_detector"

    def run(self, context: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
        """Analyse page for technology fingerprints.

        *context* keys:
            ``headers``  – dict of HTTP response headers
            ``body``     – page HTML (str)
            ``cookies``  – list of cookie names (list[str])
            ``scripts``  – list of script src URLs (list[str])

        Returns dict with ``technologies`` list, each entry having
        ``name`` and ``category``.
        """
        headers = {k.lower(): v for k, v in context.get("headers", {}).items()}
        body = context.get("body", "")
        cookies = [c.lower() for c in context.get("cookies", [])]
        scripts = [s.lower() for s in context.get("scripts", [])]

        detected: list[dict[str, str]] = []

        for tech in _TECH_DB:
            if self._match(tech["indicators"], headers, body, cookies, scripts):
                detected.append({"name": tech["name"], "category": tech["category"]})

        return {"technologies": detected}

    @staticmethod
    def _match(
        indicators: dict[str, Any],
        headers: dict[str, str],
        body: str,
        cookies: list[str],
        scripts: list[str],
    ) -> bool:
        # Check headers
        for hdr, pattern in indicators.get("headers", {}).items():
            val = headers.get(hdr.lower(), "")
            if val and (not pattern or pattern.lower() in val.lower()):
                return True

        # Check HTML patterns
        for pat in indicators.get("html_patterns", []):
            if re.search(pat, body, re.I):
                return True

        # Check scripts
        for sig in indicators.get("scripts", []):
            if any(sig.lower() in s for s in scripts):
                return True

        # Check cookies
        for sig in indicators.get("cookies", []):
            if sig.lower() in cookies:
                return True

        return False


def register(registry: PluginRegistry) -> None:
    registry.register_detector(TechDetectorPlugin())
