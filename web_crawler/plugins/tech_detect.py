"""
Technology detection engine.

Analyses HTTP headers, HTML content, scripts, meta tags, cookies and
URL patterns to identify the technology stack of a web page — similar
in philosophy to Wappalyzer.

Detection results feed into the pipeline's automatic strategy
selection.
"""

from __future__ import annotations

import re
from typing import Any

from web_crawler.plugins.base import BasePlugin


# ── Signature database ─────────────────────────────────────────────

_TECH_SIGNATURES: dict[str, dict[str, Any]] = {
    # -- Frontend frameworks --
    "React": {
        "scripts": [r"react(?:\.production|\.development)?\.min\.js", r"react-dom"],
        "meta": [],
        "headers": [],
        "dom": [r'data-reactroot', r'data-reactid'],
    },
    "Vue.js": {
        "scripts": [r"vue(?:\.min)?\.js", r"vue\.runtime"],
        "meta": [],
        "headers": [],
        "dom": [r'data-v-[a-f0-9]', r'id="app".*?v-'],
    },
    "Angular": {
        "scripts": [r"angular(?:\.min)?\.js", r"zone\.js", r"@angular/core"],
        "meta": [],
        "headers": [],
        "dom": [r'ng-version=', r'ng-app=', r'_ngcontent-'],
    },
    "jQuery": {
        "scripts": [r"jquery(?:\.min)?\.js", r"jquery[-.][\d.]+"],
        "meta": [],
        "headers": [],
        "dom": [],
    },
    "Bootstrap": {
        "scripts": [r"bootstrap(?:\.min)?\.js"],
        "meta": [],
        "headers": [],
        "dom": [r'class="[^"]*\bcontainer\b', r'class="[^"]*\bcol-(?:xs|sm|md|lg)-'],
    },
    "Tailwind CSS": {
        "scripts": [],
        "meta": [],
        "headers": [],
        "dom": [r'class="[^"]*\b(?:flex|grid|text-|bg-|p-|m-)\b'],
    },
    # -- Backend / CMS --
    "WordPress": {
        "scripts": [r"wp-content/", r"wp-includes/", r"wp-emoji-release"],
        "meta": [r'name="generator"\s+content="WordPress'],
        "headers": [r"x-powered-by:\s*wp", r"link:.*wp-json"],
        "dom": [r"wp-content/", r"wp-includes/"],
    },
    "Drupal": {
        "scripts": [r"drupal\.js", r"drupal\.min\.js"],
        "meta": [r'name="generator"\s+content="Drupal'],
        "headers": [r"x-drupal-cache", r"x-generator:\s*drupal"],
        "dom": [r'class="[^"]*\bdrupal\b'],
    },
    "Joomla": {
        "scripts": [],
        "meta": [r'name="generator"\s+content="Joomla'],
        "headers": [],
        "dom": [r"/media/jui/", r"/media/system/"],
    },
    "Django": {
        "scripts": [],
        "meta": [],
        "headers": [r"x-frame-options:\s*sameorigin"],
        "dom": [r'csrfmiddlewaretoken', r'name="csrfmiddlewaretoken"'],
        "cookies": [r"csrftoken", r"django_language"],
    },
    "Laravel": {
        "scripts": [],
        "meta": [],
        "headers": [],
        "dom": [r'name="csrf-token"', r'name="_token"'],
        "cookies": [r"laravel_session", r"XSRF-TOKEN"],
    },
    "Express.js": {
        "scripts": [],
        "meta": [],
        "headers": [r"x-powered-by:\s*express"],
        "dom": [],
    },
    "ASP.NET": {
        "scripts": [],
        "meta": [],
        "headers": [r"x-powered-by:\s*asp\.net", r"x-aspnet-version"],
        "dom": [r'__VIEWSTATE', r'__EVENTVALIDATION'],
    },
    "Next.js": {
        "scripts": [r"_next/static", r"__NEXT_DATA__"],
        "meta": [],
        "headers": [r"x-powered-by:\s*next\.js"],
        "dom": [r'id="__next"'],
    },
    "Nuxt.js": {
        "scripts": [r"_nuxt/"],
        "meta": [],
        "headers": [],
        "dom": [r'id="__nuxt"', r'id="__layout"'],
    },
    # -- CDN / Infrastructure --
    "Cloudflare CDN": {
        "scripts": [],
        "meta": [],
        "headers": [r"cf-ray:", r"server:\s*cloudflare"],
        "dom": [],
    },
    "Amazon CloudFront": {
        "scripts": [],
        "meta": [],
        "headers": [r"x-amz-cf-id:", r"x-amz-cf-pop:"],
        "dom": [],
    },
    "Fastly": {
        "scripts": [],
        "meta": [],
        "headers": [r"x-served-by:.*cache-", r"x-fastly-request-id"],
        "dom": [],
    },
    "Nginx": {
        "scripts": [],
        "meta": [],
        "headers": [r"server:\s*nginx"],
        "dom": [],
    },
    "Apache": {
        "scripts": [],
        "meta": [],
        "headers": [r"server:\s*apache"],
        "dom": [],
    },
    # -- JS libraries --
    "Lodash": {
        "scripts": [r"lodash(?:\.min)?\.js"],
        "meta": [],
        "headers": [],
        "dom": [],
    },
    "Moment.js": {
        "scripts": [r"moment(?:\.min)?\.js"],
        "meta": [],
        "headers": [],
        "dom": [],
    },
    "Axios": {
        "scripts": [r"axios(?:\.min)?\.js"],
        "meta": [],
        "headers": [],
        "dom": [],
    },
    # -- Analytics --
    "Google Analytics": {
        "scripts": [r"google-analytics\.com/analytics\.js",
                     r"googletagmanager\.com/gtag/js",
                     r"google-analytics\.com/ga\.js"],
        "meta": [],
        "headers": [],
        "dom": [],
    },
    "Google Tag Manager": {
        "scripts": [r"googletagmanager\.com/gtm\.js"],
        "meta": [],
        "headers": [],
        "dom": [r'id="GTM-'],
    },
    # -- Anti-bot / CAPTCHA --
    "reCAPTCHA": {
        "scripts": [r"google\.com/recaptcha", r"gstatic\.com/recaptcha"],
        "meta": [],
        "headers": [],
        "dom": [r'class="g-recaptcha"', r'data-sitekey='],
    },
    "hCaptcha": {
        "scripts": [r"hcaptcha\.com/1/api\.js"],
        "meta": [],
        "headers": [],
        "dom": [r'class="h-captcha"'],
    },
    "Cloudflare Turnstile": {
        "scripts": [r"challenges\.cloudflare\.com/turnstile"],
        "meta": [],
        "headers": [],
        "dom": [r'class="cf-turnstile"'],
    },
}


class TechDetectorPlugin(BasePlugin):
    """Wappalyzer-like technology detection plugin.

    Scans HTTP headers, ``<script>`` tags, ``<meta>`` tags, DOM
    patterns, and cookies to identify the technology stack.
    """

    name = "tech_detector"
    kind = "tech_detector"
    priority = 10

    def detect(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: str,
        cookies: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        detected: list[dict[str, str]] = []
        header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        body_lower = body[:65536].lower()  # inspect first 64 KB
        cookie_str = " ".join(
            f"{k}={v}" for k, v in (cookies or {}).items()
        ).lower()

        for tech_name, sigs in _TECH_SIGNATURES.items():
            match = False

            for pattern in sigs.get("headers", []):
                if re.search(pattern, header_str, re.I):
                    match = True
                    break

            if not match:
                for pattern in sigs.get("scripts", []):
                    if re.search(pattern, body_lower, re.I):
                        match = True
                        break

            if not match:
                for pattern in sigs.get("meta", []):
                    if re.search(pattern, body_lower, re.I):
                        match = True
                        break

            if not match:
                for pattern in sigs.get("dom", []):
                    if re.search(pattern, body_lower, re.I):
                        match = True
                        break

            if not match:
                for pattern in sigs.get("cookies", []):
                    if re.search(pattern, cookie_str, re.I):
                        match = True
                        break

            if match:
                category = _categorize(tech_name)
                detected.append({"name": tech_name, "category": category})

        return {"technologies": detected} if detected else {}


def _categorize(name: str) -> str:
    """Assign a high-level category to a detected technology."""
    _CATEGORIES: dict[str, str] = {
        "React": "frontend_framework",
        "Vue.js": "frontend_framework",
        "Angular": "frontend_framework",
        "jQuery": "js_library",
        "Bootstrap": "css_framework",
        "Tailwind CSS": "css_framework",
        "WordPress": "cms",
        "Drupal": "cms",
        "Joomla": "cms",
        "Django": "backend_framework",
        "Laravel": "backend_framework",
        "Express.js": "backend_framework",
        "ASP.NET": "backend_framework",
        "Next.js": "frontend_framework",
        "Nuxt.js": "frontend_framework",
        "Cloudflare CDN": "cdn",
        "Amazon CloudFront": "cdn",
        "Fastly": "cdn",
        "Nginx": "web_server",
        "Apache": "web_server",
        "Lodash": "js_library",
        "Moment.js": "js_library",
        "Axios": "js_library",
        "Google Analytics": "analytics",
        "Google Tag Manager": "analytics",
        "reCAPTCHA": "captcha",
        "hCaptcha": "captcha",
        "Cloudflare Turnstile": "captcha",
    }
    return _CATEGORIES.get(name, "other")
