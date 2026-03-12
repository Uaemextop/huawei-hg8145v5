"""
Technology detection plugin.

Analyses HTTP response headers and body content to identify web
technologies, frameworks, and backend systems.
"""

from __future__ import annotations

import re

from web_crawler.plugins.base import CrawlerPlugin


# Patterns for technology detection from headers and body content.
_TECH_SIGNATURES: dict[str, list[dict[str, str]]] = {
    "wordpress": [
        {"header": "x-powered-by", "pattern": r"wordpress|wp engine"},
        {"body": r"wp-content|wp-includes|wp-json"},
        {"body": r'<meta name="generator" content="WordPress'},
    ],
    "woocommerce": [
        {"body": r"woocommerce|wc-ajax|wc_cart"},
    ],
    "drupal": [
        {"header": "x-generator", "pattern": r"drupal"},
        {"header": "x-drupal-cache", "pattern": r".+"},
        {"body": r"drupal\.settings|Drupal\.behaviors"},
    ],
    "joomla": [
        {"header": "x-content-encoded-by", "pattern": r"joomla"},
        {"body": r"/media/jui/|/administrator/|Joomla!"},
    ],
    "django": [
        {"header": "x-frame-options", "pattern": r"sameorigin"},
        {"body": r"csrfmiddlewaretoken|__admin__"},
    ],
    "rails": [
        {"header": "x-request-id", "pattern": r".+"},
        {"header": "x-runtime", "pattern": r"\d+\.\d+"},
    ],
    "laravel": [
        {"header": "set-cookie", "pattern": r"laravel_session"},
        {"body": r"laravel|XSRF-TOKEN"},
    ],
    "nextjs": [
        {"header": "x-powered-by", "pattern": r"next\.js"},
        {"body": r"__next|_next/static"},
    ],
    "nuxtjs": [
        {"body": r"__nuxt|_nuxt/"},
    ],
    "react": [
        {"body": r"react\.production\.min|__react"},
        {"body": r'<div id="root">|<div id="app">'},
    ],
    "angular": [
        {"body": r"ng-version|angular\.min|ng-app"},
    ],
    "vue": [
        {"body": r"vue\.min|v-bind|v-model|__vue__"},
    ],
    "asp_net": [
        {"header": "x-aspnet-version", "pattern": r".+"},
        {"header": "x-powered-by", "pattern": r"asp\.net"},
        {"body": r"__VIEWSTATE|__EVENTVALIDATION"},
    ],
    "php": [
        {"header": "x-powered-by", "pattern": r"php"},
        {"body": r"\.php[?\"]"},
    ],
    "nginx": [
        {"header": "server", "pattern": r"nginx"},
    ],
    "apache": [
        {"header": "server", "pattern": r"apache"},
    ],
    "iis": [
        {"header": "server", "pattern": r"microsoft-iis"},
    ],
    "cloudflare_cdn": [
        {"header": "server", "pattern": r"cloudflare"},
        {"header": "cf-ray", "pattern": r".+"},
    ],
    "tomcat": [
        {"header": "server", "pattern": r"apache.coyote|tomcat"},
    ],
    "express": [
        {"header": "x-powered-by", "pattern": r"express"},
    ],
    "flask": [
        {"header": "server", "pattern": r"werkzeug"},
    ],
    "spring": [
        {"header": "x-application-context", "pattern": r".+"},
    ],
}


class TechnologyDetectorPlugin(CrawlerPlugin):
    """Detects web technologies from HTTP headers and page content."""

    name = "tech_detector"
    priority = 10

    def detect_technology(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> list[str]:
        detected: list[str] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        body_lower = body[:50_000].lower()  # limit body scan size

        for tech_name, signatures in _TECH_SIGNATURES.items():
            for sig in signatures:
                if "header" in sig:
                    hdr_val = lower_headers.get(sig["header"], "")
                    if hdr_val and re.search(
                        sig["pattern"], hdr_val, re.IGNORECASE
                    ):
                        detected.append(tech_name)
                        break
                elif "body" in sig:
                    if re.search(sig["body"], body_lower, re.IGNORECASE):
                        detected.append(tech_name)
                        break

        return detected
