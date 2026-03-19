"""SPA renderer handler – configures browser-based crawling for JS frameworks."""
from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["SPARendererHandler"]

# Framework-specific wait selectors
_FRAMEWORK_SELECTORS: dict[str, list[str]] = {
    "react": ["[data-reactroot]", "[data-reactid]", "#root"],
    "angular": ["[ng-version]", "[ng-app]", "app-root"],
    "vue": ["[data-v-]", "#app", "[data-server-rendered]"],
    "svelte": ["[class^='svelte-']", "#svelte"],
    "ember": [".ember-view", ".ember-application"],
    "backbone": ["[data-backbone]"],
    "gatsby": ["#___gatsby", "#gatsby-focus-wrapper"],
    "nextjs": ["#__next", "[data-nextjs-page]"],
    "nuxt": ["#__nuxt", "#__layout", "[data-server-rendered]"],
}

_SPA_TYPES = frozenset(_FRAMEWORK_SELECTORS)


class SPARendererHandler(BaseHandler):
    """Handle SPA frameworks by recommending browser-based rendering.

    Supports: React, Angular, Vue, Svelte, Ember, Backbone, Gatsby,
    Next.js, and Nuxt.js.
    """

    name = "spa_renderer"

    # ------------------------------------------------------------------
    # Interface
    # ------------------------------------------------------------------

    def can_handle(self, detection: dict) -> bool:
        """Return True for any known SPA framework detection."""
        return detection.get("type", "") in _SPA_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Configure browser rendering and extract framework-specific data."""
        fw = detection.get("type", "")
        actions: list[str] = []
        extra_urls: list[str] = []

        try:
            selectors = _FRAMEWORK_SELECTORS.get(fw, [])
            config: dict = {
                "use_browser": True,
                "wait_for_js": True,
                "wait_time": 3,
            }
            if selectors:
                config["wait_for_selectors"] = selectors
            actions.append(
                f"Configured browser rendering for {fw} "
                f"(selectors={selectors})"
            )

            body = _body(response)

            # Next.js: extract __NEXT_DATA__ for pre-rendered routes
            if fw == "nextjs" and body:
                extra_urls.extend(_extract_next_data_urls(url, body))
                if extra_urls:
                    actions.append(
                        f"Extracted {len(extra_urls)} URL(s) from __NEXT_DATA__"
                    )

            # Nuxt.js: extract __NUXT__ state
            if fw == "nuxt" and body:
                extra_urls.extend(_extract_nuxt_urls(url, body))
                if extra_urls:
                    actions.append(
                        f"Extracted {len(extra_urls)} URL(s) from __NUXT__ state"
                    )

        except Exception:
            log.debug("SPARendererHandler error for %s", url, exc_info=True)
            actions.append(f"Error processing {fw} detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={},
            recommended_config=config,
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _body(response: "requests.Response | None") -> str:
    """Safely extract response text."""
    if response is None:
        return ""
    try:
        return response.text or ""
    except Exception:
        return ""


_NEXT_DATA_RE = re.compile(
    r'<script\s+id="__NEXT_DATA__"\s+type="application/json">\s*({.*?})\s*</script>',
    re.DOTALL,
)


def _extract_next_data_urls(base_url: str, body: str) -> list[str]:
    """Parse __NEXT_DATA__ JSON and extract API / page routes."""
    urls: list[str] = []
    m = _NEXT_DATA_RE.search(body)
    if not m:
        return urls
    try:
        data = json.loads(m.group(1))
        # Collect page paths from buildManifest or dynamicIds
        pages = set()
        build_manifest = data.get("buildManifest", {})
        for page in build_manifest.get("pages", {}):
            if page != "/_app" and page != "/_error":
                pages.add(page)
        # Props may contain API endpoints
        props = data.get("props", {}).get("pageProps", {})
        _collect_urls_from_dict(props, urls, base_url)
        # Convert page paths to full URLs
        from urllib.parse import urljoin

        for page in pages:
            urls.append(urljoin(base_url, page))
    except (json.JSONDecodeError, TypeError, KeyError):
        pass
    return urls


_NUXT_RE = re.compile(
    r'window\.__NUXT__\s*=\s*(.+?);\s*</script>',
    re.DOTALL,
)


def _extract_nuxt_urls(base_url: str, body: str) -> list[str]:
    """Extract URLs from Nuxt.js __NUXT__ state."""
    urls: list[str] = []
    m = _NUXT_RE.search(body)
    if not m:
        return urls
    raw = m.group(1).strip()
    # __NUXT__ is often a JS expression, not pure JSON – try JSON first
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return urls
    _collect_urls_from_dict(data, urls, base_url)
    return urls


_URL_LIKE = re.compile(r'https?://[^\s"\'<>]+|/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=-]+')


def _collect_urls_from_dict(obj: object, out: list[str], base: str) -> None:
    """Recursively collect URL-like strings from nested dicts/lists."""
    if isinstance(obj, str):
        if _URL_LIKE.fullmatch(obj):
            from urllib.parse import urljoin

            out.append(urljoin(base, obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_urls_from_dict(v, out, base)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _collect_urls_from_dict(item, out, base)
