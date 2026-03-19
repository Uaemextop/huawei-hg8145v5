"""PWA (Progressive Web App) handler – discovers service worker and manifest."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["PWAHandler"]

_MANIFEST_RE = re.compile(
    r'<link\s+[^>]*rel="manifest"[^>]*href="([^"]+)"', re.IGNORECASE,
)

_SW_REGISTER_RE = re.compile(
    r"""navigator\.serviceWorker\.register\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


class PWAHandler(BaseHandler):
    """Handle Progressive Web Apps.

    Discovers the web app manifest and service worker script, and
    extracts cached URLs from the service worker for additional crawling.
    """

    name = "pwa_handler"

    def can_handle(self, detection: dict) -> bool:
        return detection.get("type", "") == "pwa"

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        actions: list[str] = []
        extra_urls: list[str] = []
        config: dict = {}

        try:
            body = _body(response)

            # Discover manifest.json
            m = _MANIFEST_RE.search(body)
            if m:
                manifest_url = urljoin(url, m.group(1))
                extra_urls.append(manifest_url)
                actions.append(f"Found PWA manifest: {manifest_url}")
            else:
                # Try common paths
                for path in ("/manifest.json", "/manifest.webmanifest"):
                    extra_urls.append(urljoin(url, path))
                actions.append("Probing common PWA manifest paths")

            # Discover service worker
            m = _SW_REGISTER_RE.search(body)
            if m:
                sw_url = urljoin(url, m.group(1))
                extra_urls.append(sw_url)
                actions.append(f"Found service worker: {sw_url}")
            else:
                for path in ("/sw.js", "/service-worker.js"):
                    extra_urls.append(urljoin(url, path))
                actions.append("Probing common service worker paths")

            # PWAs are SPAs – need browser rendering
            config["use_browser"] = True
            config["wait_for_js"] = True
            actions.append("PWA detected – recommending browser rendering")

        except Exception:
            log.debug("PWAHandler error for %s", url, exc_info=True)
            actions.append("Error processing PWA detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={},
            recommended_config=config,
        )


def _body(response: "requests.Response | None") -> str:
    if response is None:
        return ""
    try:
        return response.text or ""
    except Exception:
        return ""
