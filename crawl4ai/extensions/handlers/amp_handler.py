"""AMP (Accelerated Mobile Pages) handler – discovers AMP-specific resources."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["AMPHandler"]

_AMP_CANONICAL_RE = re.compile(
    r'<link\s+rel="amphtml"\s+href="([^"]+)"', re.IGNORECASE,
)

_AMP_CANONICAL_ORIG_RE = re.compile(
    r'<link\s+rel="canonical"\s+href="([^"]+)"', re.IGNORECASE,
)


class AMPHandler(BaseHandler):
    """Handle Google AMP pages.

    Discovers the canonical (non-AMP) version and any AMP-specific
    resources like AMP component scripts and AMP cache URLs.
    """

    name = "amp_handler"

    def can_handle(self, detection: dict) -> bool:
        return detection.get("type", "") == "amp"

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

            # Check for canonical link (non-AMP version)
            m = _AMP_CANONICAL_ORIG_RE.search(body)
            if m:
                canonical = urljoin(url, m.group(1))
                extra_urls.append(canonical)
                actions.append(f"Found canonical (non-AMP) URL: {canonical}")

            # Check if non-AMP page links to AMP version
            m = _AMP_CANONICAL_RE.search(body)
            if m:
                amp_url = urljoin(url, m.group(1))
                extra_urls.append(amp_url)
                actions.append(f"Found AMP version URL: {amp_url}")

            # AMP pages don't need JS rendering
            config["use_browser"] = False
            actions.append("AMP page detected – no JS rendering needed")

        except Exception:
            log.debug("AMPHandler error for %s", url, exc_info=True)
            actions.append("Error processing AMP detection")

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
