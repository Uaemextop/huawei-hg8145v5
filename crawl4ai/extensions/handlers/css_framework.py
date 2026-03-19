"""CSS / JS framework handler – informational logging and jQuery URL discovery."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["CSSFrameworkHandler"]

_CSS_TYPES = frozenset({"bootstrap", "tailwind", "jquery"})

# Pattern to find jQuery AJAX calls that reference URLs
_JQUERY_AJAX_RE = re.compile(
    r"""\$\.\s*(?:ajax|get|post|getJSON)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


class CSSFrameworkHandler(BaseHandler):
    """Handle CSS/JS framework detections.

    * **Bootstrap / Tailwind** – informational logging only.
    * **jQuery** – scans page for AJAX call patterns to discover extra URLs.
    """

    name = "css_framework"

    def can_handle(self, detection: dict) -> bool:
        """Return True for Bootstrap, Tailwind, or jQuery detections."""
        return detection.get("type", "") in _CSS_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Log detection; for jQuery scan for AJAX URL patterns."""
        fw = detection.get("type", "")
        actions: list[str] = []
        extra_urls: list[str] = []

        try:
            if fw in ("bootstrap", "tailwind"):
                actions.append(f"Detected {fw.title()} CSS framework (informational)")
                log.info("Detected %s on %s", fw, url)

            elif fw == "jquery":
                actions.append("Detected jQuery; scanning for AJAX patterns")
                body = _body(response)
                if body:
                    found = _JQUERY_AJAX_RE.findall(body)
                    if found:
                        from urllib.parse import urljoin

                        for endpoint in dict.fromkeys(found):
                            extra_urls.append(urljoin(url, endpoint))
                        actions.append(
                            f"Discovered {len(extra_urls)} jQuery AJAX endpoint(s)"
                        )
        except Exception:
            log.debug("CSSFrameworkHandler error for %s", url, exc_info=True)
            actions.append(f"Error processing {fw} detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={},
            recommended_config={},
        )


def _body(response: "requests.Response | None") -> str:
    if response is None:
        return ""
    try:
        return response.text or ""
    except Exception:
        return ""
