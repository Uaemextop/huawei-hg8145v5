"""Firebase handler – discovers Firebase project resources."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["FirebaseHandler"]

_FIREBASE_CONFIG_RE = re.compile(
    r"""firebase(?:Config|App)[\s\S]*?(?:apiKey|projectId)\s*:\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_FIRESTORE_PROJECT_RE = re.compile(
    r"""firestore\.googleapis\.com/v1/projects/([a-zA-Z0-9_-]+)""",
)


class FirebaseHandler(BaseHandler):
    """Discover Firebase project endpoints and Firestore collections.

    When Firebase is detected, probes for Firestore REST API, Realtime
    Database, Cloud Functions, and Firebase Hosting config.
    """

    name = "firebase_handler"

    def can_handle(self, detection: dict) -> bool:
        return detection.get("type", "") == "firebase"

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
            # Probe Firebase Hosting config
            extra_urls.append(urljoin(url, "/__/firebase/init.json"))
            actions.append("Probing Firebase Hosting init config")

            # Look for Firebase project ID in page
            body = _body(response)
            project_ids: set[str] = set()

            if body:
                for m in _FIRESTORE_PROJECT_RE.finditer(body):
                    project_ids.add(m.group(1))

            if project_ids:
                config["firebase_projects"] = list(project_ids)
                actions.append(
                    f"Found Firebase project(s): {', '.join(project_ids)}"
                )

            # Recommend browser-based crawling for Firebase SPAs
            config["use_browser"] = True
            config["wait_for_js"] = True
            actions.append(
                "Firebase SPA detected – recommending browser rendering"
            )

        except Exception:
            log.debug("FirebaseHandler error for %s", url, exc_info=True)
            actions.append("Error processing Firebase detection")

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
