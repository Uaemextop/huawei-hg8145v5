"""Server optimizer handler – tunes requests based on detected web server."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["ServerOptimizerHandler"]

_SERVER_TYPES = frozenset({"nginx", "apache", "iis", "express"})


class ServerOptimizerHandler(BaseHandler):
    """Optimise request headers and probe server-specific endpoints.

    Supports Nginx, Apache, IIS, and Express.
    """

    name = "server_optimizer"

    def can_handle(self, detection: dict) -> bool:
        """Return True for any known web-server detection."""
        return detection.get("type", "") in _SERVER_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Apply server-specific optimisations."""
        server = detection.get("type", "")
        actions: list[str] = []
        extra_urls: list[str] = []
        extra_headers: dict = {}

        try:
            if server == "nginx":
                extra_headers["Accept-Encoding"] = "gzip, deflate, br"
                actions.append(
                    "Added Accept-Encoding: gzip, deflate, br for Nginx"
                )

            elif server == "apache":
                probes = ["/.htaccess", "/server-status", "/server-info"]
                for p in probes:
                    extra_urls.append(urljoin(url, p))
                actions.append(
                    "Probing Apache info endpoints: "
                    + ", ".join(probes)
                )

            elif server == "iis":
                probes = ["/web.config", "/_vti_bin/", "/aspnet_client/"]
                for p in probes:
                    extra_urls.append(urljoin(url, p))
                actions.append(
                    "Probing IIS info endpoints: "
                    + ", ".join(probes)
                )

            elif server == "express":
                extra_urls.extend([
                    urljoin(url, "/api/"),
                    urljoin(url, "/health"),
                    urljoin(url, "/status"),
                ])
                actions.append(
                    "Probing common Express routes (/api/, /health, /status); "
                    "adjusted timeout expectations for Node.js"
                )

        except Exception:
            log.debug(
                "ServerOptimizerHandler error for %s", url, exc_info=True
            )
            actions.append(f"Error processing {server} detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers=extra_headers,
            recommended_config={},
        )
