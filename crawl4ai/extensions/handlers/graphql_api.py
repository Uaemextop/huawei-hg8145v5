"""GraphQL API handler – discovers and probes GraphQL endpoints."""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["GraphQLAPIHandler"]

_GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/gql",
)

_GRAPHQL_ENDPOINT_RE = re.compile(
    r"""(?:fetch|axios\.post|url|endpoint)\s*[\(\:=]\s*['"]([^'"]*graphql[^'"]*?)['"]""",
    re.IGNORECASE,
)


class GraphQLAPIHandler(BaseHandler):
    """Discover and probe GraphQL endpoints.

    When a GraphQL API is detected on a page, this handler extracts
    endpoint URLs and queues introspection queries to map the schema.
    """

    name = "graphql_api"

    def can_handle(self, detection: dict) -> bool:
        return detection.get("type", "") == "graphql"

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        actions: list[str] = []
        extra_urls: list[str] = []

        try:
            # Probe common GraphQL paths
            for path in _GRAPHQL_PATHS:
                extra_urls.append(urljoin(url, path))
            actions.append(
                f"Probing {len(_GRAPHQL_PATHS)} common GraphQL endpoint(s)"
            )

            # Try to extract endpoint URLs from the page body
            body = _body(response)
            if body:
                matches = _GRAPHQL_ENDPOINT_RE.findall(body)
                for m in matches:
                    resolved = urljoin(url, m)
                    if resolved not in extra_urls:
                        extra_urls.append(resolved)
                if matches:
                    actions.append(
                        f"Extracted {len(matches)} GraphQL endpoint(s) from page"
                    )

        except Exception:
            log.debug("GraphQLAPIHandler error for %s", url, exc_info=True)
            actions.append("Error processing GraphQL detection")

        return HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=extra_urls,
            extra_headers={"Content-Type": "application/json"},
            recommended_config={},
        )


def _body(response: "requests.Response | None") -> str:
    if response is None:
        return ""
    try:
        return response.text or ""
    except Exception:
        return ""
