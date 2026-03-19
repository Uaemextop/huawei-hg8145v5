"""
GraphQL API detection.

Identifies GraphQL APIs by searching for common GraphQL markers in the
response body such as ``__schema``, ``__typename``, ``/graphql``,
and query/mutation syntax.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["GraphQLDetector"]


class GraphQLDetector(BaseDetector):
    """Detect GraphQL API endpoints and clients."""

    name = "graphql"

    _BODY_SIGNATURES = (
        "__schema",
        "__typename",
        "/graphql",
        "query {",
        "mutation {",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if not body:
            return None

        for sig in self._BODY_SIGNATURES:
            if sig in body:
                return {"type": "graphql", "method": "body",
                        "signature": sig}

        return None
