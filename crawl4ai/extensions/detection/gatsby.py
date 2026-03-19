"""
Gatsby detection.

Identifies Gatsby-powered websites by checking for ``___gatsby``,
``gatsby-image``, ``gatsby-link``, ``gatsby-resp-image``,
``gatsby-plugin``, ``window.___gatsby``, and ``gatsby-focus-wrapper``
signatures in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["GatsbyDetector"]


class GatsbyDetector(BaseDetector):
    """Detect Gatsby-powered websites."""

    name = "gatsby"

    _SIGNATURES = (
        "___gatsby",
        "gatsby-image",
        "gatsby-link",
        "gatsby-resp-image",
        "gatsby-plugin",
        "window.___gatsby",
        "gatsby-focus-wrapper",
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
        for sig in self._SIGNATURES:
            if sig in body:
                return {"type": "gatsby", "method": "body", "signature": sig}
        return None
