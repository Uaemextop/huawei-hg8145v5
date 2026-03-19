"""
Netlify platform detection.

Identifies Netlify-hosted sites by inspecting ``x-nf-request-id``,
``server`` headers and body references to Netlify domains.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["NetlifyDetector"]


class NetlifyDetector(BaseDetector):
    """Detect Netlify-hosted websites."""

    name = "netlify"

    _BODY_SIGNATURES = (
        "netlify.app",
        "netlify.com",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if headers.get("x-nf-request-id"):
            return {"type": "netlify", "method": "header",
                    "signature": "x-nf-request-id"}

        server = headers.get("server", "").lower()
        if server == "netlify":
            return {"type": "netlify", "method": "header",
                    "signature": "server"}

        if body:
            for sig in self._BODY_SIGNATURES:
                if sig in body:
                    return {"type": "netlify", "method": "body",
                            "signature": sig}

        return None
