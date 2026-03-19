"""
Vercel platform detection.

Identifies Vercel-hosted sites by inspecting ``x-vercel-id``,
``x-vercel-cache``, ``server`` headers and body references to Vercel.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["VercelDetector"]


class VercelDetector(BaseDetector):
    """Detect Vercel-hosted websites."""

    name = "vercel"

    _BODY_SIGNATURES = (
        "_vercel/",
        "vercel.app",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if headers.get("x-vercel-id"):
            return {"type": "vercel", "method": "header",
                    "signature": "x-vercel-id"}

        if headers.get("x-vercel-cache"):
            return {"type": "vercel", "method": "header",
                    "signature": "x-vercel-cache"}

        server = headers.get("server", "").lower()
        if server == "vercel":
            return {"type": "vercel", "method": "header",
                    "signature": "server"}

        if body:
            for sig in self._BODY_SIGNATURES:
                if sig in body:
                    return {"type": "vercel", "method": "body",
                            "signature": sig}

        return None
