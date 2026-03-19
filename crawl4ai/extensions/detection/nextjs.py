"""
Next.js detection.

Identifies Next.js-powered websites by checking for ``x-nextjs-cache``,
``x-nextjs-matched-path``, and ``x-powered-by: Next.js`` response headers,
as well as ``__NEXT_DATA__``, ``_next/static``, ``_next/image``, and other
body signatures.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["NextjsDetector"]


class NextjsDetector(BaseDetector):
    """Detect Next.js-powered websites."""

    name = "nextjs"

    _SIGNATURES = (
        "__NEXT_DATA__",
        "_next/static",
        "_next/image",
        "next/dist",
        "__next",
        "next-route-announcer",
    )

    _HEADER_KEYS = (
        "x-nextjs-cache",
        "x-nextjs-matched-path",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers first (cheapest)
        for key in self._HEADER_KEYS:
            if key in headers:
                return {"type": "nextjs", "method": "header", "signature": key}

        powered_by = headers.get("x-powered-by", "")
        if "Next.js" in powered_by:
            return {"type": "nextjs", "method": "header",
                    "signature": "x-powered-by: Next.js"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "nextjs", "method": "body",
                            "signature": sig}

        return None
