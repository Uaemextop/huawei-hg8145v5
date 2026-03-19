"""
Nuxt.js detection.

Identifies Nuxt.js-powered websites by checking for the
``x-powered-by: Nuxt`` response header, as well as ``__NUXT__``,
``_nuxt/``, ``nuxt.config``, ``data-n-head``, ``nuxt-link``, and
``$nuxt`` body signatures.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["NuxtDetector"]


class NuxtDetector(BaseDetector):
    """Detect Nuxt.js-powered websites."""

    name = "nuxt"

    _SIGNATURES = (
        "__NUXT__",
        "_nuxt/",
        "nuxt.config",
        "data-n-head",
        "nuxt-link",
        "$nuxt",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers first (cheapest)
        powered_by = headers.get("x-powered-by", "")
        if "Nuxt" in powered_by:
            return {"type": "nuxt", "method": "header",
                    "signature": "x-powered-by: Nuxt"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "nuxt", "method": "body",
                            "signature": sig}

        return None
