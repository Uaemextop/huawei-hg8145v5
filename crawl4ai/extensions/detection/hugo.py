"""
Hugo static site generator detection.

Identifies Hugo-generated websites by checking for a ``Hugo`` generator
meta tag and body signatures such as ``hugo-``, ``/tags/``, and
``/categories/``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["HugoDetector"]


class HugoDetector(BaseDetector):
    """Detect Hugo-generated websites."""

    name = "hugo"

    _GENERATOR_SIGNATURES = (
        'content="Hugo',
        "generator Hugo",
    )

    _BODY_SIGNATURES = (
        "Hugo",
        "hugo-",
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

        # Strong signal: generator meta tag mentioning Hugo
        for sig in self._GENERATOR_SIGNATURES:
            if sig in body:
                return {"type": "hugo", "method": "body", "signature": sig}

        # Weaker signals: Hugo-specific patterns combined with typical
        # Hugo URL structures (/tags/, /categories/)
        body_lower = body.lower()
        has_hugo_ref = any(sig.lower() in body_lower
                          for sig in self._BODY_SIGNATURES)
        if has_hugo_ref:
            if "/tags/" in body or "/categories/" in body:
                return {"type": "hugo", "method": "body",
                        "signature": "hugo + url patterns"}

        return None
