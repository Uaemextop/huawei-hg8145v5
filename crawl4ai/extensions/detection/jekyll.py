"""
Jekyll static site generator detection.

Identifies Jekyll-generated websites by checking for a ``Jekyll`` generator
meta tag, body signatures such as ``jekyll-theme-`` and ``/assets/main.css``,
and the ``server: GitHub.com`` header (GitHub Pages often runs Jekyll).
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["JekyllDetector"]


class JekyllDetector(BaseDetector):
    """Detect Jekyll-generated websites."""

    name = "jekyll"

    _SIGNATURES = (
        'generator" content="Jekyll',
        "jekyll",
        "/assets/main.css",
        "jekyll-theme-",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check for GitHub Pages server header combined with Jekyll body hint
        server = headers.get("server", "")
        is_github_pages = "GitHub.com" in server

        if is_github_pages and body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "jekyll", "method": "header+body",
                            "signature": sig}

        # Check body signatures alone
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "jekyll", "method": "body",
                            "signature": sig}

        return None
