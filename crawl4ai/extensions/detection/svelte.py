"""
Svelte / SvelteKit detection.

Identifies Svelte- or SvelteKit-powered websites by checking for
``svelte-``, ``__sveltekit``, ``data-sveltekit``, ``svelte/internal``,
``.svelte-``, and ``__svelte_meta`` signatures in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["SvelteDetector"]


class SvelteDetector(BaseDetector):
    """Detect Svelte / SvelteKit-powered websites."""

    name = "svelte"

    _SIGNATURES = (
        "svelte-",
        "__sveltekit",
        "data-sveltekit",
        "svelte/internal",
        ".svelte-",
        "__svelte_meta",
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
                return {"type": "svelte", "method": "body", "signature": sig}
        return None
