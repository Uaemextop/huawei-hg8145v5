"""
Tailwind CSS detection.

Identifies websites using Tailwind CSS by checking for ``tailwindcss``
and ``tailwind.min.css`` script/style references in the response body.
Utility-class heuristics (``flex``, ``grid``, ``bg-``, etc.) are used as
a secondary signal but are not relied upon alone because many frameworks
share similar class names.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["TailwindDetector"]


class TailwindDetector(BaseDetector):
    """Detect Tailwind CSS framework usage on websites."""

    name = "tailwind"

    _SIGNATURES = (
        "tailwindcss",
        "tailwind.min.css",
    )

    _UTILITY_PATTERNS = (
        'class="flex ',
        'class="grid ',
        'class="bg-',
        'class="text-',
        'class="p-',
        'class="m-',
    )

    _MIN_UTILITY_CLASS_MATCHES = 5

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if not body:
            return None

        # Strong signals: explicit Tailwind references
        for sig in self._SIGNATURES:
            if sig in body:
                return {"type": "tailwind", "method": "body",
                        "signature": sig}

        # Weak heuristic: multiple Tailwind-style utility classes
        matches = sum(1 for pat in self._UTILITY_PATTERNS if pat in body)
        if matches > self._MIN_UTILITY_CLASS_MATCHES:
            return {"type": "tailwind", "method": "heuristic",
                    "signature": "utility-classes",
                    "matches": matches}

        return None
