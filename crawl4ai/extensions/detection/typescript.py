"""
TypeScript build-artifact detection.

Identifies websites built with TypeScript by checking for ``.ts.map``
source-map references, ``tsconfig`` mentions, ``sourceMapping`` directives,
and ``.js.map`` source maps that reference ``.ts`` source files in the
response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["TypeScriptDetector"]


class TypeScriptDetector(BaseDetector):
    """Detect TypeScript build artifacts in websites."""

    name = "typescript"

    _SIGNATURES = (
        ".ts.map",
        "tsconfig",
        "sourceMappingURL",
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

        # Direct TypeScript artifact signatures
        for sig in self._SIGNATURES:
            if sig in body:
                return {"type": "typescript", "method": "body",
                        "signature": sig}

        # Heuristic: .js.map files referencing .ts sources
        if ".js.map" in body and ".ts" in body:
            return {"type": "typescript", "method": "heuristic",
                    "signature": ".js.map+.ts"}

        return None
