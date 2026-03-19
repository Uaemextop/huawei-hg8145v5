"""
Backbone.js detection.

Identifies websites using Backbone.js by checking for ``backbone.min.js``,
``backbone.js``, ``Backbone.Model``, ``Backbone.View``,
``Backbone.Collection``, and ``Backbone.Router`` references in the
response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["BackboneDetector"]


class BackboneDetector(BaseDetector):
    """Detect Backbone.js usage on websites."""

    name = "backbone"

    _SIGNATURES = (
        "backbone.min.js",
        "backbone.js",
        "Backbone.Model",
        "Backbone.View",
        "Backbone.Collection",
        "Backbone.Router",
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
                return {"type": "backbone", "method": "body",
                        "signature": sig}
        return None
