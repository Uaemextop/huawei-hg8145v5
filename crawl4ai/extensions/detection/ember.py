"""
Ember.js detection.

Identifies Ember.js-powered websites by checking for ``ember-view``,
``ember-application``, ``data-ember-action``, ``Ember.Application``,
``ember-cli``, and Ember library script references in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["EmberDetector"]


class EmberDetector(BaseDetector):
    """Detect Ember.js-powered websites."""

    name = "ember"

    _SIGNATURES = (
        "ember-view",
        "ember-application",
        "data-ember-action",
        "ember.min.js",
        "ember.js",
        "Ember.Application",
        "ember-cli",
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
                return {"type": "ember", "method": "body", "signature": sig}
        return None
