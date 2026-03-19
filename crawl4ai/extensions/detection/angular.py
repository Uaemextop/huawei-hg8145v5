"""
Angular detection.

Identifies Angular-powered websites by checking for ``ng-version``,
``ng-app``, ``ng-controller``, ``ng-model``, ``platformBrowserDynamic``,
and Angular library script references in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["AngularDetector"]


class AngularDetector(BaseDetector):
    """Detect Angular-powered websites."""

    name = "angular"

    _SIGNATURES = (
        "ng-version",
        "ng-app",
        "ng-controller",
        "ng-model",
        "angular.min.js",
        "angular.js",
        "ng-binding",
        ".ng-scope",
        "platformBrowserDynamic",
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
                return {"type": "angular", "method": "body", "signature": sig}
        return None
