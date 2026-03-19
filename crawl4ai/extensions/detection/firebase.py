"""
Firebase detection.

Identifies Firebase-powered applications by searching for
``firebaseapp.com``, ``firebaseio.com``, ``firebase.js``, and
related markers in the response body.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["FirebaseDetector"]


class FirebaseDetector(BaseDetector):
    """Detect Firebase-powered applications."""

    name = "firebase"

    _BODY_SIGNATURES = (
        "firebase.google.com",
        "firebaseapp.com",
        "firebase.js",
        "firebaseio.com",
        "__firebase_request_key",
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

        for sig in self._BODY_SIGNATURES:
            if sig in body:
                return {"type": "firebase", "method": "body",
                        "signature": sig}

        return None
