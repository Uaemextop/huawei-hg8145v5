"""
Flask framework detection.

Identifies Flask / Werkzeug applications by checking for ``Werkzeug`` in the
``server`` response header and the typical Flask session cookie pattern in
``Set-Cookie``, as well as body references to ``flask`` and ``werkzeug``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["FlaskDetector"]


class FlaskDetector(BaseDetector):
    """Detect Flask / Werkzeug applications."""

    name = "flask"

    _SIGNATURES = (
        "flask",
        "werkzeug",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Werkzeug server header
        server = headers.get("server", "")
        if "Werkzeug" in server:
            return {"type": "flask", "method": "header",
                    "signature": "server: Werkzeug"}

        # Flask-signed session cookie (starts with "session=" and a dot)
        set_cookie = headers.get("set-cookie", "")
        if "session=" in set_cookie and "." in set_cookie:
            # Flask session cookies use itsdangerous signing: "session=<b64>.<sig>"
            idx = set_cookie.index("session=")
            fragment = set_cookie[idx:idx + 80]
            if "." in fragment:
                return {"type": "flask", "method": "header",
                        "signature": "session cookie"}

        # Check body signatures
        if body:
            body_lower = body.lower()
            for sig in self._SIGNATURES:
                if sig in body_lower:
                    return {"type": "flask", "method": "body",
                            "signature": sig}

        return None
