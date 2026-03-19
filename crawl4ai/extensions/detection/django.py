"""
Django framework detection.

Identifies Django-powered websites by checking for ``csrfmiddlewaretoken``,
``/static/admin/``, and ``djangoproject.com`` in the response body, as well
as the ``csrftoken`` cookie and ``X-Frame-Options: DENY`` header (common
Django defaults).
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["DjangoDetector"]


class DjangoDetector(BaseDetector):
    """Detect Django-powered websites."""

    name = "django"

    _SIGNATURES = (
        "csrfmiddlewaretoken",
        "django.contrib",
        "__admin_media_prefix__",
        "/static/admin/",
        "djangoproject.com",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check Set-Cookie for csrftoken (strong signal)
        set_cookie = headers.get("set-cookie", "")
        if "csrftoken" in set_cookie:
            return {"type": "django", "method": "header",
                    "signature": "csrftoken cookie"}

        # X-Frame-Options: DENY is Django's default – weak on its own,
        # combine with body check below
        x_frame = headers.get("x-frame-options", "")

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "django", "method": "body",
                            "signature": sig}

            # X-Frame-Options DENY + any Django-ish body hint
            if x_frame.upper() == "DENY" and "csrf" in body.lower():
                return {"type": "django", "method": "header",
                        "signature": "X-Frame-Options: DENY"}

        return None
