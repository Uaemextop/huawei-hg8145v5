"""
Ruby on Rails detection.

Identifies Ruby on Rails applications by checking for ``X-Runtime``,
``X-Request-Id``, and ``X-Powered-By: Phusion Passenger`` response headers,
the ``_session_id`` cookie, and body signatures such as ``csrf-token``,
``authenticity_token``, ``data-turbolinks-``, and ``turbo-frame``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["RailsDetector"]


class RailsDetector(BaseDetector):
    """Detect Ruby on Rails applications."""

    name = "rails"

    _SIGNATURES = (
        "csrf-token",
        "authenticity_token",
        "data-turbolinks-",
        "turbo-frame",
        "data-turbo-",
    )

    _HEADER_KEYS = (
        "x-runtime",
        "x-request-id",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check characteristic headers
        for key in self._HEADER_KEYS:
            if key in headers:
                return {"type": "rails", "method": "header",
                        "signature": key}

        powered_by = headers.get("x-powered-by", "")
        if "Phusion Passenger" in powered_by:
            return {"type": "rails", "method": "header",
                    "signature": "x-powered-by: Phusion Passenger"}

        # Check Set-Cookie for _session_id
        set_cookie = headers.get("set-cookie", "")
        if "_session_id" in set_cookie:
            return {"type": "rails", "method": "header",
                    "signature": "_session_id cookie"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "rails", "method": "body",
                            "signature": sig}

        return None
