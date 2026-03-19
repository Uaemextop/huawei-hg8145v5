"""
Laravel PHP framework detection.

Identifies Laravel applications by checking for ``laravel_session`` and
``XSRF-TOKEN`` in the ``Set-Cookie`` header, and body signatures such as
``laravel-livewire`` and ``laravel.blade``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["LaravelDetector"]


class LaravelDetector(BaseDetector):
    """Detect Laravel applications."""

    name = "laravel"

    _SIGNATURES = (
        "laravel-livewire",
        "laravel.blade",
        "Laravel\\",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check Set-Cookie for laravel_session
        set_cookie = headers.get("set-cookie", "")
        if "laravel_session" in set_cookie:
            return {"type": "laravel", "method": "header",
                    "signature": "laravel_session cookie"}
        if "XSRF-TOKEN" in set_cookie:
            return {"type": "laravel", "method": "header",
                    "signature": "XSRF-TOKEN cookie"}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "laravel", "method": "body",
                            "signature": sig}

        return None
