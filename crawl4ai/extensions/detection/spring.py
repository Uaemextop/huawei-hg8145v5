"""
Spring Framework (Java) detection.

Identifies Spring-powered applications by inspecting
``X-Application-Context``, ``JSESSIONID`` cookie, and body markers
like ``Whitelabel Error Page`` or ``/webjars/``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["SpringDetector"]


class SpringDetector(BaseDetector):
    """Detect Spring Framework (Java) applications."""

    name = "spring"

    _BODY_SIGNATURES = (
        "/webjars/",
        "Whitelabel Error Page",
        "Spring Framework",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if headers.get("x-application-context"):
            return {"type": "spring", "method": "header",
                    "signature": "x-application-context"}

        set_cookie = headers.get("set-cookie", "")
        if "JSESSIONID" in set_cookie:
            return {"type": "spring", "method": "header",
                    "signature": "JSESSIONID"}

        if body:
            for sig in self._BODY_SIGNATURES:
                if sig in body:
                    return {"type": "spring", "method": "body",
                            "signature": sig}

        return None
