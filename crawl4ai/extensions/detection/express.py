"""
Express.js (Node) detection.

Identifies Express.js applications by checking for ``X-Powered-By: Express``
in response headers and the ``connect.sid`` session cookie.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["ExpressDetector"]


class ExpressDetector(BaseDetector):
    """Detect Express.js applications."""

    name = "express"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        powered_by = headers.get("x-powered-by", "")
        if "Express" in powered_by:
            return {"type": "express", "method": "header",
                    "signature": "x-powered-by: Express"}

        # Check Set-Cookie for connect.sid
        set_cookie = headers.get("set-cookie", "")
        if "connect.sid" in set_cookie:
            return {"type": "express", "method": "header",
                    "signature": "connect.sid cookie"}

        return None
