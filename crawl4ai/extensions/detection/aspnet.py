"""
ASP.NET detection.

Identifies ASP.NET applications by checking for ``X-Powered-By: ASP.NET``,
``X-AspNet-Version``, and ``X-AspNetMvc-Version`` response headers, as well
as body signatures such as ``__VIEWSTATE``, ``__EVENTVALIDATION``,
``__doPostBack``, and ``.aspx``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["AspNetDetector"]


class AspNetDetector(BaseDetector):
    """Detect ASP.NET applications."""

    name = "aspnet"

    _SIGNATURES = (
        "__VIEWSTATE",
        "__EVENTVALIDATION",
        "__doPostBack",
        "aspnetForm",
        ".aspx",
        "WebResource.axd",
        "ScriptResource.axd",
    )

    _HEADER_KEYS = (
        "x-aspnet-version",
        "x-aspnetmvc-version",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers first
        powered_by = headers.get("x-powered-by", "")
        if "ASP.NET" in powered_by:
            return {"type": "aspnet", "method": "header",
                    "signature": "x-powered-by: ASP.NET"}

        for key in self._HEADER_KEYS:
            if key in headers:
                return {"type": "aspnet", "method": "header",
                        "signature": key,
                        "version": headers[key]}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "aspnet", "method": "body",
                            "signature": sig}

        return None
