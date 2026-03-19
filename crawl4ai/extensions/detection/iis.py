"""
Microsoft IIS detection.

Identifies Microsoft IIS web servers by inspecting the ``server`` response
header for ``Microsoft-IIS``, as well as ``X-Powered-By: ASP.NET`` and
``X-AspNet-Version`` headers. Extracts the IIS version when present.
"""

from __future__ import annotations

import re

from .base import BaseDetector

__all__ = ["IISDetector"]

_VERSION_RE = re.compile(r"Microsoft-IIS[/ ]*(\d[\d.]*)", re.IGNORECASE)


class IISDetector(BaseDetector):
    """Detect Microsoft IIS web servers."""

    name = "iis"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        server = headers.get("server", "")
        if "Microsoft-IIS" in server:
            result: dict = {"type": "iis", "method": "header",
                            "signature": "server"}
            match = _VERSION_RE.search(server)
            if match:
                result["version"] = match.group(1)
            return result

        powered_by = headers.get("x-powered-by", "")
        if "ASP.NET" in powered_by:
            return {"type": "iis", "method": "header",
                    "signature": "x-powered-by: ASP.NET"}

        if "x-aspnet-version" in headers:
            return {"type": "iis", "method": "header",
                    "signature": "x-aspnet-version",
                    "version": headers["x-aspnet-version"]}

        return None
