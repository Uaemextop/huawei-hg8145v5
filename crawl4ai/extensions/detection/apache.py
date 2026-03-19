"""
Apache HTTP Server detection.

Identifies Apache web servers by inspecting the ``server`` response header
for ``Apache``. Also checks for ``X-Powered-By: PHP`` which commonly
accompanies Apache deployments. Extracts the version number when present.
"""

from __future__ import annotations

import re

from .base import BaseDetector

__all__ = ["ApacheDetector"]

_VERSION_RE = re.compile(r"Apache[/ ]*(\d[\d.]*)", re.IGNORECASE)


class ApacheDetector(BaseDetector):
    """Detect Apache HTTP servers."""

    name = "apache"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        server = headers.get("server", "")
        if "Apache" in server:
            result: dict = {"type": "apache", "method": "header",
                            "signature": "server"}
            match = _VERSION_RE.search(server)
            if match:
                result["version"] = match.group(1)
            return result

        # X-Powered-By: PHP is a common companion for Apache
        powered_by = headers.get("x-powered-by", "")
        if "PHP" in powered_by:
            return {"type": "apache", "method": "header",
                    "signature": "x-powered-by: PHP"}

        return None
