"""
Nginx server detection.

Identifies Nginx web servers by inspecting the ``server`` response header
for ``nginx``. Extracts the version number when present.
"""

from __future__ import annotations

import re

from .base import BaseDetector

__all__ = ["NginxDetector"]

_VERSION_RE = re.compile(r"nginx[/ ]*(\d[\d.]*)", re.IGNORECASE)


class NginxDetector(BaseDetector):
    """Detect Nginx web servers."""

    name = "nginx"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        server = headers.get("server", "")
        if "nginx" in server.lower():
            result: dict = {"type": "nginx", "method": "header",
                            "signature": "server"}
            match = _VERSION_RE.search(server)
            if match:
                result["version"] = match.group(1)
            return result

        return None
