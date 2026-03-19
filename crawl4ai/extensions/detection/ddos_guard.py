"""
DDoS-Guard detection.

Identifies DDoS-Guard protection by inspecting the ``server`` header
and body references to DDoS-Guard domains.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["DDoSGuardDetector"]


class DDoSGuardDetector(BaseDetector):
    """Detect DDoS-Guard protection."""

    name = "ddos_guard"

    _BODY_SIGNATURES = (
        "ddos-guard.net",
        "DDoS-Guard",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        server = headers.get("server", "").lower()
        if "ddos-guard" in server:
            return {"type": "ddos_guard", "method": "header",
                    "signature": "server"}

        if body:
            for sig in self._BODY_SIGNATURES:
                if sig in body:
                    return {"type": "ddos_guard", "method": "body",
                            "signature": sig}

        return None
