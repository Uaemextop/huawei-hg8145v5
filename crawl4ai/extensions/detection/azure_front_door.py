"""
Azure Front Door detection.

Identifies Azure Front Door by inspecting ``x-azure-ref`` and
``x-fd-healthprobe`` headers.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["AzureFrontDoorDetector"]


class AzureFrontDoorDetector(BaseDetector):
    """Detect Azure Front Door CDN."""

    name = "azure_front_door"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if headers.get("x-azure-ref"):
            return {"type": "azure_front_door", "method": "header",
                    "signature": "x-azure-ref"}

        if headers.get("x-fd-healthprobe"):
            return {"type": "azure_front_door", "method": "header",
                    "signature": "x-fd-healthprobe"}

        return None
