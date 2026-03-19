"""
Magento / Adobe Commerce detection.

Identifies Magento-powered websites by checking for ``X-Magento-*`` response
headers and body signatures such as ``Mage.``, ``/skin/frontend/``,
``/media/catalog/``, and ``Magento_``.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["MagentoDetector"]


class MagentoDetector(BaseDetector):
    """Detect Magento / Adobe Commerce websites."""

    name = "magento"

    _SIGNATURES = (
        "Mage.",
        "/skin/frontend/",
        "/media/catalog/",
        "mage/cookies",
        "Magento_",
        "varien/js",
        "magento.com",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check for X-Magento-* headers
        for key in headers:
            if key.lower().startswith("x-magento-"):
                return {"type": "magento", "method": "header",
                        "signature": key}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "magento", "method": "body",
                            "signature": sig}

        return None
