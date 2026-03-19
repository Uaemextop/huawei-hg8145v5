"""
Shopify detection.

Identifies Shopify-powered storefronts by checking for ``x-shopify-stage``,
``x-shopid``, and ``x-sorting-hat-shopid`` response headers, as well as
``cdn.shopify.com``, ``Shopify.theme``, and ``shopify-section`` body
signatures.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["ShopifyDetector"]


class ShopifyDetector(BaseDetector):
    """Detect Shopify-powered storefronts."""

    name = "shopify"

    _SIGNATURES = (
        "cdn.shopify.com",
        "Shopify.theme",
        "shopify-section",
        "myshopify.com",
        "/shopify_",
        "shopify.com/s/",
    )

    _HEADER_KEYS = (
        "x-shopify-stage",
        "x-shopid",
        "x-sorting-hat-shopid",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers first (cheapest)
        for key in self._HEADER_KEYS:
            if key in headers:
                return {"type": "shopify", "method": "header",
                        "signature": key}

        # Check body signatures
        if body:
            for sig in self._SIGNATURES:
                if sig in body:
                    return {"type": "shopify", "method": "body",
                            "signature": sig}

        return None
