"""
AWS CloudFront CDN detection.

Identifies CloudFront-served responses by inspecting ``x-amz-cf-id``,
``x-amz-cf-pop``, ``x-cache``, ``via``, and ``server`` headers.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["CloudFrontDetector"]


class CloudFrontDetector(BaseDetector):
    """Detect AWS CloudFront CDN."""

    name = "cloudfront"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if headers.get("x-amz-cf-id"):
            return {"type": "cloudfront", "method": "header",
                    "signature": "x-amz-cf-id"}

        if headers.get("x-amz-cf-pop"):
            return {"type": "cloudfront", "method": "header",
                    "signature": "x-amz-cf-pop"}

        x_cache = headers.get("x-cache", "").lower()
        if "cloudfront" in x_cache:
            return {"type": "cloudfront", "method": "header",
                    "signature": "x-cache"}

        via = headers.get("via", "").lower()
        if "cloudfront" in via:
            return {"type": "cloudfront", "method": "header",
                    "signature": "via"}

        server = headers.get("server", "").lower()
        if server == "cloudfront":
            return {"type": "cloudfront", "method": "header",
                    "signature": "server"}

        return None
