"""
AWS WAF detection.

Identifies AWS WAF-blocked responses by inspecting ``x-amzn-requestid``,
``x-amzn-trace-id`` headers (especially with 403 status), and body
signatures of AWS WAF block pages.
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["AWSWAFDetector"]


class AWSWAFDetector(BaseDetector):
    """Detect AWS WAF protection."""

    name = "aws_waf"

    _BLOCK_PAGE_SIGNATURES = (
        "aws waf",
        "request blocked",
        "automated access",
        "#waf-container",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        has_amzn_request = bool(headers.get("x-amzn-requestid"))
        has_amzn_trace = bool(headers.get("x-amzn-trace-id"))

        # 403 + AWS headers is a strong signal for WAF block
        if status_code == 403 and (has_amzn_request or has_amzn_trace):
            return {"type": "aws_waf", "method": "header",
                    "signature": "403+amzn-header"}

        # Check body for AWS WAF block page signatures
        if body:
            body_lower = body.lower()
            for sig in self._BLOCK_PAGE_SIGNATURES:
                if sig in body_lower:
                    return {"type": "aws_waf", "method": "body",
                            "signature": sig}

        return None
