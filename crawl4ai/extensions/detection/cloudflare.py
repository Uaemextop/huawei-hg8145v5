"""
Cloudflare Managed Challenge / Turnstile detection.

Identifies Cloudflare-protected pages by inspecting response headers
(``cf-mitigated: challenge``) and body signatures (``_cf_chl_opt``,
``challenges.cloudflare.com``, etc.).
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["CloudflareDetector"]


class CloudflareDetector(BaseDetector):
    """Detect Cloudflare Managed Challenge (JS challenge / turnstile)."""

    name = "cloudflare"

    _CF_SIGNATURES = (
        "cf-mitigated",
        "cf_chl_opt",
        "challenges.cloudflare.com",
        "cf-browser-verification",
        "cf-spinner-please-wait",
        "Checking your browser",
        "Enable JavaScript and cookies to continue",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        # Check headers first (cheapest)
        if headers.get("cf-mitigated") == "challenge":
            return {"type": "cloudflare", "method": "header"}
        server = headers.get("server", "").lower()
        if "cloudflare" in server and status_code == 403:
            body_lower = body.lower() if body else ""
            for sig in self._CF_SIGNATURES:
                if sig.lower() in body_lower:
                    return {"type": "cloudflare", "method": "body", "signature": sig}
        return None
