"""Generic WAF / CAPTCHA signature detection."""

from web_crawler.detection.base import BaseDetector
from web_crawler.config.settings import WAF_SIGNATURES


class WAFDetector(BaseDetector):
    """Detect generic WAF or CAPTCHA protection on a page."""

    name = "waf"

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if not body:
            return None
        body_lower = body.lower()
        for category, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body_lower:
                    return {
                        "type": "waf",
                        "category": category,
                        "signature": sig,
                    }
        return None
