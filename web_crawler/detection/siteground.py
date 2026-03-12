"""SiteGround Security CAPTCHA detection."""

from web_crawler.detection.base import BaseDetector


class SiteGroundDetector(BaseDetector):
    """Detect SiteGround Security CAPTCHA (proof-of-work challenge)."""

    name = "siteground"

    _SG_SIGNATURES = (
        "sg-captcha-form",
        "sg_captcha_challenge",
        "<input name=\"sg-bypass-key\"",
    )

    def detect(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
    ) -> dict | None:
        if not body:
            return None
        for sig in self._SG_SIGNATURES:
            if sig in body:
                return {"type": "siteground", "signature": sig}
        return None
