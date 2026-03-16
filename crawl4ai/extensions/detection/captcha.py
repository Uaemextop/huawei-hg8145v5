"""
CAPTCHA detection – reCAPTCHA, hCAPTCHA, Cloudflare Turnstile, FunCaptcha,
GeeTest, and generic "verify you are a human" challenge pages.

This module focuses specifically on CAPTCHA challenges that may be embedded
in otherwise normal pages (as opposed to the full-page WAF blocks detected
by :mod:`waf`).
"""

from __future__ import annotations

from .base import BaseDetector

__all__ = ["CaptchaDetector"]

_CAPTCHA_SIGNATURES = (
    "g-recaptcha",
    "recaptcha/api.js",
    "recaptcha/enterprise.js",
    "grecaptcha.execute",
    "h-captcha",
    "hcaptcha.com/1/api.js",
    "cf-turnstile",
    "challenges.cloudflare.com/turnstile",
    "funcaptcha",
    "arkoselabs.com",
    "geetest",
    "geetest_challenge",
    "please verify you are a human",
    "verificar que eres humano",
    "complete the security check",
    "prove you are not a robot",
    "i'm not a robot",
)


class CaptchaDetector(BaseDetector):
    """Detect embedded CAPTCHA challenges (reCAPTCHA, hCAPTCHA, Turnstile, etc.)."""

    name = "captcha"

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
        for sig in _CAPTCHA_SIGNATURES:
            if sig.lower() in body_lower:
                return {"type": "captcha", "signature": sig}
        return None
