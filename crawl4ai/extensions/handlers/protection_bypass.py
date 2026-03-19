"""Protection / WAF bypass handler – recommends stealth strategies."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import BaseHandler, HandlerResult

if TYPE_CHECKING:
    import requests

log = logging.getLogger(__name__)

__all__ = ["ProtectionBypassHandler"]

_PROTECTION_TYPES = frozenset({
    "cloudflare", "siteground", "waf", "captcha",
    "akamai", "imperva", "sucuri", "wordfence", "modsecurity",
    "aws_waf", "ddos_guard", "azure_front_door",
})


class ProtectionBypassHandler(BaseHandler):
    """Recommend crawling strategies to bypass WAF / protection layers.

    Supports Cloudflare, Akamai, Imperva (Incapsula), Sucuri,
    Wordfence, ModSecurity, generic WAF, CAPTCHA, and SiteGround.
    """

    name = "protection_bypass"

    def can_handle(self, detection: dict) -> bool:
        """Return True for any WAF or protection detection."""
        return detection.get("type", "") in _PROTECTION_TYPES

    def apply(
        self,
        url: str,
        session: "requests.Session",
        response: "requests.Response | None",
        detection: dict,
    ) -> HandlerResult:
        """Return recommended configuration for bypassing protections."""
        ptype = detection.get("type", "")
        actions: list[str] = []
        config: dict = {}
        retry_with: dict = {}

        try:
            if ptype == "cloudflare":
                config.update({
                    "use_browser": True,
                    "tls_fingerprint": "chrome",
                    "rate_limit_delay": 2,
                })
                actions.append(
                    "Cloudflare detected – recommending browser-based crawling "
                    "with TLS fingerprinting and 2 s rate limit"
                )

            elif ptype == "akamai":
                config.update({
                    "rate_limit_delay": 1,
                    "max_concurrent": 1,
                    "rotate_user_agent": True,
                })
                actions.append(
                    "Akamai detected – conservative rate limit (1 req/s), "
                    "aggressive UA rotation"
                )

            elif ptype == "imperva":
                config.update({
                    "use_browser": True,
                    "handle_cookies": True,
                    "rate_limit_delay": 2,
                })
                actions.append(
                    "Imperva/Incapsula detected – browser crawling with "
                    "cookie handling recommended"
                )

            elif ptype == "sucuri":
                config.update({
                    "clean_ip": True,
                    "rate_limit_delay": 1.5,
                })
                retry_with["headers"] = {
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                actions.append(
                    "Sucuri detected – adjusted headers, recommend clean IP"
                )

            elif ptype == "wordfence":
                config.update({
                    "rate_limit_delay": 3,
                    "max_concurrent": 1,
                    "avoid_scan_patterns": True,
                })
                actions.append(
                    "Wordfence detected – very conservative rate limit (3 s), "
                    "avoiding scanning patterns"
                )

            elif ptype == "modsecurity":
                config.update({
                    "sanitize_urls": True,
                    "avoid_sqli_patterns": True,
                    "avoid_xss_patterns": True,
                })
                actions.append(
                    "ModSecurity detected – avoiding common SQL/XSS patterns "
                    "in URLs"
                )

            elif ptype == "waf":
                config.update({
                    "use_browser": True,
                    "stealth_mode": True,
                    "browser_fingerprint": True,
                    "rate_limit_delay": 2,
                })
                actions.append(
                    "Generic WAF detected – stealth mode with browser "
                    "fingerprints recommended"
                )

            elif ptype == "captcha":
                config.update({
                    "use_browser": True,
                    "solve_captcha": True,
                })
                actions.append(
                    "CAPTCHA detected – browser-based solving recommended"
                )

            elif ptype == "siteground":
                config.update({
                    "use_browser": True,
                    "solve_pow": True,
                })
                actions.append(
                    "SiteGround PoW challenge detected – triggering PoW solver"
                )

            elif ptype == "aws_waf":
                config.update({
                    "rate_limit_delay": 2,
                    "rotate_user_agent": True,
                    "use_browser": True,
                })
                actions.append(
                    "AWS WAF detected – browser crawling with UA rotation "
                    "and 2 s rate limit"
                )

            elif ptype == "ddos_guard":
                config.update({
                    "use_browser": True,
                    "handle_cookies": True,
                    "rate_limit_delay": 2,
                })
                actions.append(
                    "DDoS-Guard detected – browser crawling with cookie "
                    "persistence recommended"
                )

            elif ptype == "azure_front_door":
                config.update({
                    "rate_limit_delay": 1.5,
                    "handle_cookies": True,
                })
                actions.append(
                    "Azure Front Door detected – moderate rate limit with "
                    "cookie handling"
                )

        except Exception:
            log.debug(
                "ProtectionBypassHandler error for %s", url, exc_info=True
            )
            actions.append(f"Error processing {ptype} detection")

        result = HandlerResult(
            handler=self.name,
            actions_taken=actions,
            extra_urls=[],
            extra_headers={},
            recommended_config=config,
        )
        if retry_with:
            result["retry_with"] = retry_with
        return result
