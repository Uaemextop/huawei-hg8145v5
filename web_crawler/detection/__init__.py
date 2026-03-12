"""
Automatic detection engine.

Aggregates results from all detection plugins (technology, WAF,
framework, behaviour) to automatically determine the best crawling
strategy for a given page.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from web_crawler.plugins.registry import PluginRegistry
from web_crawler.utils.log import log


@dataclass
class DetectionResult:
    """Container for aggregated detection results."""

    url: str
    technologies: list[str] = field(default_factory=list)
    protections: list[str] = field(default_factory=list)
    has_captcha: bool = False
    has_waf: bool = False
    is_dynamic: bool = False
    suggested_strategy: str = "default"

    @property
    def summary(self) -> str:
        parts = []
        if self.technologies:
            parts.append(f"tech=[{', '.join(self.technologies)}]")
        if self.protections:
            parts.append(f"prot=[{', '.join(self.protections)}]")
        if self.has_captcha:
            parts.append("captcha=yes")
        if self.has_waf:
            parts.append("waf=yes")
        if self.is_dynamic:
            parts.append("dynamic=yes")
        parts.append(f"strategy={self.suggested_strategy}")
        return " | ".join(parts) if parts else "no detections"


class DetectionEngine:
    """Runs all registered detection plugins and produces a
    :class:`DetectionResult` for a page."""

    # WAF identifiers that count as "WAF present"
    _WAF_NAMES = frozenset({
        "cloudflare", "sucuri", "wordfence", "imperva", "akamai",
        "shield_security", "siteground", "aws_waf", "mod_security",
    })

    # Identifiers that indicate CAPTCHA presence
    _CAPTCHA_NAMES = frozenset({
        "captcha", "recaptcha", "hcaptcha", "turnstile",
    })

    # Technologies that suggest dynamic (JS-rendered) content
    _DYNAMIC_TECHS = frozenset({
        "react", "angular", "vue", "nextjs", "nuxtjs",
    })

    def __init__(self, registry: PluginRegistry) -> None:
        self._registry = registry

    def analyse(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> DetectionResult:
        """Run all detection plugins and return an aggregated result."""
        techs = self._registry.detect_technologies(url, headers, body)
        protections = self._registry.detect_protections(url, headers, body)

        result = DetectionResult(
            url=url,
            technologies=techs,
            protections=protections,
        )

        # Classify protections
        prot_set = {p.lower() for p in protections}
        result.has_waf = bool(prot_set & self._WAF_NAMES)
        result.has_captcha = bool(prot_set & self._CAPTCHA_NAMES)

        # Classify dynamic content
        tech_set = {t.lower() for t in techs}
        result.is_dynamic = bool(tech_set & self._DYNAMIC_TECHS)

        # Suggest strategy
        if result.has_captcha:
            result.suggested_strategy = "browser"
        elif result.has_waf:
            result.suggested_strategy = "stealth"
        elif result.is_dynamic:
            result.suggested_strategy = "headless"
        else:
            result.suggested_strategy = "default"

        log.debug("[DETECT] %s → %s", url, result.summary)
        return result
