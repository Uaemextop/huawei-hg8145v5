"""
Modular page-analysis pipeline.

Each page fetched by the crawler is processed through a sequence of
independent stages:

1. **HTTP analysis**      – status, headers, content-type
2. **Technology detection** – identify frameworks, CMS, libraries
3. **Protection detection** – WAFs, CAPTCHAs, anti-bot systems
4. **Strategy selection**  – choose parser/extractor based on tech stack
5. **Link extraction**     – extract and normalise discovered URLs
6. **Content analysis**    – external links, interesting patterns
7. **Endpoint discovery**  – hidden routes, APIs, dynamic links

Each stage produces a result dict that is merged into the overall
:class:`PageResult`.  The pipeline delegates to registered plugins
for extensibility.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from web_crawler.plugins.base import PluginRegistry

log = logging.getLogger("web-crawler")


@dataclass
class PageResult:
    """Aggregated result of running the pipeline on a single page."""

    url: str
    status_code: int = 0
    content_type: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[dict[str, str]] = field(default_factory=list)
    protections: list[str] = field(default_factory=list)
    discovered_links: set[str] = field(default_factory=set)
    external_links: list[dict[str, str]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def has_protection(self) -> bool:
        return bool(self.protections)

    @property
    def is_wordpress(self) -> bool:
        return any(t.get("name") == "WordPress" for t in self.technologies)


class Pipeline:
    """Modular page-analysis pipeline.

    Runs registered plugins through the detection → extraction →
    analysis stages and collects results into a :class:`PageResult`.
    """

    def process(
        self,
        *,
        url: str,
        status_code: int,
        headers: dict[str, str],
        body: str,
        base: str,
        cookies: dict[str, str] | None = None,
    ) -> PageResult:
        """Run all pipeline stages and return aggregated results."""
        result = PageResult(
            url=url,
            status_code=status_code,
            content_type=headers.get("Content-Type", ""),
            headers=dict(headers),
        )

        # Stage 1–2: Technology detection
        for plugin in PluginRegistry.by_kind("tech_detector"):
            try:
                det = plugin.detect(
                    url=url, headers=headers, body=body, cookies=cookies,
                )
                if det:
                    result.technologies.extend(det.get("technologies", []))
                    result.extra.update(
                        {k: v for k, v in det.items() if k != "technologies"}
                    )
            except Exception as exc:
                log.debug("Plugin %s error: %s", plugin.name, exc)

        # Stage 3: Protection / WAF detection
        for plugin in PluginRegistry.by_kind("waf_detector"):
            try:
                det = plugin.detect(url=url, headers=headers, body=body)
                if det:
                    result.protections.extend(det.get("protections", []))
            except Exception as exc:
                log.debug("Plugin %s error: %s", plugin.name, exc)

        # Stage 4–5: Link extraction + endpoint discovery
        for kind in ("link_extractor", "endpoint_discovery"):
            for plugin in PluginRegistry.by_kind(kind):
                try:
                    links = plugin.extract_links(
                        url=url, body=body, base=base,
                    )
                    result.discovered_links.update(links)
                except Exception as exc:
                    log.debug("Plugin %s error: %s", plugin.name, exc)

        # Stage 6: Content analysis
        for plugin in PluginRegistry.by_kind("content_analyzer"):
            try:
                analysis = plugin.analyze(
                    url=url, headers=headers, body=body, base=base,
                )
                if analysis:
                    result.external_links.extend(
                        analysis.get("external_links", [])
                    )
                    result.extra.update(
                        {k: v for k, v in analysis.items()
                         if k != "external_links"}
                    )
            except Exception as exc:
                log.debug("Plugin %s error: %s", plugin.name, exc)

        # De-duplicate technologies by name (preserving insertion order)
        unique_tech: dict[str, dict[str, str]] = {}
        for t in result.technologies:
            name = t.get("name", "")
            if name and name not in unique_tech:
                unique_tech[name] = t
        result.technologies = list(unique_tech.values())

        return result
