"""Built-in pipeline stages for the default crawling workflow."""

from __future__ import annotations

import logging
from typing import Any

from web_crawler.pipeline.stages import PipelineStage

log = logging.getLogger(__name__)


class URLDiscoveryStage(PipelineStage):
    """Discover and normalise URLs from page content."""

    @property
    def name(self) -> str:
        return "url_discovery"

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        from web_crawler.extraction.links import extract_links

        content = context.get("content", "")
        content_type = context.get("content_type", "")
        url = context.get("url", "")
        base = context.get("base_url", "")

        links = extract_links(content, content_type, url, base)
        context.setdefault("discovered_urls", set()).update(links)
        return context


class TechDetectionStage(PipelineStage):
    """Run technology detection plugins."""

    @property
    def name(self) -> str:
        return "tech_detection"

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        registry = context.get("plugin_registry")
        if registry is None:
            return context

        detectors = registry.get_plugins("detector")
        all_techs: list[dict[str, str]] = []
        all_protections: list[str] = []

        for det in detectors:
            result = det.run(context)
            all_techs.extend(result.get("technologies", []))
            all_protections.extend(result.get("protections", []))

        context["technologies"] = all_techs
        context["protections"] = all_protections
        return context


class StrategySelectionStage(PipelineStage):
    """Select crawling strategy based on detected technologies."""

    @property
    def name(self) -> str:
        return "strategy_selection"

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        registry = context.get("plugin_registry")
        if registry is None:
            return context

        strategies = registry.get_plugins("strategy")
        extra_urls: list[tuple[str, bool]] = []

        for strat in strategies:
            result = strat.run(context)
            extra_urls.extend(result.get("urls", []))

        context["strategy_urls"] = extra_urls
        return context


class DataProcessingStage(PipelineStage):
    """Run registered data processors on the response."""

    @property
    def name(self) -> str:
        return "data_processing"

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        registry = context.get("plugin_registry")
        if registry is None:
            return context

        processors = registry.get_plugins("processor")
        for proc in processors:
            result = proc.run(context)
            context.update(result or {})

        return context
