"""
Crawling pipeline — modular processing stages.

Provides a :class:`CrawlingPipeline` that executes an ordered sequence
of :class:`PipelineStage` instances for every crawled URL.  Stages are
independently replaceable and new ones can be inserted without touching
the core crawler.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from web_crawler.utils.log import log


class PipelineStage(ABC):
    """A single processing stage within the crawling pipeline."""

    name: str = "stage"

    @abstractmethod
    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        """Process the pipeline *context* and return it (possibly modified).

        The *context* dict carries at least:
        * ``url`` – the URL being processed.
        * ``response`` – the :class:`requests.Response` object.
        * ``body`` – decoded body text (may be truncated for binary content).
        * ``headers`` – dict of response headers.
        * ``content_type`` – the normalised content-type string.
        * ``technologies`` – list of detected technology identifiers.
        * ``protections`` – list of detected WAF/protection identifiers.
        * ``links`` – set of discovered links.
        * ``skip`` – if ``True``, downstream stages should skip processing.
        """
        ...


# ──────────────────────────────────────────────────────────────────────
# Built-in stages
# ──────────────────────────────────────────────────────────────────────

class DiscoveryStage(PipelineStage):
    """Initial stage — validates the URL and prepares the context."""

    name = "discovery"

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        context.setdefault("technologies", [])
        context.setdefault("protections", [])
        context.setdefault("links", set())
        context.setdefault("skip", False)
        return context


class TechnologyDetectionStage(PipelineStage):
    """Detects technologies using the plugin registry."""

    name = "tech_detection"

    def __init__(self, registry: Any) -> None:
        self._registry = registry

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        if context.get("skip"):
            return context
        techs = self._registry.detect_technologies(
            context["url"],
            context["headers"],
            context.get("body", ""),
        )
        context["technologies"] = techs
        if techs:
            log.debug("[PIPELINE] Technologies: %s", ", ".join(techs))
        return context


class ProtectionDetectionStage(PipelineStage):
    """Detects WAF / protection layers using the plugin registry."""

    name = "protection_detection"

    def __init__(self, registry: Any) -> None:
        self._registry = registry

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        if context.get("skip"):
            return context
        prots = self._registry.detect_protections(
            context["url"],
            context["headers"],
            context.get("body", ""),
        )
        context["protections"] = prots
        if prots:
            log.debug("[PIPELINE] Protections: %s", ", ".join(prots))
        return context


class LinkExtractionStage(PipelineStage):
    """Collects links from the page content via the plugin registry."""

    name = "link_extraction"

    def __init__(self, registry: Any) -> None:
        self._registry = registry

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        if context.get("skip"):
            return context
        extra = self._registry.collect_extra_links(
            context["url"],
            context.get("body", ""),
            context.get("content_type", ""),
        )
        context["links"] = context.get("links", set()) | extra
        return context


class ContentProcessingStage(PipelineStage):
    """Processes downloaded content — placeholder for custom logic
    (e.g. structured data extraction, indexing)."""

    name = "content_processing"

    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        return context


# ──────────────────────────────────────────────────────────────────────
# Pipeline orchestrator
# ──────────────────────────────────────────────────────────────────────

class CrawlingPipeline:
    """Orchestrates an ordered sequence of :class:`PipelineStage` instances."""

    def __init__(self, stages: list[PipelineStage] | None = None) -> None:
        self._stages: list[PipelineStage] = list(stages or [])

    def add_stage(self, stage: PipelineStage) -> None:
        self._stages.append(stage)

    def insert_stage(self, index: int, stage: PipelineStage) -> None:
        self._stages.insert(index, stage)

    @property
    def stages(self) -> list[PipelineStage]:
        return list(self._stages)

    def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Run every stage in order, passing the context through."""
        for stage in self._stages:
            try:
                context = stage.process(context)
            except Exception as exc:  # noqa: BLE001
                log.debug("[PIPELINE] Stage '%s' error: %s", stage.name, exc)
        return context
