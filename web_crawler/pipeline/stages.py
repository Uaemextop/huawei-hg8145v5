"""Pipeline stage definitions and runner."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

log = logging.getLogger(__name__)


class PipelineStage(ABC):
    """Base class for a processing pipeline stage."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable stage name for logging."""

    @abstractmethod
    def process(self, context: dict[str, Any]) -> dict[str, Any]:
        """Process *context* and return the (possibly modified) context.

        Set ``context["skip"] = True`` to short-circuit remaining stages.
        """


class Pipeline:
    """Ordered chain of :class:`PipelineStage` instances."""

    def __init__(self, stages: list[PipelineStage] | None = None) -> None:
        self._stages: list[PipelineStage] = list(stages or [])

    def add_stage(self, stage: PipelineStage) -> "Pipeline":
        """Append a stage and return self for chaining."""
        self._stages.append(stage)
        return self

    def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Run all stages sequentially.  Stops early when *skip* is set."""
        for stage in self._stages:
            if context.get("skip"):
                log.debug("Pipeline short-circuited before %s", stage.name)
                break
            try:
                context = stage.process(context)
            except Exception:
                log.warning("Pipeline stage %s failed", stage.name, exc_info=True)
                context.setdefault("errors", []).append(stage.name)
        return context

    @property
    def stages(self) -> list[PipelineStage]:
        return list(self._stages)
