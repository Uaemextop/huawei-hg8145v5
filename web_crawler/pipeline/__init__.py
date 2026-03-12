"""
Modular processing pipeline for crawled pages.

Each pipeline stage is a callable that receives and returns a
:class:`PipelineContext` dict.  Stages are chained in order and any
stage may short-circuit the pipeline by setting ``context["skip"] = True``.
"""

from web_crawler.pipeline.stages import Pipeline, PipelineStage

__all__ = ["Pipeline", "PipelineStage"]
