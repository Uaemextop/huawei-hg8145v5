"""Base class for all page technology detectors.

Delegates to :mod:`crawl4ai.extensions.detection.base` — the canonical
implementation shared by both ``web_crawler`` and ``crawl4ai``.
"""

from crawl4ai.extensions.detection.base import BaseDetector  # noqa: F401

__all__ = ["BaseDetector"]
