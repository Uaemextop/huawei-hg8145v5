"""Soft-404 page detection.

Delegates to :mod:`crawl4ai.extensions.detection.soft404`.
"""

from crawl4ai.extensions.detection.soft404 import Soft404Detector  # noqa: F401

__all__ = ["Soft404Detector"]
