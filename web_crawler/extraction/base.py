"""Base class for all link extractors.

Delegates to :mod:`crawl4ai.extensions.extraction`.
"""

from crawl4ai.extensions.extraction import BaseExtractor  # noqa: F401

__all__ = ["BaseExtractor"]
