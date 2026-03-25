"""WordPress CMS detection.

Delegates to :mod:`crawl4ai.extensions.detection.wordpress`.
"""

from crawl4ai.extensions.detection.wordpress import WordPressDetector  # noqa: F401

__all__ = ["WordPressDetector"]
