"""JSON path extraction.

Delegates to :mod:`crawl4ai.extensions.extraction`.
"""

from crawl4ai.extensions.extraction import extract_json_paths  # noqa: F401

__all__ = ["extract_json_paths"]
