"""Extract Google Drive and cloud storage links from pages.

Delegates to :mod:`crawl4ai.extensions.extraction`.
"""

from crawl4ai.extensions.extraction import (  # noqa: F401
    GoogleDriveExtractor,
    extract_cloud_links,
)

__all__ = ["GoogleDriveExtractor", "extract_cloud_links"]
