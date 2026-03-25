"""URL normalisation and deduplication.

Delegates to :mod:`crawl4ai.extensions.url_utils`.
"""

from crawl4ai.extensions.url_utils import (  # noqa: F401
    normalise_url,
    url_key,
    url_to_local_path,
)

__all__ = ["normalise_url", "url_key", "url_to_local_path"]
