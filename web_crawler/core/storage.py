"""File I/O, content hashing, and local path mapping.

Delegates to :mod:`crawl4ai.extensions.storage`.
"""

from crawl4ai.extensions.storage import (  # noqa: F401
    save_file,
    stream_to_file,
    content_hash,
    file_content_hash,
    smart_local_path,
)

__all__ = [
    "save_file",
    "stream_to_file",
    "content_hash",
    "file_content_hash",
    "smart_local_path",
]
