"""Utility subpackage for the Huawei HG8145V5 crawler."""

from .url import normalise_url, url_key, url_to_local_path, smart_local_path
from .files import save_file, content_hash

__all__ = [
    "normalise_url",
    "url_key",
    "url_to_local_path",
    "smart_local_path",
    "save_file",
    "content_hash",
]
