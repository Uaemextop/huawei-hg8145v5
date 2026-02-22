"""
Utility functions for the crawler.

Provides URL normalization, file path mapping, and other helper functions.
"""

import sys
from pathlib import Path

# Import utility functions from the main crawler.py
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crawler import (
    normalise_url,
    url_key,
    url_to_local_path,
    save_file,
    content_hash,
    smart_local_path,
)

__all__ = [
    "normalise_url",
    "url_key",
    "url_to_local_path",
    "save_file",
    "content_hash",
    "smart_local_path",
]
