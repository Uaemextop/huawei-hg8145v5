"""Core crawler logic – BFS crawler and file storage."""

from web_crawler.core.crawler import Crawler
from web_crawler.core.storage import save_file, content_hash, smart_local_path

__all__ = ["Crawler", "save_file", "content_hash", "smart_local_path"]
