"""
Huawei HG8145V5 Router Web Crawler
====================================
A modular Python package for crawling and archiving Huawei router admin interfaces.

This package provides functionality to:
- Authenticate with the router using various login methods
- Recursively discover and download all accessible pages and resources
- Extract links from HTML, JavaScript, CSS, and JSON content
- Maintain sessions with automatic re-authentication
- Resume interrupted crawls

Modules:
- auth: Authentication and session management
- network: HTTP client configuration and request handling
- parser: Content parsing and link extraction
- crawler: Core BFS crawling logic
- cli: Command-line interface
"""

__version__ = "2.0.0"
__author__ = "Huawei HG8145V5 Crawler Project"

from huawei_crawler.crawler.core import Crawler

__all__ = ["Crawler"]
