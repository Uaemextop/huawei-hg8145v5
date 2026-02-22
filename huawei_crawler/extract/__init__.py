"""
huawei_crawler.extract
=======================
Sub-package for extracting resource URLs from downloaded content.

Public API
----------
    from huawei_crawler.extract import extract_links
"""

from .core import extract_links

__all__ = ["extract_links"]
