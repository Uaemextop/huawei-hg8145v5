"""
Plugin architecture for the web crawler.

Provides a base class for all plugins and an auto-loading registry
that discovers and instantiates plugins without modifying the core.
"""

from web_crawler.plugins.base import CrawlerPlugin
from web_crawler.plugins.registry import PluginRegistry

__all__ = ["CrawlerPlugin", "PluginRegistry"]
