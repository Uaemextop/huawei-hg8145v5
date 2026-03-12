"""
Scheduler and worker pool for concurrent crawling.

Provides a :class:`CrawlScheduler` that manages a URL queue and
dispatches work items to a pool of concurrent workers.
"""

from web_crawler.scheduler.worker_pool import CrawlScheduler

__all__ = ["CrawlScheduler"]
