"""Configuration classes for the web crawler.

Inspired by crawl4ai's async_configs.py, using stdlib dataclasses to keep
dependencies minimal while providing a structured, composable config system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet

__all__ = [
    "CrawlerConfig",
    "SessionConfig",
    "ExtractionConfig",
    "StorageConfig",
    "BrowserConfig",
    "CrawlerRunConfig",
]


@dataclass
class CrawlerConfig:
    """Top-level crawler configuration.

    Combines the most common knobs needed to kick off a crawl into a single
    flat object, suitable for CLI or simple scripting use-cases.
    """

    start_url: str = ""
    output_dir: str = "downloaded_site"
    max_depth: int = 0
    delay: float = 0.25
    concurrency: int = 8
    verify_ssl: bool = True
    respect_robots: bool = True
    force: bool = False
    debug: bool = False
    mode: str = "local"  # "local", "browser", "combined"


@dataclass
class SessionConfig:
    """HTTP session / transport-level settings."""

    verify_ssl: bool = True
    cf_clearance: str = ""
    user_agent: str = ""  # empty string means rotate user-agents
    timeout: int = 30
    max_retries: int = 3


@dataclass
class ExtractionConfig:
    """Controls *what* content gets extracted from crawled pages."""

    download_extensions: FrozenSet[str] = field(default_factory=frozenset)
    skip_download_exts: FrozenSet[str] = field(default_factory=frozenset)
    skip_media_files: bool = False
    allow_external: bool = True
    skip_captcha_check: bool = False


@dataclass
class StorageConfig:
    """Controls where and how crawled artifacts are persisted."""

    output_dir: str = "downloaded_site"
    git_push_every: int = 0
    upload_extensions: FrozenSet[str] = field(default_factory=frozenset)


@dataclass
class BrowserConfig:
    """Browser-based crawling settings (for crawl4ai / Playwright integration).

    Mirrors a subset of crawl4ai's BrowserConfig so we can hand these values
    through when delegating to a browser-based crawler.
    """

    headless: bool = True
    browser_type: str = "chromium"  # "chromium", "firefox", "webkit"
    viewport_width: int = 1920
    viewport_height: int = 1080


@dataclass
class CrawlerRunConfig:
    """Combined run-time configuration, analogous to crawl4ai's CrawlerRunConfig.

    Bundles all sub-configs needed for a single crawl execution. Can be built
    manually or derived from a :class:`CrawlerConfig` via the
    :meth:`from_crawler_config` class method.
    """

    session: SessionConfig = field(default_factory=SessionConfig)
    extraction: ExtractionConfig = field(default_factory=ExtractionConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)

    @classmethod
    def from_crawler_config(cls, config: CrawlerConfig) -> CrawlerRunConfig:
        """Create a :class:`CrawlerRunConfig` from a flat :class:`CrawlerConfig`.

        Maps the high-level, user-facing knobs onto the more granular
        sub-config objects used internally.
        """
        return cls(
            session=SessionConfig(
                verify_ssl=config.verify_ssl,
            ),
            extraction=ExtractionConfig(),
            storage=StorageConfig(
                output_dir=config.output_dir,
            ),
            browser=BrowserConfig(),
        )
