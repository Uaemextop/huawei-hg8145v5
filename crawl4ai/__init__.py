# __init__.py
import warnings

# ---------------------------------------------------------------------------
# Core crawl4ai imports are wrapped in try/except so that the *extensions*
# sub-package (detection, bypass, downloader, etc.) can be imported even when
# the heavy crawl4ai dependencies (playwright, lark, etc.) are not installed.
# ---------------------------------------------------------------------------
try:
    from .async_webcrawler import AsyncWebCrawler, CacheMode
    # MODIFIED: Add SeedingConfig and VirtualScrollConfig here
    from .async_configs import BrowserConfig, CrawlerRunConfig, HTTPCrawlerConfig, LLMConfig, ProxyConfig, GeolocationConfig, SeedingConfig, VirtualScrollConfig, LinkPreviewConfig, MatchMode

    from .content_scraping_strategy import (
    ContentScrapingStrategy,
    LXMLWebScrapingStrategy,
    WebScrapingStrategy,  # Backward compatibility alias
    )
    from .async_logger import (
    AsyncLoggerBase,
    AsyncLogger,
    )
    from .proxy_strategy import (
    ProxyRotationStrategy,
    RoundRobinProxyStrategy,
    )
    from .extraction_strategy import (
    ExtractionStrategy,
    LLMExtractionStrategy,
    CosineStrategy,
    JsonCssExtractionStrategy,
    JsonXPathExtractionStrategy,
    JsonLxmlExtractionStrategy,
    RegexExtractionStrategy
    )
    from .chunking_strategy import ChunkingStrategy, RegexChunking
    from .markdown_generation_strategy import DefaultMarkdownGenerator
    from .table_extraction import (
    TableExtractionStrategy,
    DefaultTableExtraction,
    NoTableExtraction,
    LLMTableExtraction,
    )
    from .content_filter_strategy import (
    PruningContentFilter,
    BM25ContentFilter,
    LLMContentFilter,
    RelevantContentFilter,
    )
    from .models import CrawlResult, MarkdownGenerationResult, DisplayMode
    from .components.crawler_monitor import CrawlerMonitor
    from .link_preview import LinkPreview
    from .async_dispatcher import (
    MemoryAdaptiveDispatcher,
    SemaphoreDispatcher,
    RateLimiter,
    BaseDispatcher,
    )
    from .docker_client import Crawl4aiDockerClient
    from .hub import CrawlerHub
    from .browser_profiler import BrowserProfiler
    from .deep_crawling import (
    DeepCrawlStrategy,
    BFSDeepCrawlStrategy,
    FilterChain,
    URLPatternFilter,
    DomainFilter,
    ContentTypeFilter,
    URLFilter,
    FilterStats,
    SEOFilter,
    KeywordRelevanceScorer,
    URLScorer,
    CompositeScorer,
    DomainAuthorityScorer,
    FreshnessScorer,
    PathDepthScorer,
    BestFirstCrawlingStrategy,
    DFSDeepCrawlStrategy,
    DeepCrawlDecorator,
    ContentRelevanceFilter,
    ContentTypeScorer,
    )
    # NEW: Import AsyncUrlSeeder
    from .async_url_seeder import AsyncUrlSeeder
    # Adaptive Crawler
    from .adaptive_crawler import (
    AdaptiveCrawler,
    AdaptiveConfig,
    CrawlState,
    CrawlStrategy,
    StatisticalStrategy
    )

    # C4A Script Language Support
    from .script import (
    compile as c4a_compile,
    validate as c4a_validate,
    compile_file as c4a_compile_file,
    CompilationResult,
    ValidationResult,
    ErrorDetail
    )

    # Browser Adapters
    from .browser_adapter import (
    BrowserAdapter,
    PlaywrightAdapter,
    UndetectedAdapter
    )

    from .utils import (
        start_colab_display_server,
        setup_colab_environment,
        hooks_to_string
    )

    __all__ = [
        "AsyncLoggerBase",
        "AsyncLogger",
        "AsyncWebCrawler",
        "BrowserProfiler",
        "LLMConfig",
        "GeolocationConfig",
        # NEW: Add SeedingConfig and VirtualScrollConfig
        "SeedingConfig",
        "VirtualScrollConfig",
        # NEW: Add AsyncUrlSeeder
        "AsyncUrlSeeder",
        # Adaptive Crawler
        "AdaptiveCrawler",
        "AdaptiveConfig", 
        "CrawlState",
        "CrawlStrategy",
        "StatisticalStrategy",
        "DeepCrawlStrategy",
        "BFSDeepCrawlStrategy",
        "BestFirstCrawlingStrategy",
        "DFSDeepCrawlStrategy",
        "FilterChain",
        "URLPatternFilter",
        "ContentTypeFilter",
        "DomainFilter",
        "FilterStats",
        "URLFilter",
        "SEOFilter",
        "KeywordRelevanceScorer",
        "URLScorer",
        "CompositeScorer",
        "DomainAuthorityScorer",
        "FreshnessScorer",
        "PathDepthScorer",
        "DeepCrawlDecorator",
        "CrawlResult",
        "CrawlerHub",
        "CacheMode",
        "MatchMode",
        "ContentScrapingStrategy",
        "WebScrapingStrategy",
        "LXMLWebScrapingStrategy",
        "BrowserConfig",
        "CrawlerRunConfig",
        "HTTPCrawlerConfig",
        "ExtractionStrategy",
        "LLMExtractionStrategy",
        "CosineStrategy",
        "JsonCssExtractionStrategy",
        "JsonXPathExtractionStrategy",
        "JsonLxmlExtractionStrategy",
        "RegexExtractionStrategy",
        "ChunkingStrategy",
        "RegexChunking",
        "DefaultMarkdownGenerator",
        "TableExtractionStrategy",
        "DefaultTableExtraction",
        "NoTableExtraction",
        "RelevantContentFilter",
        "PruningContentFilter",
        "BM25ContentFilter",
        "LLMContentFilter",
        "BaseDispatcher",
        "MemoryAdaptiveDispatcher",
        "SemaphoreDispatcher",
        "RateLimiter",
        "CrawlerMonitor",
        "LinkPreview",
        "DisplayMode",
        "MarkdownGenerationResult",
        "Crawl4aiDockerClient",
        "ProxyRotationStrategy",
        "RoundRobinProxyStrategy",
        "ProxyConfig",
        "start_colab_display_server",
        "setup_colab_environment",
        "hooks_to_string",
        # C4A Script additions
        "c4a_compile",
        "c4a_validate", 
        "c4a_compile_file",
        "CompilationResult",
        "ValidationResult",
        "ErrorDetail",
        # Browser Adapters
        "BrowserAdapter",
        "PlaywrightAdapter", 
        "UndetectedAdapter",
        "LinkPreviewConfig"
    ]

except (ImportError, ModuleNotFoundError) as _core_err:
    # Core crawl4ai dependencies (playwright, lark, etc.) are not installed.
    # The extensions sub-package (detection, bypass, downloader) can still be
    # used standalone; only the async crawler/browser features are unavailable.
    import logging as _logging
    _logging.getLogger("crawl4ai").debug(
        "crawl4ai core modules not available (%s) – extensions-only mode", _core_err,
    )
    __all__ = []


# def is_sync_version_installed():
#     try:
#         import selenium # noqa

#         return True
#     except ImportError:
#         return False


# if is_sync_version_installed():
#     try:
#         from .web_crawler import WebCrawler

#         __all__.append("WebCrawler")
#     except ImportError:
#         print(
#             "Warning: Failed to import WebCrawler even though selenium is installed. This might be due to other missing dependencies."
#         )
# else:
#     WebCrawler = None
#     # import warnings
#     # print("Warning: Synchronous WebCrawler is not available. Install crawl4ai[sync] for synchronous support. However, please note that the synchronous version will be deprecated soon.")

# ---------------------------------------------------------------------------
# Extensions ported from the web_crawler package (Huawei HG8145V5 project)
# ---------------------------------------------------------------------------
from .extensions.downloader import SiteDownloader

# Detection – individual modules in crawl4ai/extensions/detection/
from .extensions.detection import (
    BaseDetector,
    CloudflareDetector,
    SiteGroundDetector,
    WAFDetector,
    Soft404Detector,
    WordPressDetector,
    CaptchaDetector,
    detect_all as detect_protection,
)

# Extraction
from .extensions.extraction import (
    extract_all as extract_all_links,
    extract_html_attrs,
    extract_css_urls,
    extract_js_paths,
    extract_json_paths,
    extract_cloud_links,
)

# Bypass / correction – individual modules in crawl4ai/extensions/bypass/
from .extensions.bypass import (
    build_session,
    build_cf_session,
    random_headers,
    cache_bust_url,
    solve_sg_pow,
    solve_sg_captcha,
    is_sg_captcha_response,
    is_s3_access_denied,
    is_tomcat_ip_restricted,
    is_cf_managed_challenge,
    inject_cf_clearance,
    solve_cf_challenge,
)

__all__ += [
    # Huawei / web_crawler extensions
    "SiteDownloader",
    # Detection
    "BaseDetector",
    "CloudflareDetector",
    "SiteGroundDetector",
    "WAFDetector",
    "Soft404Detector",
    "WordPressDetector",
    "CaptchaDetector",
    "detect_protection",
    # Extraction
    "extract_all_links",
    "extract_html_attrs",
    "extract_css_urls",
    "extract_js_paths",
    "extract_json_paths",
    "extract_cloud_links",
    # Bypass / correction
    "build_session",
    "build_cf_session",
    "random_headers",
    "cache_bust_url",
    "solve_sg_pow",
    "solve_sg_captcha",
    "is_sg_captcha_response",
    "is_s3_access_denied",
    "is_tomcat_ip_restricted",
    "is_cf_managed_challenge",
    "inject_cf_clearance",
    "solve_cf_challenge",
]

# Disable all Pydantic warnings
warnings.filterwarnings("ignore", module="pydantic")
# pydantic_warnings.filter_warnings()