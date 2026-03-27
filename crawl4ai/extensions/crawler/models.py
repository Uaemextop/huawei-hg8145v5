"""Data models for web crawler results.

Inspired by crawl4ai's models.py, using stdlib dataclasses instead of pydantic
to keep dependencies minimal.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

__all__ = [
    "CrawlStatus",
    "MediaItem",
    "Link",
    "MarkdownGenerationResult",
    "CrawlResult",
]


class CrawlStatus(Enum):
    """Status of a crawl task."""

    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class MediaItem:
    """Represents a media resource discovered during crawling."""

    src: str = ""
    alt: str = ""
    desc: str = ""
    score: int = 0
    type: str = "image"
    format: Optional[str] = None


@dataclass
class Link:
    """Represents a hyperlink discovered during crawling."""

    href: str = ""
    text: str = ""
    title: str = ""
    base_domain: str = ""


@dataclass
class MarkdownGenerationResult:
    """Result of converting HTML content to Markdown."""

    raw_markdown: str = ""
    markdown_with_citations: str = ""
    references_markdown: str = ""
    fit_markdown: Optional[str] = None

    def __str__(self) -> str:
        return self.raw_markdown


@dataclass
class CrawlResult:
    """Main result object returned after crawling a URL.

    Mirrors crawl4ai's CrawlResult structure, adapted for our local
    web crawling use case.
    """

    url: str
    html: str
    success: bool
    cleaned_html: Optional[str] = None
    media: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    links: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    extracted_content: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    markdown: Optional[str] = None
    downloaded_files: List[str] = field(default_factory=list)
