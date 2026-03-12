"""
Log analysis module.

Analyses crawler logs to discover additional pages, interesting paths,
repeated patterns, and unexplored links that may yield more content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from web_crawler.utils.log import log


@dataclass
class LogAnalysisResult:
    """Results from analysing crawler logs."""

    potential_urls: list[str] = field(default_factory=list)
    interesting_paths: list[str] = field(default_factory=list)
    repeated_patterns: dict[str, int] = field(default_factory=dict)
    unexplored_links: list[str] = field(default_factory=list)
    error_summary: dict[str, int] = field(default_factory=dict)


# Regex patterns to extract URLs and paths from log lines
_URL_IN_LOG = re.compile(r'https?://[^\s"\'<>]+')
_PATH_IN_LOG = re.compile(r'(?:GET|POST|PUT|DELETE|HEAD)\s+(/[^\s"\'<>]+)')
_STATUS_PATTERN = re.compile(r'\b(2\d{2}|3\d{2}|4\d{2}|5\d{2})\b')
_REDIRECT_PATTERN = re.compile(r'(?:redirect|location|→|->)\s*(https?://[^\s"\'<>]+)', re.I)


class LogAnalyser:
    """Parses crawler log output to find discovery opportunities."""

    def __init__(self) -> None:
        self._seen_urls: set[str] = set()

    def analyse_file(self, path: str | Path) -> LogAnalysisResult:
        """Read and analyse a log file."""
        path = Path(path)
        if not path.exists():
            log.warning("[LOG-ANALYSIS] File not found: %s", path)
            return LogAnalysisResult()

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return self.analyse_lines(lines)

    def analyse_lines(self, lines: list[str]) -> LogAnalysisResult:
        """Analyse a list of log lines."""
        result = LogAnalysisResult()
        path_counts: dict[str, int] = {}
        error_counts: dict[str, int] = {}

        for line in lines:
            # Extract URLs
            for m in _URL_IN_LOG.finditer(line):
                url = m.group(0).rstrip(".,;:)")
                if url not in self._seen_urls:
                    result.potential_urls.append(url)
                    self._seen_urls.add(url)

            # Extract paths
            for m in _PATH_IN_LOG.finditer(line):
                p = m.group(1)
                path_counts[p] = path_counts.get(p, 0) + 1

            # Extract redirects
            for m in _REDIRECT_PATTERN.finditer(line):
                url = m.group(1).rstrip(".,;:)")
                if url not in self._seen_urls:
                    result.unexplored_links.append(url)
                    self._seen_urls.add(url)

            # Count error statuses
            for m in _STATUS_PATTERN.finditer(line):
                code = m.group(1)
                if code.startswith(("4", "5")):
                    error_counts[code] = error_counts.get(code, 0) + 1

        # Find interesting / repeated paths
        for p, count in sorted(path_counts.items(), key=lambda x: -x[1]):
            if count >= 3:
                result.repeated_patterns[p] = count
            elif any(
                kw in p.lower()
                for kw in ("api", "admin", "config", "wp-", "backup", "debug")
            ):
                result.interesting_paths.append(p)

        result.error_summary = error_counts
        return result
