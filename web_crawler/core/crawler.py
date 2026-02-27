"""
Generic BFS web crawler.

Crawls a target website starting from a seed URL, downloading ALL reachable
pages and static assets with NO page limit.  Supports:

* robots.txt respect
* Configurable depth limit
* Resume from previously downloaded files
* Deduplication by content hash
* Saves ALL file types (html, php, asp, js, css, json, xml, txt, images, …)
* Saves HTTP response headers alongside each downloaded file
"""

import json
import time
import urllib.parse
import urllib.robotparser
from collections import deque
from pathlib import Path

import requests

try:
    from tqdm import tqdm as _tqdm
    _TQDM_AVAILABLE = True
except ImportError:
    _TQDM_AVAILABLE = False

from web_crawler.config import (
    BLOCKED_PATH_RE,
    CRAWLABLE_TYPES,
    DEFAULT_DELAY,
    REQUEST_TIMEOUT,
)
from web_crawler.session import build_session
from web_crawler.core.storage import content_hash, save_file, smart_local_path
from web_crawler.extraction.links import extract_links
from web_crawler.utils.log import log
from web_crawler.utils.url import normalise_url, url_key, url_to_local_path


class Crawler:
    """
    Generic BFS web crawler.  Downloads every reachable page and asset
    from a target website with NO page limit.
    """

    def __init__(
        self,
        start_url: str,
        output_dir: Path,
        max_depth: int = 0,
        delay: float = DEFAULT_DELAY,
        verify_ssl: bool = True,
        respect_robots: bool = True,
        force: bool = False,
    ) -> None:
        parsed = urllib.parse.urlparse(start_url)
        self.start_url = start_url
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.allowed_host = parsed.netloc
        self.output_dir = output_dir
        self.max_depth = max_depth
        self.delay = delay
        self.force = force
        self.session = build_session(verify_ssl=verify_ssl)

        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)
        self._hashes: set[str] = set()
        self._stats = {"ok": 0, "skip": 0, "err": 0, "dup": 0}

        # robots.txt
        self._robots: urllib.robotparser.RobotFileParser | None = None
        if respect_robots:
            self._load_robots()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        log.info("Output directory : %s", self.output_dir.resolve())
        log.info("Target URL       : %s", self.start_url)
        log.info("Allowed host     : %s", self.allowed_host)
        log.info("Page limit       : NONE (exhaustive)")
        if self.max_depth:
            log.info("Max depth        : %d", self.max_depth)

        # Resume from disk
        if not self.force:
            n = self._resume_from_disk()
            if n:
                log.info("Resume: %d existing file(s) loaded from disk.", n)

        # Seed the queue
        self._enqueue(self.start_url, 0)

        log.info("Crawl started. Dynamic discovery begins.")

        if _TQDM_AVAILABLE:
            self._run_with_progress()
        else:
            while self._queue:
                url, depth = self._queue.popleft()
                self._fetch_and_process(url, depth)

        log.info(
            "Crawl complete. visited=%d  ok=%d  skip=%d  dup=%d  err=%d",
            len(self._visited),
            self._stats["ok"],
            self._stats["skip"],
            self._stats["dup"],
            self._stats["err"],
        )
        log.info("Files saved in: %s", self.output_dir.resolve())

    def _run_with_progress(self) -> None:
        """BFS loop with a tqdm progress bar."""
        bar = _tqdm(
            desc="Crawling",
            unit="URL",
            dynamic_ncols=True,
            bar_format="{l_bar}{bar}| {n}/{total} [{elapsed}<{remaining}] {postfix}",
        )
        total_seen = len(self._queue) + len(self._visited)
        bar.total = total_seen

        while self._queue:
            url, depth = self._queue.popleft()
            prev_q = len(self._queue)
            self._fetch_and_process(url, depth)
            new_items = len(self._queue) - prev_q
            if new_items > 0:
                bar.total += new_items
                total_seen += new_items
            bar.update(1)
            bar.set_postfix(
                queued=len(self._queue),
                ok=self._stats["ok"],
                err=self._stats["err"],
            )

        bar.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_robots(self) -> None:
        """Parse robots.txt from the target host."""
        robots_url = self.base + "/robots.txt"
        self._robots = urllib.robotparser.RobotFileParser()
        self._robots.set_url(robots_url)
        try:
            self._robots.read()
            log.info("Loaded robots.txt from %s", robots_url)
        except Exception as exc:
            log.debug("Could not load robots.txt: %s", exc)
            self._robots = None

    def _is_allowed(self, url: str) -> bool:
        """Check if the URL is allowed by robots.txt."""
        if self._robots is None:
            return True
        try:
            return self._robots.can_fetch("*", url)
        except Exception:
            return True

    _DISK_CT: dict[str, str] = {
        ".html": "text/html",
        ".htm":  "text/html",
        ".asp":  "text/html",
        ".php":  "text/html",
        ".txt":  "text/plain",
        ".js":   "application/javascript",
        ".css":  "text/css",
        ".json": "application/json",
        ".xml":  "application/xml",
    }

    def _parse_local_file(self, local_path: Path, url: str) -> int:
        """Read a local file, extract links, and enqueue new ones."""
        ct = self._DISK_CT.get(local_path.suffix.lower())
        if ct is None:
            return 0
        try:
            content = local_path.read_bytes()
        except OSError as exc:
            log.debug("Could not read %s: %s", local_path, exc)
            return 0
        added = 0
        for link in extract_links(content, ct, url, self.base):
            k = url_key(link)
            if k not in self._visited:
                self._queue.append((link, 1))
                added += 1
        return added

    def _resume_from_disk(self) -> int:
        """Scan output_dir for previously downloaded files."""
        if not self.output_dir.exists():
            return 0
        count = 0
        for local_path in sorted(self.output_dir.rglob("*")):
            if not local_path.is_file():
                continue
            # Skip HTTP header files
            if local_path.suffix == ".headers":
                continue
            rel = local_path.relative_to(self.output_dir)
            path_str = "/" + str(rel).replace("\\", "/")
            if path_str == "/index.html":
                path_str = "/"
            elif path_str.endswith("/index.html"):
                path_str = path_str[:-len("index.html")]
            url = self.base + path_str
            key = url_key(url)
            if key in self._visited:
                continue
            self._visited.add(key)
            count += 1
            log.debug("Resume: %s → %s", local_path.name, url)
            self._parse_local_file(local_path, url)
        return count

    def _enqueue(self, url: str, depth: int) -> None:
        """Add *url* to the queue if not yet visited and within scope."""
        key = url_key(url)
        if key in self._visited:
            return
        # Only crawl URLs on the same host
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc != self.allowed_host:
            return
        if self.max_depth and depth > self.max_depth:
            return
        self._queue.append((url, depth))

    @staticmethod
    def _save_http_headers(local: Path, resp: requests.Response, url: str) -> None:
        """Save HTTP response headers as a .headers JSON file next to the content."""
        headers_path = local.parent / (local.name + ".headers")
        header_data = {
            "url": url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
        }
        headers_path.parent.mkdir(parents=True, exist_ok=True)
        headers_path.write_text(
            json.dumps(header_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _fetch_and_process(self, url: str, depth: int) -> None:
        key = url_key(url)
        if key in self._visited:
            return
        self._visited.add(key)

        # Blocked patterns
        parsed_url = urllib.parse.urlparse(url)
        if BLOCKED_PATH_RE.search(parsed_url.path):
            log.debug("Blocked URL, skipping: %s", url)
            return

        # Check robots.txt
        if not self._is_allowed(url):
            log.debug("Disallowed by robots.txt: %s", url)
            return

        local = smart_local_path(url, self.output_dir, "")

        # Skip already-downloaded files
        if not self.force and local.exists() and local.stat().st_size > 0:
            log.info("[SKIP] Already on disk: %s", url)
            self._stats["skip"] += 1
            added = self._parse_local_file(local, url)
            if added:
                log.debug("  +%d new URLs from cached %s", added, local.name)
            return

        log.info("[%d queued] GET %s", len(self._queue), url)

        try:
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
        except requests.RequestException as exc:
            log.warning("Request failed for %s – %s", url, exc)
            self._stats["err"] += 1
            return

        if not resp.ok:
            log.warning("HTTP %s for %s – skipping", resp.status_code, url)
            self._stats["err"] += 1
            return

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        content_disp = resp.headers.get("Content-Disposition", "")
        content = resp.content

        log.debug(
            "  ← HTTP %s  CT: %s  %d bytes",
            resp.status_code, content_type, len(content),
        )

        # Always save the file (every type: html, php, js, css, json, xml,
        # txt, asp, images, fonts, pdf, …)
        ch = content_hash(content)
        if ch in self._hashes:
            log.debug("  Duplicate content for %s – not saving again", url)
            self._stats["dup"] += 1
        else:
            self._hashes.add(ch)
            local = smart_local_path(url, self.output_dir, content_type, content_disp)
            save_file(local, content)
            self._save_http_headers(local, resp, url)
            self._stats["ok"] += 1

        # Extract and enqueue links from parseable content
        ct = content_type.split(";")[0].strip().lower()
        path_lower = parsed_url.path.lower()
        is_parseable_ext = path_lower.endswith(
            (".asp", ".php", ".html", ".htm", ".js", ".css",
             ".json", ".xml", ".txt")
        )
        if ct in CRAWLABLE_TYPES or is_parseable_ext:
            new_links = extract_links(content, content_type, url, self.base)
            added = 0
            for link in new_links:
                k = url_key(link)
                if k not in self._visited:
                    self._enqueue(link, depth + 1)
                    added += 1
            if added:
                log.debug("  +%d new URLs enqueued", added)

        time.sleep(self.delay)
