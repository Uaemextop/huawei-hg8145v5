"""
Generic BFS web crawler.

Crawls a target website starting from a seed URL, downloading ALL reachable
pages and static assets with NO page limit.  Supports:

* robots.txt respect
* Configurable depth limit
* Resume from previously downloaded files
* Deduplication by content hash
* Soft-404 / false-positive detection
* WordPress auto-discovery (REST API, sitemaps, feeds, plugins, themes)
* User-Agent rotation and header-rotation retry on 403/402
* Cloudflare / WAF / CAPTCHA detection
* Exponential backoff on 429 (rate limiting)
* Saves ALL file types (html, php, asp, js, css, json, xml, txt, images, …)
* Saves HTTP response headers alongside each downloaded file
"""

import json
import random
import re
import string
import subprocess
import threading
import time
import urllib.parse
import urllib.robotparser
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from web_crawler.auth.lmsa import LMSASession

import requests

try:
    from curl_cffi.requests.exceptions import RequestException as CfRequestException
except ImportError:
    CfRequestException = None  # type: ignore[misc,assignment]

# Network exception tuple that catches both requests and curl_cffi errors
_NETWORK_ERRORS: tuple[type[Exception], ...] = (requests.RequestException,)
if CfRequestException is not None:
    _NETWORK_ERRORS = (requests.RequestException, CfRequestException)

_VIDEO_EXTENSIONS = frozenset((
    ".mp4", ".webm", ".ogv", ".avi", ".mov", ".flv", ".mkv", ".wmv",
    ".m4v", ".3gp", ".3g2", ".ts", ".mpeg", ".mpg", ".f4v", ".asf",
    ".m3u8",
))

_AUDIO_EXTENSIONS = frozenset((
    ".mp3", ".ogg", ".wav", ".flac", ".aac", ".m4a", ".weba",
))

_MEDIA_EXTENSIONS = _VIDEO_EXTENSIONS | _AUDIO_EXTENSIONS

try:
    from tqdm import tqdm as _tqdm
    _TQDM_AVAILABLE = True
except ImportError:
    _TQDM_AVAILABLE = False

from web_crawler.config import (
    BACKOFF_429_BASE,
    BACKOFF_429_MAX,
    BINARY_CONTENT_TYPES,
    BLOCKED_PATH_RE,
    CRAWLABLE_TYPES,
    DEFAULT_DELAY,
    DEFAULT_CONCURRENCY,
    HEADER_RETRY_MAX,
    HIDDEN_FILE_PROBES,
    MAX_QUEUE_SIZE,
    MAX_URL_RETRIES,
    PROBE_403_THRESHOLD,
    PROBE_404_THRESHOLD,
    PROBE_DIR_404_LIMIT,
    REQUEST_TIMEOUT,
    RETRY_STATUS_CODES,
    SITEGROUND_BLOCKED_EXTENSIONS,
    SOFT_404_KEYWORDS,
    SOFT_404_MIN_KEYWORD_HITS,
    SOFT_404_SIZE_RATIO,
    SOFT_404_STANDALONE_MIN_HITS,
    SOFT_404_TITLE_KEYWORDS,
    STREAM_SIZE_THRESHOLD,
    USER_AGENTS,
    WAF_SIGNATURES,
    WP_DISCOVERY_PATHS,
    WP_PLUGIN_FILES,
    WP_PLUGIN_PROBES,
    WP_THEME_FILES,
    WP_THEME_PROBES,
    auto_concurrency,
)
from web_crawler.session import (
    build_cf_session, build_session, cache_bust_url, inject_cf_clearance,
    is_cf_managed_challenge, is_s3_access_denied, is_sg_captcha_response,
    is_tomcat_ip_restricted, random_headers, solve_cf_challenge,
    solve_sg_captcha,
)
from web_crawler.core.storage import (
    content_hash, file_content_hash, save_file, smart_local_path,
    stream_to_file,
)
from web_crawler.extraction.links import extract_links
from web_crawler.utils.log import ci_endgroup, ci_group, log
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
        git_push_every: int = 0,
        skip_captcha_check: bool = False,
        download_extensions: frozenset[str] | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        upload_extensions: frozenset[str] | None = None,
        debug: bool = False,
        cf_clearance: str = "",
        allow_external: bool = True,
        skip_media_files: bool = False,
        skip_download_exts: frozenset[str] | None = None,
        lmsa_session: "Optional[LMSASession]" = None,
        extra_seed_urls: list[str] | None = None,
    ) -> None:
        parsed = urllib.parse.urlparse(start_url)
        self.start_url = start_url
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.allowed_host = parsed.netloc
        self.output_dir = output_dir
        self.max_depth = max_depth
        self.delay = delay
        self.force = force
        self.debug = debug
        self.git_push_every = git_push_every
        self.skip_captcha_check = skip_captcha_check
        self.skip_media_files = skip_media_files
        # Extensions for which we record the download link but skip the actual
        # download.  Links are written to download_links.txt with ready-to-run
        # curl commands including all required authentication headers.
        self.skip_download_exts: frozenset[str] = frozenset(
            e.lower().lstrip(".") for e in (skip_download_exts or [])
        )
        self.download_extensions = download_extensions or frozenset()
        self.upload_extensions = upload_extensions or frozenset()
        self.concurrency = auto_concurrency() if concurrency <= 0 else concurrency
        self._ext_link_re: re.Pattern | None = None
        if self.download_extensions:
            ext_pattern = "|".join(re.escape(e) for e in self.download_extensions)
            self._ext_link_re = re.compile(
                r'''(?:href|src|data-src|action)\s*=\s*['"]([^'"]*?(?:'''
                + ext_pattern
                + r""")(?:\?[^'"]*)?)['"]\s*""",
                re.I,
            )
        self.session = build_session(verify_ssl=verify_ssl)
        if cf_clearance:
            inject_cf_clearance(self.session, parsed.netloc, cf_clearance)
        # Inject LMSA auth headers when an authenticated session is provided.
        if lmsa_session is not None and lmsa_session.is_authenticated:
            lmsa_session.inject_into_requests_session(self.session, parsed.netloc)
            log.info("[LMSA] Auth headers injected into crawler session")

        # Pre-seeded URLs added before crawl starts (e.g. LMSA firmware scan).
        self._extra_seed_urls: list[str] = list(extra_seed_urls or [])

        self._lock = threading.Lock()     # protects shared state in concurrent mode

        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)
        self._hashes: set[str] = set()
        self._probed_dirs: set[str] = set()  # directories already probed for hidden files
        self._probe_urls: set[str] = set()   # URLs generated by hidden-file / WP probing
        self._probe_403_count: int = 0       # consecutive 403s from probe URLs
        self._probe_404_count: int = 0       # consecutive 404s from probe URLs
        self._probe_dir_failures: dict[str, int] = {}  # per-directory probe failure count
        # Pre-disable probing for known private S3 buckets — _probe_hidden_files
        # is called before the HTTP response arrives, so without this guard the
        # queue would be flooded with ~340 probe URLs that all return 403 before
        # the reactive S3-AccessDenied detection can fire.
        _is_s3_host = parsed.netloc == "rsddownload-secure.lenovo.com"
        self._probing_disabled: bool = _is_s3_host
        if _is_s3_host:
            log.info(
                "[LMSA] Probing pre-disabled for private S3 bucket (%s)",
                parsed.netloc,
            )
        self._sg_captcha_solves: int = 0     # how many inline captchas solved
        self._sg_solve_lock = threading.Lock()  # serialize concurrent CAPTCHA solves
        self._url_retries: dict[str, int] = {}  # per-URL retry count for transient errors
        self._stats = {"ok": 0, "skip": 0, "err": 0, "dup": 0,
                       "soft404": 0, "waf": 0, "retry_ok": 0, "probe": 0,
                       "restricted": 0}

        # Soft-404 detection
        self._soft404_size: int | None = None
        self._soft404_hash: str | None = None

        # WordPress detection
        self._wp_detected: bool = False
        self._wp_probed: bool = False
        self._wp_nonce: str = ""        # extracted from page HTML (not sent globally)
        self._wp_confirmed_plugins: set[str] = set()
        self._wp_confirmed_themes: set[str] = set()

        # Cloudflare bypass state
        self._cf_bypass_done: bool = False

        # CDN hosts: external domains discovered from media elements
        # (video/audio/source tags, Schema.org itemprop).  URLs on
        # these hosts are downloaded but NOT crawled for links.
        self._cdn_hosts: set[str] = set()
        self._allow_external = allow_external
        self._video_urls: list[str] = []
        self._video_meta: dict[str, dict[str, str]] = {}  # url → {title, author, thumbnail, duration, upload_date}
        self._saved_urls: list[str] = []

        # download_links.txt – populated when skip_download_exts is set.
        # Each line is a ready-to-run curl command with all auth headers.
        self._download_links_path = self.output_dir / "download_links.txt"
        self._download_links_seen: set[str] = set()

        # robots.txt (loaded after captcha solve in run())
        self._robots: urllib.robotparser.RobotFileParser | None = None
        self._respect_robots = respect_robots

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        ci_group("Crawl configuration")
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Output directory : %s", self.output_dir.resolve())
        log.info("Target URL       : %s", self.start_url)
        log.info("Allowed host     : %s", self.allowed_host)
        log.info("Page limit       : NONE (exhaustive)")
        if self.max_depth:
            log.info("Max depth        : %d", self.max_depth)
        if self.download_extensions:
            log.info("Seek extensions  : %s", ", ".join(sorted(self.download_extensions)))
        log.info("Concurrency      : %d workers", self.concurrency)
        if self.debug:
            log.info("Debug mode       : ON (headers saved, verbose logging)")
        if self.upload_extensions:
            log.info("Upload filter    : %s", ", ".join(sorted(self.upload_extensions)))
        if self.skip_media_files:
            log.info("Skip media files : ON (media URLs recorded but files not saved)")
        if self.skip_download_exts:
            log.info(
                "Skip download    : %s (links recorded in download_links.txt)",
                ", ".join(sorted(self.skip_download_exts)),
            )
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        ci_endgroup()

        # Pre-solve SiteGround CAPTCHA if the server uses it.
        # Must run before any other HTTP requests so the session cookie
        # is set for robots.txt loading and soft-404 probing.
        self._try_sg_captcha_bypass()

        # Check for Cloudflare Managed Challenge early, before wasting
        # time on robots.txt and soft-404 probing.
        self._check_cf_managed_challenge()

        # Load robots.txt (uses our session with the captcha cookie)
        if self._respect_robots:
            self._load_robots()

        # Build soft-404 baseline
        self._build_soft404_fingerprint()

        # Resume from disk
        if not self.force:
            n = self._resume_from_disk()
            if n:
                log.info("Resume: %d existing file(s) loaded from disk.", n)

        # Seed the queue
        self._enqueue(self.start_url, 0)

        # Add extra seed URLs from LMSA firmware scan (pre-signed S3 URLs).
        if self._extra_seed_urls:
            # When skip_download_exts is set, record S3 URLs matching the
            # skip list directly (without making a HEAD request) since they
            # are pre-signed direct-download links, then only enqueue the rest.
            skip_recorded = 0
            for seed_url in self._extra_seed_urls:
                seed_ext = urllib.parse.urlparse(seed_url).path.rsplit(".", 1)[-1].lower()
                if self.skip_download_exts and seed_ext in self.skip_download_exts:
                    self._record_download_link(seed_url)
                    skip_recorded += 1
                else:
                    self._enqueue(seed_url, 0, priority=True)
            enqueued = len(self._extra_seed_urls) - skip_recorded
            log.info(
                "[LMSA] Seeding crawler with %d firmware download URLs "
                "(%d enqueued, %d recorded in download_links.txt)",
                len(self._extra_seed_urls), enqueued, skip_recorded,
            )

        log.info("Crawl started. Dynamic discovery begins.")

        if self.concurrency > 1:
            self._run_concurrent()
        elif _TQDM_AVAILABLE:
            self._run_with_progress()
        else:
            while self._queue:
                url, depth = self._queue.popleft()
                self._fetch_and_process(url, depth)

        self._log_final_stats()

    def _log_final_stats(self) -> None:
        """Print a summary table with final crawl statistics."""
        s = self._stats
        total = s["ok"] + s["skip"] + s["dup"] + s["err"] + s["soft404"] + s["waf"] + s["probe"]
        pct_ok = (s["ok"] / total * 100) if total else 0
        pct_err = (s["err"] / total * 100) if total else 0
        ci_group("Crawl results")
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Crawl complete!")
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Visited     : %d URLs", len(self._visited))
        log.info("Saved (OK)  : %d  (%.1f%%)", s["ok"], pct_ok)
        log.info("Restricted  : %d  (IP/WAF – body saved)", s["restricted"])
        log.info("Skipped     : %d", s["skip"])
        log.info("Duplicates  : %d", s["dup"])
        log.info("Soft-404    : %d", s["soft404"])
        log.info("WAF blocked : %d", s["waf"])
        log.info("Probe miss  : %d", s["probe"])
        log.info("Retry OK    : %d", s["retry_ok"])
        log.info("Errors      : %d  (%.1f%%)", s["err"], pct_err)
        log.info("Captcha     : %d solves", self._sg_captcha_solves)
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Files saved in: %s", self.output_dir.resolve())
        ci_endgroup()

        # Write final URL list
        self._write_url_list()

        # Write video URL list
        self._write_video_url_list()

    @staticmethod
    def _sanitize_meta_value(value: str) -> str:
        """Sanitize a metadata value for pipe-separated output.

        Replaces pipe characters and newlines so they do not break
        the ``video_urls.txt`` line format.
        """
        return value.replace("|", "-").replace("\n", " ").replace("\r", "")

    def _write_video_url_list(self) -> None:
        """Write tracked video URLs to ``video_urls.txt``.

        Each line uses the pipe-separated format (6 fields)::

            URL|Title|Author|ThumbnailUrl|Duration|UploadDate

        Metadata is sourced from JSON-LD ``VideoObject``, Schema.org
        microdata (``itemprop`` tags), or page-level OG/meta tags (in
        that priority order).  Pipe characters and newlines inside
        metadata values are sanitized to preserve the format.
        """
        if not self._video_urls:
            return
        video_list = self.output_dir / "video_urls.txt"
        video_list.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []
        _san = self._sanitize_meta_value
        for url in self._video_urls:
            meta = self._video_meta.get(url, {})
            parts = [
                url,
                _san(meta.get("title", "")),
                _san(meta.get("author", "")),
                _san(meta.get("thumbnail", "")),
                _san(meta.get("duration", "")),
                _san(meta.get("upload_date", "")),
            ]
            lines.append("|".join(parts))
        video_list.write_text(
            "\n".join(lines) + "\n", encoding="utf-8",
        )
        log.info("Video URL list: %d URL(s) → %s",
                  len(self._video_urls), video_list)

    def _stats_postfix(self) -> dict[str, object]:
        """Return a dict suitable for tqdm ``set_postfix``."""
        return {
            "Q": len(self._queue),
            "OK": self._stats["ok"],
            "RESTR": self._stats["restricted"],
            "ERR": self._stats["err"],
            "SKIP": self._stats["skip"],
            "DUP": self._stats["dup"],
            "S404": self._stats["soft404"],
            "PROBE": self._stats["probe"],
        }

    def _track_video_url(self, url: str) -> None:
        """Append *url* to the video list if it has a video extension.

        Must be called while ``self._lock`` is held.
        """
        path_lower = urllib.parse.urlparse(url).path.lower()
        if any(path_lower.endswith(ext) for ext in _VIDEO_EXTENSIONS):
            self._video_urls.append(url)

    def _record_download_link(self, url: str) -> None:
        """Write *url* to ``download_links.txt`` as a ready-to-run curl command.

        The command includes all session headers (Authorization, guid,
        Request-Tag, etc.) so users can paste it into a terminal and download
        the file directly.

        Must be called while ``self._lock`` is held.
        """
        if url in self._download_links_seen:
            return
        self._download_links_seen.add(url)

        # Build curl header flags from the current session headers.
        header_parts: list[str] = []
        for name, value in self.session.headers.items():
            # Skip headers that curl adds automatically or that vary per request
            if name.lower() in ("host", "content-length", "transfer-encoding",
                                 "connection", "accept-encoding"):
                continue
            # Escape single quotes in header values
            safe_value = value.replace("'", "'\\''")
            header_parts.append(f"-H '{name}: {safe_value}'")

        # Derive a safe output filename from the URL path
        path = urllib.parse.urlparse(url).path
        filename = path.rstrip("/").rsplit("/", 1)[-1] or "download"
        # URL-decode special characters in the filename
        filename = urllib.parse.unquote(filename)

        headers_str = " \\\n  ".join(header_parts)
        if headers_str:
            cmd = f"curl -L -o '{filename}' \\\n  {headers_str} \\\n  '{url}'"
        else:
            cmd = f"curl -L -o '{filename}' '{url}'"

        # Also write a wget-compatible line
        wget_headers = " ".join(
            f"--header='{n}: {v.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'"
            for n, v in self.session.headers.items()
            if n.lower() not in ("host", "content-length", "transfer-encoding",
                                  "connection", "accept-encoding")
        )
        if wget_headers:
            wget_cmd = f"wget {wget_headers} -O '{filename}' '{url}'"
        else:
            wget_cmd = f"wget -O '{filename}' '{url}'"

        self.output_dir.mkdir(parents=True, exist_ok=True)
        with self._download_links_path.open("a", encoding="utf-8") as fh:
            fh.write(f"# {url}\n")
            fh.write(f"{cmd}\n\n")
            fh.write(f"# wget alternative:\n# {wget_cmd}\n\n")
            fh.write("# ─" * 40 + "\n\n")

    @staticmethod
    def _merge_video_meta(
        existing: dict[str, str],
        incoming: dict[str, str],
    ) -> None:
        """Merge *incoming* metadata into *existing*, filling empty fields.

        Non-empty values in *existing* are kept; only blank fields are
        filled from *incoming*.
        """
        for key, val in incoming.items():
            if val and not existing.get(key):
                existing[key] = val

    def _populate_video_meta(self, html: str, links: set[str]) -> None:
        """Extract metadata from an HTML page and associate it with video links.

        Per-video metadata from JSON-LD ``VideoObject`` entries and
        Schema.org microdata (``itemprop`` meta tags) takes priority
        over page-level metadata (title, author, thumbnail, duration,
        upload_date).

        When a video URL already has metadata from a previous call
        (e.g. from a JSON API response with empty fields), non-empty
        values from the new source are merged in rather than blocked.
        """
        from web_crawler.extraction.html_parser import (
            extract_page_metadata,
            extract_jsonld_video_meta,
            extract_microdata_video_meta,
        )
        page_meta = extract_page_metadata(html)
        video_meta = extract_jsonld_video_meta(html)
        microdata_meta = extract_microdata_video_meta(html)

        # Enrich page-level fallback with shared fields from the
        # page's structured data (e.g. author) so that video URLs
        # that are NOT the microdata contentURL still get them.
        # (empty dicts are falsy, so ``if src`` skips them safely)
        for src in (microdata_meta, video_meta):
            if src:
                first = next(iter(src.values()))
                if not page_meta.get("author") and first.get("author"):
                    page_meta["author"] = first["author"]
                break  # use the first available source

        with self._lock:
            # Store JSON-LD per-video metadata (highest priority)
            for vurl, vmeta in video_meta.items():
                existing = self._video_meta.get(vurl)
                if existing is None:
                    self._video_meta[vurl] = vmeta
                else:
                    self._merge_video_meta(existing, vmeta)

            # Store microdata per-video metadata (second priority)
            for vurl, vmeta in microdata_meta.items():
                existing = self._video_meta.get(vurl)
                if existing is None:
                    self._video_meta[vurl] = vmeta
                else:
                    self._merge_video_meta(existing, vmeta)

            # For discovered links that look like video URLs, use
            # page-level metadata as a fallback.
            for link in links:
                path_lower = urllib.parse.urlparse(link).path.lower()
                if any(path_lower.endswith(ext) for ext in _VIDEO_EXTENSIONS):
                    existing = self._video_meta.get(link)
                    if existing is None:
                        self._video_meta[link] = dict(page_meta)
                    else:
                        self._merge_video_meta(existing, page_meta)

    def _write_url_list(self) -> None:
        """Write all **video** URLs to ``url_list.txt``.

        Includes URLs whose path ends with a known video extension
        (``_VIDEO_EXTENSIONS``) from both saved downloads and tracked
        video URLs (e.g. media files recorded when ``--skip-media-files``
        is active).
        """
        saved_videos = [
            u for u in self._saved_urls
            if any(urllib.parse.urlparse(u).path.lower().endswith(ext)
                   for ext in _VIDEO_EXTENSIONS)
        ]
        # Merge saved video URLs with tracked video URLs, preserving order
        # and removing duplicates.
        snapshot = list(dict.fromkeys(saved_videos + self._video_urls))
        if not snapshot:
            return
        url_list = self.output_dir / "url_list.txt"
        url_list.parent.mkdir(parents=True, exist_ok=True)
        url_list.write_text(
            "\n".join(snapshot) + "\n", encoding="utf-8",
        )

    def _is_media_url(self, url: str) -> bool:
        """Return ``True`` if *url* points to a media file (video/audio)."""
        path_lower = urllib.parse.urlparse(url).path.lower()
        return any(path_lower.endswith(ext) for ext in _MEDIA_EXTENSIONS)

    def _is_media_content_type(self, ct: str) -> bool:
        """Return ``True`` if *ct* is a video or audio MIME type."""
        return ct.startswith("video/") or ct.startswith("audio/")

    def _run_with_progress(self) -> None:
        """BFS loop with a tqdm progress bar."""
        bar = _tqdm(
            desc="Crawling",
            unit="URL",
            dynamic_ncols=True,
            bar_format=(
                "{l_bar}{bar}| {n_fmt}/{total_fmt} "
                "[{elapsed}<{remaining}, {rate_fmt}] {postfix}"
            ),
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
            bar.set_postfix(self._stats_postfix())

        bar.close()

    def _run_concurrent(self) -> None:
        """BFS loop with a ThreadPoolExecutor and live progress bar."""
        log.info("Concurrent mode: %d workers", self.concurrency)
        use_bar = _TQDM_AVAILABLE

        bar = None
        if use_bar:
            bar = _tqdm(
                desc="Crawling",
                unit="URL",
                dynamic_ncols=True,
                bar_format=(
                    "{l_bar}{bar}| {n_fmt}/{total_fmt} "
                    "[{elapsed}<{remaining}, {rate_fmt}] {postfix}"
                ),
                total=len(self._queue) + len(self._visited),
            )

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            while self._queue:
                # Drain up to `concurrency` items from the queue
                batch: list[tuple[str, int]] = []
                with self._lock:
                    while self._queue and len(batch) < self.concurrency:
                        batch.append(self._queue.popleft())
                if not batch:
                    break
                futures = {
                    pool.submit(self._fetch_and_process, url, depth): url
                    for url, depth in batch
                }
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as exc:
                        log.warning("Worker error for %s: %s",
                                    futures[fut], exc)
                    if bar is not None:
                        # Update progress after each completed future
                        with self._lock:
                            new_total = len(self._queue) + len(self._visited)
                        if new_total > bar.total:
                            bar.total = new_total
                        bar.update(1)
                        bar.set_postfix(self._stats_postfix())

        if bar is not None:
            bar.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_robots(self) -> None:
        """Parse robots.txt from the target host.

        Uses our live session so captcha cookies are included.  Treats HTTP
        responses as follows (per RFC 9309 §2.3.1):

        * 2xx  → parse normally
        * 404 / 410  → no restrictions (allow all)
        * 401 / 403  → Python's ``RobotFileParser`` normally marks everything
          as disallowed for these codes.  We override that behaviour when the
          response body is an AWS/S3/CloudFront ``AccessDenied`` XML error,
          which is not a real robots.txt and should be treated as "not found".
        * Other 4xx/5xx  → treat as "not found" (allow all)
        """
        robots_url = self.base + "/robots.txt"
        try:
            resp = self.session.get(robots_url, timeout=15, allow_redirects=True)
        except Exception as exc:
            log.debug("Could not fetch robots.txt: %s", exc)
            return

        status = resp.status_code

        # 404/410 → no robots.txt file, allow everything.
        if status in (404, 410):
            log.debug("No robots.txt at %s (HTTP %s)", robots_url, status)
            return

        # 401/403 that look like S3/CloudFront AccessDenied XML → ignore.
        # Python's RobotFileParser would treat these as Disallow: / which is
        # wrong for private S3 buckets where robots.txt simply doesn't exist.
        if status in (401, 403):
            ct = resp.headers.get("Content-Type", "")
            body = resp.text
            if ("AccessDenied" in body or "application/xml" in ct
                    or "AmazonS3" in resp.headers.get("server", "")
                    or "cloudfront" in resp.headers.get("via", "").lower()):
                log.debug(
                    "robots.txt at %s returned %s with S3/CloudFront error body "
                    "— treating as not found (allow all)",
                    robots_url, status,
                )
                return
            # Genuine 403 (not an S3 artefact) → disallow all, per RFC 9309.
            log.debug("robots.txt at %s returned %s → disallowing all", robots_url, status)
            self._robots = urllib.robotparser.RobotFileParser()
            self._robots.set_url(robots_url)
            self._robots.disallow_all = True
            return

        if status != 200:
            log.debug("robots.txt fetch returned HTTP %s — treating as not found", status)
            return

        # HTTP 200 — parse normally.
        self._robots = urllib.robotparser.RobotFileParser()
        self._robots.set_url(robots_url)
        self._robots.parse(resp.text.splitlines())
        log.info("Loaded robots.txt from %s", robots_url)

    def _is_allowed(self, url: str) -> bool:
        """Check if the URL is allowed by robots.txt."""
        if self._robots is None:
            return True
        try:
            return self._robots.can_fetch("*", url)
        except Exception:
            return True

    def _try_sg_captcha_bypass(self) -> None:
        """If the target uses SiteGround CAPTCHA, solve the PoW
        challenge once so the session cookie is set."""
        log.info("Checking for SiteGround CAPTCHA …")
        solved = solve_sg_captcha(self.session, self.base, "/")
        if solved:
            # The server's meta-refresh suggests a 1-second wait
            # before the cookie is fully active.
            time.sleep(1)
            log.info("[SG-CAPTCHA] Solved – session cookie set")
        else:
            log.info("No SiteGround CAPTCHA detected (or not solvable)")

    def _check_cf_managed_challenge(self) -> None:
        """Detect and auto-solve a Cloudflare Managed Challenge.

        If the site returns ``cf-mitigated: challenge``, attempt to
        solve it by switching to a ``curl_cffi`` session (TLS fingerprint
        impersonation) or falling back to Playwright.
        """
        try:
            resp = self.session.get(
                self.start_url, timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
        except _NETWORK_ERRORS:
            return
        if not is_cf_managed_challenge(resp):
            log.info("No Cloudflare challenge detected")
            return

        log.warning(
            "Cloudflare Managed Challenge detected on %s",
            self.start_url,
        )
        self._solve_cf_and_inject()

    def _solve_cf_and_inject(self) -> bool:
        """Switch the session to bypass Cloudflare.

        Uses ``curl_cffi`` TLS impersonation (preferred) or Playwright
        headless browser (fallback).  When ``curl_cffi`` works, the
        entire ``self.session`` is replaced with a ``curl_cffi`` session
        so that all subsequent requests use the same TLS fingerprint.

        Returns ``True`` on success.
        """
        cf_session = build_cf_session(verify_ssl=self.session.verify)
        if cf_session is not None:
            # Transfer existing cookies to the new session
            for cookie in self.session.cookies:
                cf_session.cookies.set(
                    cookie.name, cookie.value,
                    domain=cookie.domain, path=cookie.path,
                )
            try:
                check = cf_session.get(
                    self.start_url, timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                if check.ok and "just a moment" not in check.text[:2048].lower():
                    self.session = cf_session
                    log.info("[CF] Switched to curl_cffi session – bypass confirmed")
                    self._cf_bypass_done = True
                    return True
            except Exception as exc:
                log.debug("[CF] curl_cffi direct attempt failed: %s", exc)

        # Fallback: Playwright + cookie injection
        result = solve_cf_challenge(self.start_url)
        if not result:
            log.warning(
                "[CF] Could not auto-solve. Provide --cf-clearance <cookie> "
                "obtained from a browser session to bypass it.",
            )
            return False

        cookies, browser_ua = result
        parsed = urllib.parse.urlparse(self.start_url)
        for name, value in cookies.items():
            self.session.cookies.set(name, value,
                                     domain=parsed.netloc, path="/")
        self.session.headers["User-Agent"] = browser_ua
        log.info("[CF] %d cookies injected (UA synced) – verifying …",
                 len(cookies))
        try:
            check = self.session.get(
                self.start_url, timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if check.ok and not is_cf_managed_challenge(check):
                log.info("[CF] Cloudflare bypass confirmed")
                self._cf_bypass_done = True
                return True
        except _NETWORK_ERRORS:
            pass
        log.warning("[CF] Cookies did not bypass the challenge")
        return False

    # ------------------------------------------------------------------
    # Soft-404 detection
    # ------------------------------------------------------------------

    def _build_soft404_fingerprint(self) -> None:
        """Fetch a random non-existent URL to fingerprint the server's
        custom error page (soft-404)."""
        slug = "".join(random.choices(string.ascii_lowercase, k=12))
        probe = f"{self.base}/_{slug}_does_not_exist_{slug}.html"
        try:
            resp = self.session.get(
                probe, timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
        except _NETWORK_ERRORS:
            log.debug("Soft-404 probe failed (request error); detection disabled.")
            return

        if not resp.ok:
            # Server returns a real HTTP 404 – no soft-404 problem.
            log.debug("Server returns HTTP %s for missing pages – no soft-404.", resp.status_code)
            return

        # Server returned 200 for a non-existent page – soft-404 likely.
        body = resp.content
        self._soft404_size = len(body)
        self._soft404_hash = content_hash(body)
        log.info("Soft-404 baseline: %d bytes, hash=%s (server returns 200 for missing pages)",
            self._soft404_size, self._soft404_hash,
        )

    def _is_soft_404(self, content: bytes, url: str) -> bool:
        """Return True if *content* looks like a soft-404 (false positive).

        Detection layers:
        1. Exact hash match with the baseline probe.
        2. Size-based heuristic + keyword check (when baseline exists).
        3. ``<title>`` tag contains 404-related keywords.
        4. Standalone keyword check (works even without baseline).
        """
        text = content.decode("utf-8", errors="replace").lower()

        # --- Layer 1: baseline fingerprint exact match ---
        if self._soft404_hash is not None:
            if content_hash(content) == self._soft404_hash:
                log.debug("  Soft-404 (exact baseline match): %s", url)
                return True

            # --- Layer 2: size similarity + keywords ---
            size = len(content)
            if self._soft404_size and self._soft404_size > 0:
                ratio = abs(size - self._soft404_size) / self._soft404_size
                if ratio <= SOFT_404_SIZE_RATIO:
                    hits = sum(1 for kw in SOFT_404_KEYWORDS if kw in text)
                    if hits >= SOFT_404_MIN_KEYWORD_HITS:
                        log.debug(
                            "  Soft-404 (size+keywords, %d hits): %s",
                            hits, url,
                        )
                        return True

        # --- Layer 3: <title> tag contains 404-like keywords ---
        # Search only the first 4 KB where <title> typically appears.
        head = text[:4096]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", head, re.S)
        if title_match:
            title = title_match.group(1).strip()
            for kw in SOFT_404_TITLE_KEYWORDS:
                if kw in title:
                    log.debug(
                        "  Soft-404 (title contains '%s'): %s", kw, url,
                    )
                    return True

        # --- Layer 4: standalone keyword check (no baseline needed) ---
        hits = sum(1 for kw in SOFT_404_KEYWORDS if kw in text)
        if hits >= SOFT_404_STANDALONE_MIN_HITS:
            log.debug(
                "  Soft-404 (standalone, %d keyword hits): %s", hits, url,
            )
            return True

        return False

    # ------------------------------------------------------------------
    # WordPress detection & discovery
    # ------------------------------------------------------------------

    @staticmethod
    def detect_wordpress(html: str) -> bool:
        """Return True if the HTML indicates a WordPress site."""
        lower = html.lower()
        indicators = [
            "wp-content/",
            "wp-includes/",
            'name="generator" content="wordpress',
            "/wp-json/",
            "wp-emoji-release.min.js",
        ]
        return any(ind in lower for ind in indicators)

    def _enqueue_wp_discovery(self, depth: int) -> None:
        """Enqueue WordPress-specific discovery URLs."""
        if self._wp_probed:
            return
        self._wp_probed = True
        for path in WP_DISCOVERY_PATHS:
            wp_url = self.base + path
            self._probe_urls.add(url_key(wp_url))
            self._enqueue(wp_url, 0)
        # Plugin enumeration (readme.txt to confirm existence)
        for slug in WP_PLUGIN_PROBES:
            wp_url = self.base + f"/wp-content/plugins/{slug}/readme.txt"
            self._probe_urls.add(url_key(wp_url))
            self._enqueue(wp_url, 0)
        # Theme enumeration (style.css to confirm existence)
        for slug in WP_THEME_PROBES:
            wp_url = self.base + f"/wp-content/themes/{slug}/style.css"
            self._probe_urls.add(url_key(wp_url))
            self._enqueue(wp_url, 0)
        # Author enumeration (users 1-10)
        for n in range(1, 11):
            wp_url = self.base + f"/?author={n}"
            self._probe_urls.add(url_key(wp_url))
            self._enqueue(wp_url, 0)
        total = (len(WP_DISCOVERY_PATHS) + len(WP_PLUGIN_PROBES)
                 + len(WP_THEME_PROBES) + 10)
        log.info("[WP] WordPress detected – enqueued %d discovery URLs", total)

        # Discover media file URLs (images, ZIPs) via REST API
        self._discover_wp_media()
        # Discover custom post types (e.g. Magisk modules, products, etc.)
        self._discover_wp_custom_post_types()
        # Discover WooCommerce product pages and any linked files
        self._discover_wc_products()
        # Discover Androidacy-style third-party module repositories
        self._discover_androidacy_repo()

    def _discover_wp_media(self) -> None:
        """Use the WP REST API to discover downloadable media files
        (images, ZIPs, etc.) and enqueue their direct URLs."""
        page = 1
        total = 0
        while page <= 20:  # safety cap
            api_url = (f"{self.base}/wp-json/wp/v2/media"
                       f"?per_page=100&page={page}")
            try:
                resp = self.session.get(api_url, timeout=REQUEST_TIMEOUT)
            except _NETWORK_ERRORS:
                break
            if resp.status_code != 200:
                break
            try:
                items = resp.json()
            except ValueError:
                break
            if not items:
                break
            for item in items:
                src = item.get("source_url", "")
                if src and self.allowed_host in src:
                    self._enqueue(src, 0, priority=True)
                    total += 1
            if len(items) < 100:
                break
            page += 1
            time.sleep(self.delay)
        if total:
            log.debug("  [WP-MEDIA] Discovered %d media files via REST API",
                     total)

    def _discover_wp_custom_post_types(self) -> None:
        """Discover custom post types via the WP REST API ``/wp/v2/types``
        endpoint and enumerate all their published items.

        WordPress sites often register custom post types for domain-specific
        content (e.g. Magisk modules, firmware entries, products) that live
        under non-standard URL paths.  The built-in ``posts`` and ``pages``
        are already covered by :data:`WP_DISCOVERY_PATHS`; this method
        handles all *additional* types exposed by the REST API.
        """
        # Standard types already covered by WP_DISCOVERY_PATHS
        _SKIP_TYPES = frozenset({
            "post", "page", "attachment", "nav_menu_item",
            "wp_block", "wp_template", "wp_template_part",
            "wp_global_styles", "wp_navigation", "wp_font_family",
            "wp_font_face",
        })
        types_url = f"{self.base}/wp-json/wp/v2/types"
        try:
            resp = self.session.get(types_url, timeout=REQUEST_TIMEOUT)
        except _NETWORK_ERRORS:
            return
        if resp.status_code != 200:
            return
        try:
            types_data = resp.json()
        except ValueError:
            return
        if not isinstance(types_data, dict):
            return

        for slug, info in types_data.items():
            if slug in _SKIP_TYPES:
                continue
            rest_base = info.get("rest_base", "")
            type_name = info.get("name", slug)
            if not rest_base:
                continue
            # Enumerate all published items for this custom post type
            page_num = 1
            item_total = 0
            while page_num <= 50:
                api_url = (
                    f"{self.base}/wp-json/wp/v2/{rest_base}"
                    f"?per_page=100&page={page_num}"
                )
                try:
                    items_resp = self.session.get(
                        api_url, timeout=REQUEST_TIMEOUT,
                    )
                except _NETWORK_ERRORS:
                    break
                if items_resp.status_code != 200:
                    break
                try:
                    items = items_resp.json()
                except ValueError:
                    break
                if not isinstance(items, list) or not items:
                    break
                for item in items:
                    link = item.get("link", "")
                    if link and self.allowed_host in link:
                        self._enqueue(link, 1)
                        item_total += 1
                if len(items) < 100:
                    break
                page_num += 1
                time.sleep(self.delay)
            if item_total:
                log.info(
                    "[WP-CPT] Discovered %d '%s' items via REST API",
                    item_total, type_name,
                )

    def _discover_wc_products(self) -> None:
        """Enumerate WooCommerce products via the Store API and enqueue:
        * every product permalink (HTML product page)
        * every image / thumbnail URL
        * any archive/binary files linked in the product description

        Also probes the WooCommerce uploads directory with common
        year/month sub-paths when *download_extensions* is set.
        """
        import re as _re
        page = 1
        product_total = 0
        file_total = 0
        # Archive extension pattern for scanning product descriptions
        _arch_re = _re.compile(
            r'https?://[^\s"\'<>]+\.(?:zip|rar|7z|tar|gz|bz2|xz|bin|exe'
            r'|img|iso|hwnp|fwu|pkg)(?:\?[^\s"\'<>]*)?',
            _re.I,
        )
        while page <= 50:  # WC sites rarely have >5000 products (100/page)
            api_url = (f"{self.base}/wp-json/wc/store/v1/products"
                       f"?per_page=100&page={page}")
            try:
                resp = self.session.get(api_url, timeout=REQUEST_TIMEOUT)
            except _NETWORK_ERRORS:
                break
            if resp.status_code != 200:
                break
            try:
                items = resp.json()
            except ValueError:
                break
            if not isinstance(items, list) or not items:
                break
            for item in items:
                # Product page
                permalink = item.get("permalink", "")
                if permalink and self.allowed_host in permalink:
                    self._enqueue(permalink, 1)
                    product_total += 1
                # Product images
                for img in item.get("images", []):
                    src = img.get("src", "")
                    if src and self.allowed_host in src:
                        self._enqueue(src, 0)
                # Archive files embedded in description HTML
                desc = item.get("description", "") + item.get("short_description", "")
                for m in _arch_re.finditer(desc):
                    link = m.group(0)
                    if self.allowed_host in link:
                        self._enqueue(link, 0, priority=True)
                        file_total += 1
            if len(items) < 100:
                break
            page += 1
            time.sleep(self.delay)

        if product_total:
            log.info("[WC] Discovered %d product pages, %d archive links",
                     product_total, file_total)

        # Probe WooCommerce uploads sub-directories for archive files.
        # woocommerce_uploads/ is protected by robots.txt but we probe it
        # when robots is disabled or when download_extensions is set.
        if self.download_extensions:
            self._probe_wc_uploads()

    def _probe_wc_uploads(self) -> None:
        """Probe wp-content/uploads/woocommerce_uploads/ with recent
        year/month paths to discover directly accessible firmware ZIPs."""
        import datetime as _dt
        now = _dt.datetime.now()
        # Probe the last 18 months
        paths_to_probe: list[str] = []
        for delta in range(18):
            month = (now.month - delta - 1) % 12 + 1
            year = now.year - ((now.month - delta - 1) // 12)
            for base_dir in (
                f"/wp-content/uploads/woocommerce_uploads/{year}/{month:02d}/",
                f"/wp-content/uploads/{year}/{month:02d}/",
            ):
                paths_to_probe.append(base_dir)

        probed = 0
        for path in paths_to_probe:
            try:
                r = self.session.get(
                    self.base + path,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
            except _NETWORK_ERRORS:
                continue
            if not r.ok:
                continue
            # Extract archive links from directory listing HTML
            import re as _re2
            ct = r.headers.get("Content-Type", "")
            if "html" not in ct.lower():
                continue
            for m in _re2.finditer(
                r'href=["\']([^"\']*\.(?:zip|rar|7z|bin|tar\.gz|tar|gz|bz2'
                r'|xz|exe|img|iso|hwnp|fwu|pkg'
                r'|mp4|webm|ogv|avi|mov|flv|mkv|wmv|m4v|3gp|3g2'
                r'|ts|mpeg|mpg|f4v|asf|vob|m2ts|mts'
                r'|mp3|ogg|wav|flac|aac|m4a|weba'
                r'|m3u8|mpd))["\']',
                r.text, _re2.I,
            ):
                link = urllib.parse.urljoin(self.base + path, m.group(1))
                if self.allowed_host in link:
                    self._enqueue(link, 0, priority=True)
                    probed += 1
        if probed:
            log.info("[WC-UPLOADS] Found %d archive files in uploads dirs",
                     probed)

    # ------------------------------------------------------------------
    # Androidacy Magisk module repository discovery
    # ------------------------------------------------------------------

    # Third-party module repository API endpoints discovered by analysing
    # the Androidacy WordPress plugin (``apipl``) and its companion SPA at
    # ``production-api.androidacy.com``.
    _ANDROIDACY_REPO_URL = (
        "https://production-api.androidacy.com/magisk/repo"
    )
    _MMRL_ALT_REPO_URL = (
        "https://magisk-modules-alt-repo.github.io/json-v2/json/modules.json"
    )

    def _discover_androidacy_repo(self) -> None:
        """Discover Magisk module repositories used by Androidacy sites.

        Androidacy (``www.androidacy.com``) is a WordPress site that hosts
        a Magisk module repository.  The modules are served by a separate
        Laravel API at ``production-api.androidacy.com`` and also mirrored
        on the public Magisk Modules Alt Repo (GitHub Pages).

        This method:
        1. Fetches the production API ``/magisk/repo`` JSON (118+ modules).
        2. Fetches the MMRL Alt Repo ``modules.json`` (119+ modules with
           direct ZIP download URLs from GitHub Pages).
        3. Enqueues every discoverable URL: module pages, support links,
           donation pages, README endpoints, and ZIP download URLs.
        """
        base_host = urllib.parse.urlparse(self.base).netloc
        if not (base_host == "androidacy.com"
                or base_host.endswith(".androidacy.com")):
            return

        total_urls = 0

        # ── 1. Production API module repository ─────────────────────
        try:
            resp = self.session.get(
                self._ANDROIDACY_REPO_URL, timeout=REQUEST_TIMEOUT,
            )
        except _NETWORK_ERRORS:
            resp = None

        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                data = {}
            modules = data.get("data", [])
            if isinstance(modules, list):
                for mod in modules:
                    # Enqueue the module's web page on the WP site
                    url = mod.get("url", "")
                    if url and self.allowed_host in url:
                        # Strip hash fragment for the queue
                        clean = url.split("#")[0]
                        self._enqueue(clean, 1)
                        total_urls += 1
                    # Support / donate / website links (external)
                    for key in ("support", "donate", "website"):
                        ext = mod.get(key, "")
                        if ext and ext.startswith("http"):
                            self._enqueue(ext, 2)
                            total_urls += 1
                log.info(
                    "[ANDROIDACY] Production API: %d modules, "
                    "%d URLs enqueued",
                    len(modules), total_urls,
                )

        # ── 2. MMRL Alt Repo (public GitHub Pages with ZIPs) ────────
        alt_total = 0
        try:
            alt_resp = self.session.get(
                self._MMRL_ALT_REPO_URL, timeout=REQUEST_TIMEOUT,
            )
        except _NETWORK_ERRORS:
            alt_resp = None

        if alt_resp is not None and alt_resp.status_code == 200:
            try:
                alt_data = alt_resp.json()
            except ValueError:
                alt_data = {}
            alt_mods = alt_data.get("modules", [])
            if isinstance(alt_mods, list):
                for mod in alt_mods:
                    # GitHub source repository
                    track = mod.get("track", {})
                    source = track.get("source", "")
                    if source and source.startswith("http"):
                        self._enqueue(source.rstrip(".git"), 2)
                        alt_total += 1
                    # Direct ZIP downloads (GitHub Pages hosted)
                    for ver in mod.get("versions", []):
                        zip_url = ver.get("zipUrl", "")
                        if zip_url and zip_url.startswith("http"):
                            self._enqueue(zip_url, 2)
                            alt_total += 1
                        # Changelog markdown
                        cl = ver.get("changelog", "")
                        if cl and cl.startswith("http"):
                            self._enqueue(cl, 2)
                            alt_total += 1
                    # Support / donate links
                    for key in ("support", "donate"):
                        ext = mod.get(key, "")
                        if ext and ext.startswith("http"):
                            self._enqueue(ext, 2)
                            alt_total += 1
                if alt_total:
                    log.info(
                        "[ANDROIDACY] Alt Repo: %d modules, "
                        "%d URLs enqueued (incl. ZIP downloads)",
                        len(alt_mods), alt_total,
                    )

        total_urls += alt_total
        if total_urls:
            log.info(
                "[ANDROIDACY] Total: %d URLs discovered across "
                "all module repositories",
                total_urls,
            )

    def _deep_crawl_wp_plugin(self, slug: str, depth: int) -> None:
        """Enqueue internal files for a confirmed WordPress plugin."""
        if slug in self._wp_confirmed_plugins:
            return
        self._wp_confirmed_plugins.add(slug)
        base_path = f"/wp-content/plugins/{slug}/"
        for f in WP_PLUGIN_FILES:
            self._enqueue(self.base + base_path + f, depth + 1)
        log.debug("  [WP-PLUGIN] Deep-crawling plugin '%s' (%d files)",
                 slug, len(WP_PLUGIN_FILES))

    def _deep_crawl_wp_theme(self, slug: str, depth: int) -> None:
        """Enqueue internal files for a confirmed WordPress theme."""
        if slug in self._wp_confirmed_themes:
            return
        self._wp_confirmed_themes.add(slug)
        base_path = f"/wp-content/themes/{slug}/"
        for f in WP_THEME_FILES:
            self._enqueue(self.base + base_path + f, depth + 1)
        log.debug("  [WP-THEME] Deep-crawling theme '%s' (%d files)",
                 slug, len(WP_THEME_FILES))

    # ------------------------------------------------------------------
    # WAF / Cloudflare / CAPTCHA detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_protection(headers: dict[str, str], body: str) -> list[str]:
        """Return a list of detected WAF/protection names from *headers* and
        *body* content.

        Only the first 8 KB of the body is inspected.  Real challenge /
        CAPTCHA pages are small and put indicators near the top, while
        large content pages may mention "captcha" or "cloudflare" deep
        in plugin configuration strings, causing false positives.
        """
        # Exclude Permissions-Policy – it merely declares allowed origins
        # (e.g. recaptcha.net, cloudflare.com) and is not a WAF indicator.
        filtered = {k: v for k, v in headers.items()
                    if k.lower() != "permissions-policy"}
        combined = " ".join(f"{k}: {v}" for k, v in filtered.items()).lower()
        combined += " " + body[:8192].lower()
        detected: list[str] = []
        for name, sigs in WAF_SIGNATURES.items():
            if any(s in combined for s in sigs):
                detected.append(name)
        return detected

    # ------------------------------------------------------------------
    # Header-rotation retry for 403 / 402
    # ------------------------------------------------------------------

    def _retry_with_headers(
        self, url: str
    ) -> requests.Response | None:
        """Retry *url* up to HEADER_RETRY_MAX times with different header
        profiles, cache-busted URLs, and Cloudflare-aware techniques.
        Returns a successful response or ``None``."""
        for attempt in range(1, HEADER_RETRY_MAX + 1):
            hdrs = random_headers(self.base)
            # Use cache-busted URL to bypass CDN/proxy cached 403
            bust_url = cache_bust_url(url)
            try:
                resp = self.session.get(
                    bust_url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                    headers=hdrs,
                )
                if resp.ok and not is_sg_captcha_response(resp):
                    log.debug(
                        "  [RETRY %d/%d] OK for %s (UA: %s…)",
                        attempt, HEADER_RETRY_MAX, url,
                        hdrs["User-Agent"][:40],
                    )
                    self._stats["retry_ok"] += 1
                    return resp
                # Cloudflare cookie-based challenge: first request sets
                # cf_clearance cookie, second request should succeed
                if not self._cf_bypass_done and resp.status_code == 403:
                    cf_cookies = {c.name for c in self.session.cookies
                                  if "cf" in c.name.lower()
                                  or "clearance" in c.name.lower()}
                    if cf_cookies:
                        self._cf_bypass_done = True
                        log.debug("  Cloudflare cookies found (%s), retrying",
                                  ", ".join(cf_cookies))
                        time.sleep(self.delay * 2)
                        resp2 = self.session.get(
                            url, timeout=REQUEST_TIMEOUT,
                            allow_redirects=True, headers=hdrs,
                        )
                        if resp2.ok:
                            self._stats["retry_ok"] += 1
                            log.debug("  [CF-BYPASS] Succeeded for %s", url)
                            return resp2
                log.debug(
                    "  [RETRY %d/%d] HTTP %s for %s",
                    attempt, HEADER_RETRY_MAX, resp.status_code, url,
                )
            except _NETWORK_ERRORS:
                pass
            time.sleep(self.delay * attempt)
        return None

    # ------------------------------------------------------------------
    # 429 exponential backoff
    # ------------------------------------------------------------------

    def _handle_rate_limit(self, resp: requests.Response, url: str) -> None:
        """Sleep with exponential backoff when a 429 is received."""
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            wait = min(int(retry_after), BACKOFF_429_MAX)
        else:
            wait = BACKOFF_429_BASE
        log.warning(
            "  [429] Rate limited on %s – sleeping %.1f s", url, wait
        )
        time.sleep(wait)

    _DISK_CT: dict[str, str] = {
        ".html": "text/html",
        ".htm":  "text/html",
        ".asp":  "text/html",
        ".aspx": "text/html",
        ".jsp":  "text/html",
        ".php":  "text/html",
        ".txt":  "text/plain",
        ".js":   "application/javascript",
        ".mjs":  "application/javascript",
        ".cjs":  "application/javascript",
        ".ts":   "application/javascript",
        ".jsx":  "application/javascript",
        ".tsx":  "application/javascript",
        ".css":  "text/css",
        ".scss": "text/css",
        ".sass": "text/css",
        ".less": "text/css",
        ".json": "application/json",
        ".xml":  "application/xml",
        ".svg":  "application/xml",
        ".rss":  "application/xml",
        ".atom": "application/xml",
        ".env":  "text/plain",
        ".cfg":  "text/plain",
        ".conf": "text/plain",
        ".config": "text/plain",
        ".hst":  "text/plain",
        ".ini":  "text/plain",
        ".toml": "text/plain",
        ".yml":  "text/plain",
        ".yaml": "text/plain",
        ".log":  "text/plain",
        ".sql":  "text/plain",
        ".csv":  "text/plain",
        ".tsv":  "text/plain",
        ".md":   "text/plain",
        ".rst":  "text/plain",
        ".py":   "text/plain",
        ".rb":   "text/plain",
        ".pl":   "text/plain",
        ".sh":   "text/plain",
        ".bat":  "text/plain",
        ".ps1":  "text/plain",
        ".lua":  "text/plain",
        ".go":   "text/plain",
        ".rs":   "text/plain",
        ".java": "text/plain",
        ".c":    "text/plain",
        ".cpp":  "text/plain",
        ".h":    "text/plain",
        ".vue":  "text/html",
        ".svelte": "text/html",
        ".htaccess": "text/plain",
        ".htpasswd": "text/plain",
        ".gitignore": "text/plain",
        ".dockerignore": "text/plain",
        ".editorconfig": "text/plain",
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

    def _enqueue(self, url: str, depth: int, *, priority: bool = False) -> None:
        """Add *url* to the queue if not yet visited and within scope.

        When *priority* is ``True`` the URL is pushed to the front of
        the queue so that real-content pages are processed before
        speculative probe URLs.  URLs matching ``download_extensions``
        are always prioritized.
        """
        key = url_key(url)
        with self._lock:
            if key in self._visited:
                return
            # Only crawl URLs on the same host or allowed CDN hosts
            parsed = urllib.parse.urlparse(url)
            is_cdn = parsed.netloc in self._cdn_hosts
            if parsed.netloc != self.allowed_host and not is_cdn:
                return
            # Reject glob/wildcard patterns (e.g. extracted from
            # <script type="speculationrules"> exclusion lists).
            # '*' is not a valid character in an HTTP request path.
            if "*" in parsed.path:
                return
            # Skip extensions that SiteGround's WAF always blocks with 403.
            # Probing these wastes requests and inflates error counters.
            path_lower_eq = parsed.path.lower()
            if any(path_lower_eq.endswith(ext)
                   for ext in SITEGROUND_BLOCKED_EXTENSIONS):
                return
            # Block known bad URL patterns early (before scheme enforcement)
            if BLOCKED_PATH_RE.search(parsed.path):
                return
            # Enforce the base scheme (upgrade http → https when base is https)
            # so every request uses the protocol the server expects and the
            # session cookie (e.g. SG-CAPTCHA bypass) is always included.
            base_parsed = urllib.parse.urlparse(self.base)
            if parsed.scheme != base_parsed.scheme:
                url = urllib.parse.urlunparse(
                    (base_parsed.scheme,) + urllib.parse.urlparse(url)[1:]
                )
                key = url_key(url)
                if key in self._visited:
                    return
            if self.max_depth and depth > self.max_depth:
                # CDN URLs bypass depth limits – they are terminal
                # downloads (no link extraction) and would otherwise
                # be unreachable when discovered at the depth boundary.
                if not is_cdn:
                    return
            # Queue size cap – prevent unbounded memory growth on sites
            # whose REST API / pagination generates an ever-expanding
            # set of discovery URLs.  Priority URLs (target extension
            # downloads, CF retries) bypass the soft cap but are bounded
            # by a hard cap at 2× to ensure high-value targets are not
            # lost while still preventing runaway growth.
            qlen = len(self._queue)
            if qlen >= MAX_QUEUE_SIZE:
                if not priority or qlen >= MAX_QUEUE_SIZE * 2:
                    return
            # Auto-prioritize target extension files
            if not priority and self.download_extensions:
                path_lower = parsed.path.lower()
                if any(path_lower.endswith(ext) for ext in self.download_extensions):
                    priority = True
            if priority:
                self._queue.appendleft((url, depth))
            else:
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

    # Size threshold for automatic Git LFS tracking (50 MB)
    _LFS_SIZE_THRESHOLD = 50 * 1024 * 1024

    def _git_lfs_track_large_files(self, cwd: str) -> None:
        """Find files > 50 MB and track them with Git LFS."""
        out_dir = Path(cwd)
        tracked_any = False
        for f in out_dir.rglob("*"):
            if not f.is_file() or ".git" in f.parts:
                continue
            try:
                if f.stat().st_size > self._LFS_SIZE_THRESHOLD:
                    rel = f.relative_to(out_dir)
                    subprocess.run(
                        ["git", "lfs", "track", str(rel)],
                        cwd=cwd, capture_output=True, timeout=15,
                    )
                    log.debug("[GIT-LFS] Tracking %s (%.0f MB)",
                              rel, f.stat().st_size / (1024 * 1024))
                    tracked_any = True
            except (OSError, subprocess.SubprocessError):
                continue
        if tracked_any:
            gitattr = out_dir / ".gitattributes"
            if gitattr.exists():
                subprocess.run(
                    ["git", "add", ".gitattributes"],
                    cwd=cwd, capture_output=True, timeout=15,
                )

    def _maybe_git_push(self) -> None:
        """Commit and push progress every *git_push_every* saved files.

        When *upload_extensions* is set, only files matching those
        extensions (plus README.md) are staged.  When debug mode is
        active, ``.headers`` files are included too.

        Files exceeding 50 MB are automatically tracked with Git LFS.
        """
        if self.git_push_every <= 0:
            return
        if self._stats["ok"] % self.git_push_every != 0:
            return

        # Update URL lists before pushing so they are included in the commit
        self._write_url_list()
        self._write_video_url_list()

        ok = self._stats["ok"]
        log.info("[GIT] Pushing progress (%d files saved so far)…", ok)
        try:
            cwd = str(self.output_dir.resolve())
            # Track large files with Git LFS before staging
            self._git_lfs_track_large_files(cwd)
            if self.upload_extensions:
                # Stage only files matching the upload extensions
                subprocess.run(
                    ["git", "add", "README.md"],
                    cwd=cwd, capture_output=True, timeout=30,
                )
                # Stage URL list files when they exist
                for txt in ("url_list.txt", "video_urls.txt"):
                    if (self.output_dir / txt).exists():
                        subprocess.run(
                            ["git", "add", "--", txt],
                            cwd=cwd, capture_output=True, timeout=30,
                        )
                for ext in self.upload_extensions:
                    args = ["git", "add", "--", f"*{ext}"]
                    if self.debug:
                        args.append(f"*{ext}.headers")
                    subprocess.run(
                        args,
                        cwd=cwd, capture_output=True, timeout=60,
                    )
            else:
                subprocess.run(
                    ["git", "add", "-A"],
                    cwd=cwd, check=True, capture_output=True, timeout=60,
                )
            subprocess.run(
                ["git", "commit", "-m",
                 f"Crawl progress: {ok} files saved"],
                cwd=cwd, check=True, capture_output=True, timeout=60,
            )
            subprocess.run(
                ["git", "push"],
                cwd=cwd, check=True, capture_output=True, timeout=300,
            )
            log.info("[GIT] Push OK (%d files)", ok)
        except subprocess.CalledProcessError as exc:
            msg = exc.stderr.decode(errors="replace").strip() if exc.stderr else str(exc)
            log.warning("[GIT] Push failed: %s", msg)
        except FileNotFoundError:
            log.warning("[GIT] git not found – disabling periodic push")
            self.git_push_every = 0
        except Exception as exc:
            log.warning("[GIT] Push error: %s", exc)

    @staticmethod
    def _dir_from_url(url: str) -> str:
        """Derive the directory path from a URL for probe tracking."""
        path = urllib.parse.urlparse(url).path
        if path.endswith("/"):
            return path
        return path.rsplit("/", 1)[0] + "/" or "/"

    def _probe_hidden_files(self, url: str, depth: int) -> None:
        """Enqueue hidden/config files for every new directory discovered."""
        if self._probing_disabled:
            return

        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        # Derive directory: strip filename if path doesn't end with /
        if path.endswith("/"):
            dir_path = path
        else:
            dir_path = path.rsplit("/", 1)[0] + "/"
        if not dir_path:
            dir_path = "/"

        with self._lock:
            if dir_path in self._probed_dirs:
                return
            self._probed_dirs.add(dir_path)

        enqueued = 0
        for probe in HIDDEN_FILE_PROBES:
            # Skip probes whose extension is blocked by SiteGround WAF
            # to avoid inflating error/probe counters with guaranteed 403s
            probe_lower = probe.lower()
            if any(probe_lower.endswith(ext)
                   for ext in SITEGROUND_BLOCKED_EXTENSIONS):
                continue
            probe_url = self.base + dir_path + probe
            with self._lock:
                self._probe_urls.add(url_key(probe_url))
            self._enqueue(probe_url, depth + 1)
            enqueued += 1

        log.debug("Probed %d hidden files at %s", enqueued, dir_path)

    def _fetch_and_process(self, url: str, depth: int) -> None:
        key = url_key(url)
        with self._lock:
            if key in self._visited:
                return
            self._visited.add(key)

        parsed_url = urllib.parse.urlparse(url)
        is_cdn_url = parsed_url.netloc in self._cdn_hosts

        # CDN URLs: download-only fast path (no probing, no robots, no
        # link extraction).  Always streamed to disk.
        if is_cdn_url:
            self._fetch_cdn_media(url)
            return

        # Early skip for probe URLs whose directory already exhausted
        is_probe_early = key in self._probe_urls
        if is_probe_early:
            probe_dir = self._dir_from_url(url)
            with self._lock:
                dir_fails = self._probe_dir_failures.get(probe_dir, 0)
            if dir_fails >= PROBE_DIR_404_LIMIT:
                log.debug("[PROBE] Dir %s exhausted (%d fails) – skipping %s",
                          probe_dir, dir_fails, url)
                self._stats["probe"] += 1
                return

        # Probe hidden/config files at each new directory
        self._probe_hidden_files(url, depth)

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

        # Load cached HTTP headers (ETag / Last-Modified) for conditional
        # requests so we can avoid re-downloading unchanged resources.
        _cached_headers: dict[str, str] = {}
        _headers_path = local.parent / (local.name + ".headers")
        if not self.force and _headers_path.exists():
            try:
                _cached_headers = json.loads(
                    _headers_path.read_text(encoding="utf-8")
                ).get("headers", {})
            except Exception:
                pass

        # Skip already-downloaded files (no force, file on disk).
        # If a cached ETag or Last-Modified is available we will make a
        # conditional request instead of a hard skip so that changed
        # resources are refreshed.
        _has_validators = bool(
            _cached_headers.get("ETag") or _cached_headers.get("Last-Modified")
        )
        if not self.force and local.exists() and local.stat().st_size > 0:
            if not _has_validators:
                log.debug("[SKIP] Already on disk: %s", url)
                self._stats["skip"] += 1
                added = self._parse_local_file(local, url)
                if added:
                    log.debug("  +%d new URLs from cached %s", added, local.name)
                return
            # Fall through to make a conditional request

        log.debug("[Q:%d OK:%d ERR:%d] GET %s",
                 len(self._queue), self._stats["ok"], self._stats["err"], url)

        # Rotate User-Agent per request (skip for curl_cffi which
        # manages its own UA via TLS impersonation).
        # For rsddownload-secure.lenovo.com (S3 bucket), use the exact UA that
        # the LMSA HttpDownload.OpenRequest() uses (GlobalVar.UserAgent = IE8).
        if not self._cf_bypass_done:
            parsed_host = urllib.parse.urlparse(url).netloc.lower()
            if "rsddownload" in parsed_host and "lenovo.com" in parsed_host:
                from web_crawler.auth.lmsa import DOWNLOAD_USER_AGENT as _S3_UA
                self.session.headers["User-Agent"] = _S3_UA
            else:
                self.session.headers["User-Agent"] = random.choice(USER_AGENTS)

        # Build conditional request headers from cached ETag / Last-Modified
        _conditional: dict[str, str] = {}
        if _has_validators:
            if _cached_headers.get("ETag"):
                _conditional["If-None-Match"] = _cached_headers["ETag"]
            if _cached_headers.get("Last-Modified"):
                _conditional["If-Modified-Since"] = _cached_headers["Last-Modified"]

        # Use streaming mode for URLs that look like large binary files so we
        # don't buffer the entire response in RAM before saving to disk.
        _path_lower_pre = urllib.parse.urlparse(url).path.lower()
        _use_stream = any(
            _path_lower_pre.endswith(ext)
            for ext in (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
                        ".xz", ".bin", ".exe", ".img", ".iso",
                        ".hwnp", ".fwu", ".pkg",
                        ".mp4", ".webm", ".ogv", ".avi", ".mov",
                        ".flv", ".mkv", ".wmv", ".m4v", ".3gp",
                        ".3g2", ".ts", ".mpeg", ".mpg", ".f4v",
                        ".asf", ".vob", ".m2ts", ".mts",
                        ".mp3", ".ogg", ".wav", ".flac", ".aac",
                        ".m4a", ".weba")
        )

        try:
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                stream=_use_stream,
                headers=_conditional if _conditional else None,
            )
        except _NETWORK_ERRORS as exc:
            # Re-enqueue on transient network errors up to MAX_URL_RETRIES
            with self._lock:
                retries = self._url_retries.get(key, 0)
                if retries < MAX_URL_RETRIES:
                    self._url_retries[key] = retries + 1
                    self._visited.discard(key)
                    can_retry = True
                else:
                    can_retry = False
            if can_retry:
                self._enqueue(url, depth)
                log.debug("Request failed for %s – retry %d/%d – %s",
                          url, retries + 1, MAX_URL_RETRIES, exc)
                return
            log.warning("Request failed for %s – %s", url, exc)
            self._stats["err"] += 1
            return

        # Track final URL after redirects to avoid re-crawling
        final_url = resp.url
        if final_url != url:
            final_parsed = urllib.parse.urlparse(final_url)
            # Reject cross-domain redirects
            if final_parsed.netloc != self.allowed_host:
                log.debug("  Redirect to external host %s – skipping",
                          final_parsed.netloc)
                self._stats["skip"] += 1
                return
            # WordPress protection: redirect to wp-login.php means
            # the page requires authentication – save the redirect
            # target but don't treat as error
            if "wp-login.php" in final_parsed.path:
                log.debug("  WP auth redirect to wp-login.php – skipping %s",
                          url)
                self._stats["skip"] += 1
                return
            # Mark the final URL as visited too
            final_key = url_key(final_url)
            self._visited.add(final_key)
            log.debug("  Redirect: %s → %s", url, final_url)

        # Handle 304 Not Modified – cached copy is still current
        if resp.status_code == 304:
            log.debug("[304] Not modified – reusing cached: %s", url)
            self._stats["skip"] += 1
            if local.exists():
                added = self._parse_local_file(local, url)
                if added:
                    log.debug("  +%d new URLs from 304 cache %s", added, local.name)
            return

        # Handle 429 (rate limiting) with exponential backoff + re-enqueue
        if resp.status_code == 429:
            self._handle_rate_limit(resp, url)
            self._visited.discard(key)
            self._enqueue(url, depth)
            return

        is_probe = key in self._probe_urls

        # Handle 403 / 402 – retry with rotated headers + cache busting
        if resp.status_code in RETRY_STATUS_CODES:
            # Cloudflare Managed Challenge – re-solve with Playwright/curl_cffi.
            # CF challenge pages are JS-rendered stubs with no real content;
            # saving them is pointless, so keep the existing re-solve logic.
            if is_cf_managed_challenge(resp):
                log.info("[CF] Challenge on %s – re-solving …", url)
                if self._solve_cf_and_inject():
                    self._visited.discard(key)
                    self._enqueue(url, depth, priority=True)
                    return
                # Could not bypass CF – fall through to save the CF page body
                log.debug("  [CF] Bypass failed – saving CF page body: %s", url)

            # Skip expensive retries for speculative probe URLs
            elif is_probe:
                self._probe_403_count += 1
                # Track per-directory failures
                probe_dir = self._dir_from_url(url)
                with self._lock:
                    self._probe_dir_failures[probe_dir] = (
                        self._probe_dir_failures.get(probe_dir, 0) + 1
                    )
                if (self._probe_403_count >= PROBE_403_THRESHOLD
                        and not self._probing_disabled):
                    self._probing_disabled = True
                    log.info(
                        "[PROBE] %d consecutive 403s – disabling hidden-file "
                        "probing for remaining directories",
                        self._probe_403_count,
                    )
                log.debug("  [PROBE] 403 for %s – skipping (no retry)", url)
                self._stats["probe"] += 1
                return

            # Amazon S3 private-bucket AccessDenied — enforced at the bucket
            # policy level.  No header trick can bypass it; skip retries and
            # count as restricted (the XML error body is saved below).
            elif is_s3_access_denied(resp):
                log.info(
                    "[S3-403] Private bucket – saving AccessDenied body: %s",
                    url,
                )
                self._stats["restricted"] += 1
                # Disable probing immediately — S3 buckets never expose
                # hidden files at public paths; every probe URL would 403.
                if not self._probing_disabled:
                    self._probing_disabled = True
                    log.info(
                        "[S3-403] Disabling hidden-file probing "
                        "(S3 bucket – all probe paths return 403)"
                    )
                # Fall through to content-saving code

            # Tomcat IP-restriction: detected by a distinctive body phrase.
            # Header rotation never helps for server-level IP whitelists, so
            # skip retries entirely and fall through to save the HTML body
            # (which IS real content – the Tomcat "access denied" error page).
            elif is_tomcat_ip_restricted(resp):
                log.info(
                    "[TOMCAT-403] IP-restricted page – saving body: %s", url
                )
                self._stats["restricted"] += 1
                # Fall through to the content-saving code below

            else:
                # Rotate headers and retry.  If the retry succeeds the new
                # response replaces resp and processing continues normally.
                # If all retries fail we fall through to save whatever HTML
                # body the server returned rather than discarding it.
                log.debug("  [%d] Blocked – retrying with rotated headers: %s",
                         resp.status_code, url)
                retry_resp = self._retry_with_headers(url)
                if retry_resp is not None:
                    resp = retry_resp
                else:
                    # All retries exhausted.
                    body_text = resp.content.decode("utf-8", errors="replace")
                    if is_sg_captcha_response(resp):
                        # Serialize to avoid concurrent PoW solves.
                        with self._sg_solve_lock:
                            if solve_sg_captcha(self.session, self.base,
                                                parsed_url.path):
                                try:
                                    retry_resp = self.session.get(
                                        url, timeout=REQUEST_TIMEOUT,
                                        allow_redirects=True,
                                    )
                                except _NETWORK_ERRORS:
                                    retry_resp = None
                                if (retry_resp is not None and retry_resp.ok
                                        and not is_sg_captcha_response(retry_resp)):
                                    log.debug(
                                        "  [SG-CAPTCHA] Solved 403 for %s", url
                                    )
                                    resp = retry_resp
                                else:
                                    # CAPTCHA page is not real content – skip
                                    self._stats["err"] += 1
                                    return
                            else:
                                log.warning(
                                    "  [SG-CAPTCHA] Failed to solve for %s", url
                                )
                                self._stats["err"] += 1
                                return
                    else:
                        # Not a CAPTCHA.  Detect WAF type for logging, but
                        # always fall through to save the HTML response body –
                        # the server DID return content, even if access is
                        # restricted.
                        protections = self.detect_protection(
                            dict(resp.headers), body_text
                        )
                        if protections:
                            log.info(
                                "  [WAF-%s] Saving body despite protection: %s",
                                "+".join(protections), url,
                            )
                            self._stats["waf"] += 1
                        else:
                            log.info(
                                "  [403] Saving body for restricted page: %s",
                                url,
                            )
                        self._stats["restricted"] += 1
                        # Fall through to content-saving code

        # Reset probe 403/404 streak on any successful probe response
        if is_probe and resp.ok:
            self._probe_403_count = 0
            self._probe_404_count = 0

        if not resp.ok:
            # For probe URLs returning 404, demote to debug and track
            # separately to avoid flooding logs with expected misses.
            if is_probe and resp.status_code == 404:
                self._probe_404_count += 1
                # Track per-directory failures so remaining probes for this
                # directory can be skipped without making HTTP requests.
                probe_dir = self._dir_from_url(url)
                with self._lock:
                    self._probe_dir_failures[probe_dir] = (
                        self._probe_dir_failures.get(probe_dir, 0) + 1
                    )
                if (self._probe_404_count >= PROBE_404_THRESHOLD
                        and not self._probing_disabled):
                    self._probing_disabled = True
                    log.info(
                        "[PROBE] %d consecutive 404s – disabling hidden-file "
                        "probing for remaining directories",
                        self._probe_404_count,
                    )
                log.debug("  [PROBE] 404 for %s – skipping", url)
                self._stats["probe"] += 1
                return
            # For non-probe 4xx/5xx responses that have an HTML body, fall
            # through to save the content – the response IS a page (error or
            # access-denied), and skipping it loses information.
            ct_check = resp.headers.get("Content-Type", "").lower()
            if "html" not in ct_check or not resp.content:
                log.warning("HTTP %s for %s – skipping (no HTML body)",
                            resp.status_code, url)
                self._stats["err"] += 1
                return
            log.debug("  [%s] HTML body present – saving: %s",
                      resp.status_code, url)

        # SG-Captcha challenge: solve the PoW and retry the request
        # to get the real content behind the captcha.
        if is_sg_captcha_response(resp):
            # For probe URLs, treat SG-Captcha like a 403 – the file
            # almost certainly doesn't exist; solving PoW individually
            # for each probe is too slow.
            if is_probe:
                self._probe_403_count += 1
                # Track per-directory failures
                probe_dir = self._dir_from_url(url)
                with self._lock:
                    self._probe_dir_failures[probe_dir] = (
                        self._probe_dir_failures.get(probe_dir, 0) + 1
                    )
                log.debug("  [PROBE] SG-Captcha for %s – skipping", url)
                self._stats["probe"] += 1
                return

            # Limit inline captcha solves to avoid endless PoW loops
            # when the server keeps re-challenging.
            if self._sg_captcha_solves >= PROBE_403_THRESHOLD:
                log.debug("  [SG-CAPTCHA] Solve limit reached – skipping %s",
                          url)
                self._stats["err"] += 1
                return

            # Serialize CAPTCHA solves: only one worker at a time.
            # When concurrent workers all hit the CAPTCHA, each would
            # independently spend ~20s solving PoW.  With the lock,
            # one worker solves while others wait, then re-try using
            # the shared bypass cookie.
            with self._sg_solve_lock:
                # Re-check: another worker may have solved while we waited
                try:
                    resp = self.session.get(
                        url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                    )
                except _NETWORK_ERRORS:
                    self._stats["err"] += 1
                    return
                if not is_sg_captcha_response(resp):
                    log.debug("  [SG-CAPTCHA] Bypassed via shared cookie: %s",
                              url)
                    # Fall through to normal processing below
                else:
                    log.debug("  [SG-CAPTCHA] Challenge for %s – solving …",
                              url)
                    solved = solve_sg_captcha(
                        self.session, self.base, parsed_url.path,
                    )
                    self._sg_captcha_solves += 1
                    if solved:
                        time.sleep(self.delay * 2)
                        try:
                            resp = self.session.get(
                                url, timeout=REQUEST_TIMEOUT,
                                allow_redirects=True,
                            )
                        except _NETWORK_ERRORS:
                            self._stats["err"] += 1
                            return
                        if is_sg_captcha_response(resp):
                            log.warning(
                                "  [SG-CAPTCHA] Still blocked after solve: "
                                "HTTP %s for %s", resp.status_code, url)
                            self._stats["err"] += 1
                            return
                        log.debug("  [SG-CAPTCHA] Solved – got HTTP %s for %s",
                                  resp.status_code, url)
                        self._sg_captcha_solves = 0
                    else:
                        log.warning("  [SG-CAPTCHA] Failed to solve for %s",
                                    url)
                        self._stats["waf"] += 1
                        return

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        content_disp = resp.headers.get("Content-Disposition", "")
        ct_lower = content_type.split(";")[0].strip().lower()

        # Decide whether to stream this response or buffer it.
        # Stream when: Content-Type is a known binary type, or the server
        # sent Content-Disposition: attachment (explicit download signal),
        # or the request was already made in stream mode.
        _is_binary = (
            ct_lower in BINARY_CONTENT_TYPES
            or content_disp.lower().startswith("attachment")
        )
        if _use_stream or _is_binary:
            # Skip media files if requested – record URL but don't download
            if self.skip_media_files and (
                self._is_media_url(url) or self._is_media_content_type(ct_lower)
            ):
                with self._lock:
                    self._track_video_url(url)
                    self._stats["skip"] += 1
                log.info("  [SKIP-MEDIA] %s (media file skipped)", url)
                resp.close()

            # Skip-download: record a ready-to-run curl command instead
            url_ext = urllib.parse.urlparse(url).path.rsplit(".", 1)[-1].lower()
            if (
                self.skip_download_exts
                and url_ext in self.skip_download_exts
            ):
                with self._lock:
                    self._record_download_link(url)
                    self._stats["skip"] += 1
                log.info("  [SKIP-DOWNLOAD] %s (link recorded, not downloaded)", url)
                resp.close()
                time.sleep(self.delay)
                return
                time.sleep(self.delay)
                return

            # Streaming path: write chunks directly to disk, read first chunk
            # only for WAF/SG-CAPTCHA checks on unexpected HTML responses.
            local_stream = smart_local_path(url, self.output_dir,
                                            content_type, content_disp)
            try:
                chunks = resp.iter_content(chunk_size=524288)
                first_chunk = next(chunks, b"")
            except _NETWORK_ERRORS as exc:
                log.warning("  Stream error for %s – %s", url, exc)
                self._stats["err"] += 1
                return

            # If the first chunk looks like HTML (unexpected WAF/CAPTCHA page),
            # fall back to in-memory handling so protection checks can run.
            if ct_lower in ("text/html", "application/xhtml+xml"):
                remaining = b"".join(chunks)
                content: bytes = first_chunk + remaining
            else:
                # Pure binary – deduplicate using on-disk streaming hash
                content_size_hint = int(
                    resp.headers.get("Content-Length", "0") or "0"
                )
                _size_mb = (content_size_hint or len(first_chunk)) / (1024 * 1024)
                with self._lock:
                    # Optimistic lock: skip dup check for now, verify after write
                    pass
                local_stream.parent.mkdir(parents=True, exist_ok=True)
                written = len(first_chunk)
                with local_stream.open("wb") as fh:
                    fh.write(first_chunk)
                    for chunk in chunks:
                        if chunk:
                            fh.write(chunk)
                            written += len(chunk)
                ch = file_content_hash(local_stream)
                with self._lock:
                    if ch in self._hashes:
                        log.debug(
                            "  Duplicate binary for %s – removing extra copy",
                            url,
                        )
                        local_stream.unlink(missing_ok=True)
                        self._stats["dup"] += 1
                    else:
                        self._hashes.add(ch)
                        log.info(
                            "  [DOWNLOAD] %s → %s (%.1f MiB)",
                            url, local_stream.name, written / (1024 * 1024),
                        )
                        self._stats["ok"] += 1
                        self._saved_urls.append(url)
                        self._track_video_url(url)
                        if self.debug:
                            self._save_http_headers(local_stream, resp, url)
                        self._maybe_git_push()
                time.sleep(self.delay)
                return
        else:
            content = resp.content

        log.debug(
            "  ← HTTP %s  CT: %s  %d bytes",
            resp.status_code, content_type, len(content),
        )

        # Detect WAF / Cloudflare / CAPTCHA on successful responses too
        if ct_lower in ("text/html", "application/xhtml+xml"):
            text = content.decode("utf-8", errors="replace")
            if not self.skip_captcha_check:
                protections = self.detect_protection(dict(resp.headers), text)
                if protections:
                    log.warning("  [PROTECTION] %s on %s – not saving",
                                ", ".join(protections), url)
                    self._stats["waf"] += 1
                    return

            # Soft-404 detection – skip false positives
            if self._is_soft_404(content, url):
                self._stats["soft404"] += 1
                log.debug("  [SOFT-404] %s – not saving", url)
                return

            # WordPress detection on first HTML page
            if not self._wp_detected and self.detect_wordpress(text):
                self._wp_detected = True
                self._enqueue_wp_discovery(depth)

            # Extract WP nonce from HTML for REST API access
            if self._wp_detected:
                self._extract_wp_nonce(text)
        else:
            text = None

        # Deep-crawl confirmed WP plugins/themes
        path_lower = parsed_url.path.lower()
        if self._wp_detected and resp.ok:
            self._check_wp_deep_crawl(path_lower, depth)

        # Always save the file (every type)
        ch = content_hash(content)
        with self._lock:
            if ch in self._hashes:
                log.debug("  Duplicate content for %s – not saving again", url)
                self._stats["dup"] += 1
                is_dup = True
            else:
                self._hashes.add(ch)
                is_dup = False
        if not is_dup:
            local = smart_local_path(url, self.output_dir, content_type,
                                     content_disp)
            save_file(local, content)
            if self.debug:
                self._save_http_headers(local, resp, url)
            with self._lock:
                self._stats["ok"] += 1
                self._saved_urls.append(url)
                self._track_video_url(url)
            self._maybe_git_push()

        # Extract and enqueue links from parseable content
        ct = ct_lower
        is_parseable_ext = path_lower.endswith(
            (".asp", ".aspx", ".jsp", ".php", ".html", ".htm",
             ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
             ".css", ".scss", ".sass", ".less",
             ".json", ".xml", ".svg", ".rss", ".atom",
             ".txt", ".csv", ".tsv", ".md", ".rst",
             ".env", ".cfg", ".conf", ".config", ".hst",
             ".ini", ".toml", ".yml", ".yaml",
             ".log", ".sql",
             ".py", ".rb", ".pl", ".sh", ".bat", ".ps1",
             ".lua", ".go", ".rs", ".java", ".c", ".cpp", ".h",
             ".vue", ".svelte",
             ".htaccess", ".htpasswd",
             ".gitignore", ".dockerignore", ".editorconfig")
        )
        if ct in CRAWLABLE_TYPES or is_parseable_ext:
            new_links = extract_links(content, content_type, url, self.base)
            # Also scan for links to target download extensions
            if self.download_extensions:
                new_links |= self._extract_extension_links(
                    content, url, self.download_extensions,
                )
            # Extract page & video metadata for discovered video URLs
            if text is not None:
                self._populate_video_meta(text, new_links)
            added = 0
            for link in new_links:
                # Register external hosts from media URLs as CDN hosts
                link_parsed = urllib.parse.urlparse(link)
                if (self._allow_external
                        and link_parsed.netloc
                        and link_parsed.netloc != self.allowed_host):
                    with self._lock:
                        is_new_cdn = link_parsed.netloc not in self._cdn_hosts
                        self._cdn_hosts.add(link_parsed.netloc)
                    if is_new_cdn:
                        log.info("  [CDN] Discovered media host: %s",
                                 link_parsed.netloc)
                k = url_key(link)
                if k not in self._visited:
                    self._enqueue(link, depth + 1, priority=True)
                    added += 1
            if added:
                log.debug("  +%d new URLs enqueued", added)

        time.sleep(self.delay)

    # ------------------------------------------------------------------
    # CDN media download
    # ------------------------------------------------------------------

    def _fetch_cdn_media(self, url: str) -> None:
        """Download a media file from an external CDN host.

        CDN URLs are always streamed directly to disk. No link
        extraction, probe, or WAF checks are performed – these are
        trusted media resources discovered from the crawled site's HTML.
        Files are saved under a ``_cdn/<hostname>/`` subdirectory.
        """
        log.debug("[CDN] GET %s", url)

        try:
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                stream=True,
            )
        except _NETWORK_ERRORS as exc:
            log.warning("[CDN] Request failed for %s – %s", url, exc)
            self._stats["err"] += 1
            return

        if not resp.ok:
            log.debug("[CDN] HTTP %s for %s – skipping", resp.status_code, url)
            self._stats["err"] += 1
            return

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        content_disp = resp.headers.get("Content-Disposition", "")
        ct_lower_cdn = content_type.split(";")[0].strip().lower()

        # Skip media files if requested – record URL but don't download
        if self.skip_media_files and (
            self._is_media_url(url) or self._is_media_content_type(ct_lower_cdn)
        ):
            with self._lock:
                self._track_video_url(url)
                self._stats["skip"] += 1
            log.info("[CDN] [SKIP-MEDIA] %s (media file skipped)", url)
            resp.close()
            time.sleep(self.delay)
            return

        # Skip-download: record curl command instead of downloading
        cdn_url_ext = urllib.parse.urlparse(url).path.rsplit(".", 1)[-1].lower()
        if self.skip_download_exts and cdn_url_ext in self.skip_download_exts:
            with self._lock:
                self._record_download_link(url)
                self._stats["skip"] += 1
            log.info("[CDN] [SKIP-DOWNLOAD] %s (link recorded, not downloaded)", url)
            resp.close()
            time.sleep(self.delay)
            return

        # Build local path: _cdn/<hostname>/<path>
        parsed = urllib.parse.urlparse(url)
        cdn_dir = self.output_dir / "_cdn" / parsed.netloc
        rel_path = parsed.path.lstrip("/")
        if not rel_path:
            rel_path = "index"
        local_stream = cdn_dir / rel_path
        # Apply extension from Content-Type if file has no extension
        if not local_stream.suffix:
            hint = smart_local_path(url, cdn_dir, content_type, content_disp)
            if hint.suffix:
                local_stream = local_stream.with_suffix(hint.suffix)

        try:
            chunks = resp.iter_content(chunk_size=524288)
            first_chunk = next(chunks, b"")
        except _NETWORK_ERRORS as exc:
            log.warning("[CDN] Stream error for %s – %s", url, exc)
            self._stats["err"] += 1
            return

        if not first_chunk:
            log.debug("[CDN] Empty response for %s – skipping", url)
            self._stats["err"] += 1
            return

        local_stream.parent.mkdir(parents=True, exist_ok=True)
        written = len(first_chunk)
        with local_stream.open("wb") as fh:
            fh.write(first_chunk)
            for chunk in chunks:
                if chunk:
                    fh.write(chunk)
                    written += len(chunk)

        ch = file_content_hash(local_stream)
        with self._lock:
            if ch in self._hashes:
                log.debug("[CDN] Duplicate for %s – removing", url)
                local_stream.unlink(missing_ok=True)
                self._stats["dup"] += 1
            else:
                self._hashes.add(ch)
                log.info(
                    "  [CDN-DOWNLOAD] %s → %s (%.1f MiB)",
                    url, local_stream.name, written / (1024 * 1024),
                )
                self._stats["ok"] += 1
                self._saved_urls.append(url)
                self._track_video_url(url)
                if self.debug:
                    self._save_http_headers(local_stream, resp, url)
                self._maybe_git_push()

        time.sleep(self.delay)

    # ------------------------------------------------------------------
    # Extension-seeking link extraction
    # ------------------------------------------------------------------

    def _extract_extension_links(
        self, content: bytes, page_url: str, extensions: frozenset[str],
    ) -> set[str]:
        """Scan *content* for href/src attributes pointing to files
        with any of the target *extensions*.  Returns absolute URLs."""
        if self._ext_link_re is None:
            return set()
        text = content.decode("utf-8", errors="replace")
        found: set[str] = set()
        for m in self._ext_link_re.finditer(text):
            link = m.group(1).strip()
            if not link:
                continue
            link = urllib.parse.urljoin(page_url, link)
            found.add(link)
        return found

    # ------------------------------------------------------------------
    # WordPress deep-crawl helpers
    # ------------------------------------------------------------------

    _WP_NONCE_RE = re.compile(
        r"""(?:wp_rest_nonce|wpApiSettings[^}]*nonce)\W*[=:]\s*['"]([a-f0-9]+)['"]""",
        re.I,
    )

    def _extract_wp_nonce(self, html: str) -> None:
        """Extract a WP REST nonce from page HTML.

        NOTE: The nonce is intentionally NOT added to the session's default
        headers.  Sending ``X-WP-Nonce`` on every request tells WordPress to
        treat the request as authenticated; when the nonce is not tied to a
        logged-in user (which is always the case for a crawler) WordPress
        returns **403 Forbidden** on every REST endpoint instead of the
        normal anonymous 200 response.  We store it only so sub-classes can
        use it selectively if needed.
        """
        m = self._WP_NONCE_RE.search(html)
        if m:
            self._wp_nonce = m.group(1)
            log.debug("  WP nonce extracted: %s", self._wp_nonce)

    def _check_wp_deep_crawl(self, path_lower: str, depth: int) -> None:
        """If a WP plugin/theme slug is confirmed (its readme.txt or
        style.css was fetched successfully), deep-crawl its internal
        files."""
        # Plugin: /wp-content/plugins/<slug>/readme.txt
        m = re.match(
            r"/wp-content/plugins/([a-z0-9_-]+)/readme\.txt$",
            path_lower,
        )
        if m:
            self._deep_crawl_wp_plugin(m.group(1), depth)
            return
        # Theme: /wp-content/themes/<slug>/style.css
        m = re.match(
            r"/wp-content/themes/([a-z0-9_-]+)/style\.css$",
            path_lower,
        )
        if m:
            self._deep_crawl_wp_theme(m.group(1), depth)
