"""
crawl4ai.extensions.downloader – Page & file downloader with GitHub upload.

This module provides :class:`SiteDownloader`, a self-contained tool that:

1. **Fetches pages** and saves the raw HTML to disk.
2. **Scans page content** for links to downloadable files of any type
   (exe, zip, iso, cab, rar, msi, bin, 7z, apk, jar, img, deb, rpm,
   tar.gz, pdf, doc, etc.).
3. **Downloads all discovered files** locally with streaming support for
   large binaries (>10 MiB).
4. **Pushes everything to a GitHub repository** with automatic Git LFS
   tracking for files >50 MB.

Usage::

    from crawl4ai.extensions.downloader import SiteDownloader

    dl = SiteDownloader(
        url="https://support.hp.com",
        output_dir="downloaded_site",
        download_extensions={"zip", "exe", "cab", "msi", "iso"},
        git_repo_dir="downloaded_site",   # git-initialised directory
        git_push_every=50,
    )
    dl.run()
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import threading
import time
import urllib.parse
import warnings
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator

import requests
import urllib3

from crawl4ai.extensions.bypass.session import build_session, random_headers
from crawl4ai.extensions.detection import detect_all
from crawl4ai.extensions.sites import get_matching_modules
from crawl4ai.extensions.extraction import (
    extract_html_attrs,
    extract_css_urls,
    extract_js_paths,
    extract_cloud_links,
)
from crawl4ai.extensions.storage import (
    save_file,
    stream_to_file,
    smart_local_path,
)
from crawl4ai.extensions.settings import (
    REQUEST_TIMEOUT,
    STREAM_SIZE_THRESHOLD,
    BINARY_CONTENT_TYPES,
    CLOUD_STORAGE_HOSTS,
    auto_concurrency,
)

__all__ = ["SiteDownloader"]

# ── ANSI colour helpers (inline – only keywords / URLs get colour) ───────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"

_COLORS = {
    "red": _RED, "green": _GREEN, "yellow": _YELLOW,
    "blue": _BLUE, "magenta": _MAGENTA, "cyan": _CYAN,
    "white": _WHITE, "bold": _BOLD,
}


def _c(text: object, color: str) -> str:
    """Wrap *text* in an ANSI colour escape.  Only the text is coloured."""
    code = _COLORS.get(color, "")
    return f"{code}{text}{_RESET}" if code else str(text)


# ── Plain logging (no whole-line colouring) ──────────────────────────────
_LOGGER_NAME = "crawl4ai.extensions.downloader"
log = logging.getLogger(_LOGGER_NAME)


def _setup_colored_logging(level: int = logging.INFO) -> None:
    """Configure the module logger with **plain** formatting.

    Colour is applied inline via :func:`_c` to individual keywords / URLs
    inside the log message – the line itself is not coloured.

    Side-effects (intentional for CLI / workflow usage):
    * Suppresses verbose ``urllib3`` pool and retry log messages.
    """
    if log.handlers:
        return  # already configured

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    log.setLevel(level)
    log.propagate = False

    # Quiet down noisy third-party loggers (urllib3 pool/retry messages)
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

# ── Network errors to catch ──────────────────────────────────────────────
_NETWORK_ERRORS = (
    requests.RequestException,
    ConnectionError,
    TimeoutError,
    OSError,
)

# ── Downloadable file extensions ─────────────────────────────────────────
# Master list covering virtually every file type: web assets, code, media,
# archives, executables, documents, data, etc.  The downloader will look
# for links matching these when scanning pages.  Pass ``{"all"}`` to the
# constructor to bypass this list entirely and download *everything*.
DEFAULT_DOWNLOAD_EXTENSIONS: frozenset[str] = frozenset({
    # ── Web pages / assets ──
    "html", "htm", "xhtml", "shtml", "asp", "aspx", "php", "jsp", "cgi",
    "css", "js", "mjs", "ts", "jsx", "tsx", "vue", "svelte",
    "svg", "ico", "woff", "woff2", "ttf", "eot", "otf",
    "map", "webmanifest",
    # ── Images ──
    "png", "jpg", "jpeg", "gif", "bmp", "tiff", "tif", "webp", "avif",
    "heic", "heif", "jxl", "raw", "cr2", "nef", "psd", "ai", "eps",
    # ── Video ──
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "3gp",
    "3g2", "ts", "mpeg", "mpg", "f4v", "asf", "ogv", "vob",
    # ── Audio ──
    "mp3", "flac", "wav", "ogg", "aac", "m4a", "wma", "opus", "ape",
    "aiff", "mid", "midi",
    # ── Archives ──
    "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "cab", "lzh",
    "arj", "ace", "zst", "lz", "lzma", "z",
    # ── Executables / Installers ──
    "exe", "msi", "msp", "msix", "appx", "dmg", "pkg", "deb", "rpm",
    "apk", "aab", "appimage", "snap", "flatpak", "run", "ipa",
    # ── Disk images ──
    "iso", "img", "bin", "cue", "nrg", "vhd", "vhdx", "vmdk", "qcow2",
    "ova", "ovf",
    # ── Firmware ──
    "fw", "rom", "bios", "uf2", "hex", "srec",
    # ── Documents ──
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods",
    "odp", "rtf", "epub", "djvu", "mobi", "azw3", "pages", "numbers",
    "key", "txt", "md", "rst", "tex", "latex",
    # ── Java / JVM ──
    "jar", "war", "ear", "class",
    # ── Data / Config ──
    "sql", "sqlite", "db", "mdb", "csv", "tsv", "json", "jsonl", "ndjson",
    "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "properties",
    "env", "log",
    # ── Scripts / Source code ──
    "py", "pyc", "pyw", "pyx",
    "sh", "bash", "zsh", "fish",
    "bat", "ps1", "cmd", "vbs",
    "rb", "pl", "pm", "lua",
    "c", "h", "cpp", "hpp", "cc", "cxx",
    "java", "kt", "kts", "scala", "groovy",
    "go", "rs", "swift", "m", "mm",
    "cs", "fs", "vb",
    "r", "jl", "matlab",
    "asm", "s",
    # ── .NET / Windows ──
    "dll", "sys", "ocx", "lib", "obj", "pdb", "so", "dylib", "a",
    # ── Misc ──
    "torrent", "patch", "diff", "ics", "vcf", "gpx", "kml", "kmz",
    "wasm", "swf",
})

# Regex to find download links in HTML
_DOWNLOAD_LINK_RE = re.compile(
    r"""(?:href|src|data-href|data-src|data-url|action)\s*=\s*['"]([^'"#]+)['"]""",
    re.I,
)

# Regex for direct URL strings in JavaScript
_JS_URL_RE = re.compile(
    r"""['"](\s*https?://[^'">\s]{10,})\s*['"]""",
    re.I,
)

# Meta refresh redirect
_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*['"]refresh['"][^>]+content\s*=\s*['"][^'"]*url=([^'";\s>]+)""",
    re.I,
)

# ── Chunk size for streaming ─────────────────────────────────────────────
_STREAM_CHUNK = 524_288  # 512 KiB

# ── File-index limits ────────────────────────────────────────────────────
_MAX_DESCRIPTIONS_IN_INDEX = 50


class SiteDownloader:
    """Download pages and files from a website, saving locally and optionally
    pushing to a GitHub repository.

    Parameters
    ----------
    url : str
        Starting URL to scan for downloadable files.
    output_dir : str or Path
        Local directory to save downloaded files.
    max_depth : int
        Maximum link-follow depth (0 = only the start page, 1 = one level
        of links, etc.).  Default 2.
    download_extensions : set[str] or None
        File extensions to download.  ``None`` uses the built-in master
        list.  Pass ``{"all"}`` to download every discovered file.
    delay : float
        Delay between requests in seconds.
    concurrency : int
        Number of parallel download workers.  0 = auto-detect.
    verify_ssl : bool
        Verify TLS certificates.
    allow_external : bool
        Follow download links to external hosts (CDNs, cloud storage).
    git_repo_dir : str or Path or None
        Path to a git-initialised directory.  When set, downloaded files
        are committed and pushed periodically.
    git_push_every : int
        Commit & push after every N downloaded files (0 = disabled).
    """

    def __init__(
        self,
        url: str,
        output_dir: str | Path = "downloaded_site",
        *,
        max_depth: int = 2,
        download_extensions: set[str] | None = None,
        delay: float = 0.25,
        concurrency: int = 0,
        verify_ssl: bool = True,
        allow_external: bool = True,
        git_repo_dir: str | Path | None = None,
        git_push_every: int = 0,
        future_timeout: float = 300,
    ) -> None:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")
        self.start_url = url
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.allowed_host = parsed.netloc
        self.output_dir = Path(output_dir)
        self.max_depth = max_depth
        self.delay = delay
        self.allow_external = allow_external
        self.concurrency = auto_concurrency() if concurrency <= 0 else concurrency
        self.git_repo_dir = Path(git_repo_dir) if git_repo_dir else None
        self.git_push_every = git_push_every
        self.future_timeout = future_timeout

        # Determine target extensions
        if download_extensions is None:
            self._target_exts = DEFAULT_DOWNLOAD_EXTENSIONS
        elif "all" in download_extensions:
            self._target_exts = None  # download everything
        else:
            self._target_exts = frozenset(
                e.lower().lstrip(".") for e in download_extensions
            )

        # Build regex for target extensions
        if self._target_exts:
            ext_pat = "|".join(re.escape(e) for e in sorted(self._target_exts))
            self._ext_re = re.compile(
                rf"\.(?:{ext_pat})(?:\?|#|$)", re.I,
            )
        else:
            self._ext_re = None  # match all

        # Session
        self.session = build_session(verify_ssl=verify_ssl)

        # Suppress noisy InsecureRequestWarning when TLS verification is off
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Thread-safe state
        self._lock = threading.Lock()
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()
        self._downloaded_files: list[Path] = []
        self._download_count = 0
        self._page_count = 0
        self._error_count = 0
        self._seen_hashes: set[str] = set()
        self._catalog_index_path: Path | None = None
        self._catalog_entry_count: int = 0

    # ── Public API ───────────────────────────────────────────────────

    def run(self) -> dict:
        """Run the downloader.  Returns a summary dict."""
        _setup_colored_logging()
        log.info("🔍 Starting download from %s → %s",
                 _c(self.start_url, "cyan"), _c(self.output_dir, "green"))
        log.info("   depth=%s  concurrency=%s  delay=%s",
                 _c(self.max_depth, "cyan"), _c(self.concurrency, "cyan"),
                 _c(f"{self.delay:.2f}s", "cyan"))
        if self._target_exts:
            log.info("   target extensions: %s",
                     _c(", ".join(sorted(self._target_exts)), "cyan"))
        else:
            log.info("   target extensions: %s", _c("ALL files", "green"))

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._queue.append((self.start_url, 0))

        # ── Site-specific modules ────────────────────────────────────
        # Check if any site module matches the start URL and generate
        # a file index with metadata instead of downloading files.
        site_modules = get_matching_modules(self.start_url, session=self.session)
        for mod in site_modules:
            log.info("🔌 %s matched — generating file index …",
                     _c(mod.name, "magenta"))
            try:
                index_entries = mod.generate_index(self.start_url)
                if index_entries:
                    index_path = self._write_file_index(
                        mod.name, index_entries,
                    )
                    log.info("🔌 %s: wrote %s entries to %s",
                             _c(mod.name, "magenta"),
                             _c(len(index_entries), "green"),
                             _c(index_path, "green"))
                else:
                    log.info("🔌 %s: no files discovered", _c(mod.name, "magenta"))
            except Exception as exc:
                log.warning("⚠️  %s error: %s", _c(mod.name, "yellow"), exc)

            # Add extra page URLs discovered by the site module
            try:
                extra_pages = mod.page_urls(self.start_url)
                if extra_pages:
                    added = 0
                    for page_url in extra_pages:
                        key = self._url_key(page_url)
                        with self._lock:
                            if key not in self._visited:
                                self._queue.append((page_url, 0))
                                added += 1
                    if added:
                        log.info("🔌 %s: added %s page URLs to crawl queue",
                                 _c(mod.name, "magenta"),
                                 _c(added, "green"))
            except Exception as exc:
                log.debug("🔌 %s page_urls error: %s", mod.name, exc)

        t0 = time.time()

        # Maximum time to wait for futures before cycling back to check
        # for new work.  Set high (300s default) because slow pages
        # (e.g. HP support documents) should NOT be cancelled — the
        # timeout only controls how often we cycle, not when we cancel.
        _FUTURE_TIMEOUT = self.future_timeout

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {}
            while self._queue or futures:
                # Submit new work
                while self._queue and len(futures) < self.concurrency * 2:
                    url, depth = self._queue.popleft()
                    key = self._url_key(url)
                    with self._lock:
                        if key in self._visited:
                            continue
                        self._visited.add(key)
                    fut = pool.submit(self._process_url, url, depth)
                    futures[fut] = (url, depth)

                if not futures:
                    break

                # Wait for at least one to complete, with a timeout to
                # prevent the crawler from stalling on stuck requests.
                done = False
                try:
                    for fut in as_completed(futures, timeout=_FUTURE_TIMEOUT):
                        try:
                            fut.result()
                        except Exception:
                            pass
                        del futures[fut]
                        done = True
                        break  # Process one and loop to submit more
                except TimeoutError:
                    pass

                # If we timed out (no future completed), just continue —
                # slow requests are not cancelled; they keep running.
                # The loop will cycle back to check for completions and
                # submit new work.  This avoids killing legitimate slow
                # pages (e.g. HP support document pages).
                if not done and futures:
                    log.debug("⏳ %d requests still running (none completed "
                              "in %ds) — continuing …",
                              len(futures), _FUTURE_TIMEOUT)

        elapsed = time.time() - t0

        # Final git push
        if self.git_repo_dir and self.git_push_every > 0:
            self._git_push("Final push – download complete")

        # Write summary
        self._write_summary()

        summary = {
            "pages_scanned": self._page_count,
            "files_downloaded": self._download_count,
            "catalog_entries": self._catalog_entry_count,
            "errors": self._error_count,
            "elapsed_seconds": round(elapsed, 1),
            "output_dir": str(self.output_dir),
        }
        parts = [
            f"{_c(self._page_count, 'cyan')} pages scanned",
            f"{_c(self._download_count, 'green')} files downloaded",
        ]
        if self._catalog_entry_count:
            parts.append(
                f"{_c(self._catalog_entry_count, 'green')} catalog entries"
            )
        parts.append(
            f"{_c(self._error_count, 'red' if self._error_count else 'green')} errors"
        )
        parts.append(f"in {_c(f'{elapsed:.1f}s', 'cyan')}")
        log.info("✅ Done: %s", ", ".join(parts))
        return summary

    # ── Internal: process a single URL ───────────────────────────────

    def _process_url(self, url: str, depth: int) -> None:
        """Fetch a URL: if it's a page, scan for links; if it's a file, download it."""
        try:
            # HEAD first to check Content-Type without downloading body
            resp = self.session.head(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            )
        except _NETWORK_ERRORS as exc:
            log.debug("HEAD failed for %s: %s", url, exc)
            with self._lock:
                self._error_count += 1
            return

        ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        cl = int(resp.headers.get("Content-Length", "0") or "0")

        # Is this a downloadable file?
        if self._is_downloadable(url, ct):
            self._download_file(url, ct, cl)
            return

        # Otherwise treat as a page to scan
        if "html" in ct or "xml" in ct or "text" in ct:
            self._scan_page(url, depth)
        else:
            # Unknown content type – save it anyway
            self._download_file(url, ct, cl)

    def _scan_page(self, url: str, depth: int) -> None:
        """Fetch a page, save it, and extract download links."""
        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except _NETWORK_ERRORS as exc:
            log.debug("GET failed for %s: %s", url, exc)
            with self._lock:
                self._error_count += 1
            return

        if not resp.ok:
            log.debug("HTTP %d for %s", resp.status_code, url)
            with self._lock:
                self._error_count += 1
            return

        with self._lock:
            self._page_count += 1

        body = resp.text
        ct = resp.headers.get("Content-Type", "text/html")

        # Run detection
        detections = detect_all(resp.url, resp.status_code, dict(resp.headers), body)
        if detections:
            log.warning("🛡️  %s %s: %s", _c("[DETECT]", "yellow"),
                     _c(url, "cyan"),
                     _c(", ".join(d.get("type", "?") for d in detections), "yellow"))

        # Save the page HTML
        page_path = smart_local_path(resp.url, self.output_dir, ct)
        page_path.parent.mkdir(parents=True, exist_ok=True)
        save_file(page_path, body.encode("utf-8", errors="replace"))

        # Extract all links from the page
        discovered_urls = self._extract_download_links(body, resp.url)

        # Also use the structured extractors
        try:
            discovered_urls |= extract_html_attrs(body, resp.url, self.base)
        except Exception:
            pass
        try:
            discovered_urls |= extract_cloud_links(body)
        except Exception:
            pass

        # Extract from inline CSS
        try:
            discovered_urls |= extract_css_urls(body, resp.url, self.base)
        except Exception:
            pass

        # Extract from inline JS
        try:
            discovered_urls |= extract_js_paths(body, resp.url, self.base)
        except Exception:
            pass

        # Filter and enqueue
        new_file_links = 0
        new_page_links = 0
        for link in discovered_urls:
            if not link or link.startswith(("javascript:", "mailto:", "data:", "#")):
                continue

            # Resolve relative URLs
            abs_url = urllib.parse.urljoin(resp.url, link)
            parsed = urllib.parse.urlparse(abs_url)

            # Check host
            is_external = parsed.netloc != self.allowed_host
            if is_external and not self.allow_external:
                # Allow cloud storage hosts even when external is disabled
                is_cloud = parsed.netloc in CLOUD_STORAGE_HOSTS or any(
                    parsed.netloc.endswith("." + h) for h in CLOUD_STORAGE_HOSTS
                )
                if not is_cloud:
                    continue

            key = self._url_key(abs_url)
            with self._lock:
                if key in self._visited:
                    continue

            if self._is_downloadable(abs_url, ""):
                new_file_links += 1
                self._queue.append((abs_url, depth + 1))
            elif depth < self.max_depth and not is_external:
                new_page_links += 1
                self._queue.append((abs_url, depth + 1))

        log.info("📄 %s %s → %s file links, %s page links",
                 _c("[PAGE]", "blue"), _c(url, "cyan"),
                 _c(new_file_links, "green"), _c(new_page_links, "green"))
        time.sleep(self.delay)

    def _download_file(self, url: str, content_type: str, content_length: int) -> None:
        """Download a file and save it locally."""
        log.info("⬇️  %s %s (%s, ~%s)",
                 _c("[DOWNLOAD]", "magenta"), _c(url, "cyan"),
                 content_type or "?",
                 _c(self._human_size(content_length), "green") if content_length else "?")

        try:
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                stream=True,
            )
        except _NETWORK_ERRORS as exc:
            log.warning("❌ %s Failed: %s – %s",
                        _c("[DOWNLOAD]", "red"), _c(url, "cyan"), exc)
            with self._lock:
                self._error_count += 1
            return

        if not resp.ok:
            log.debug("[DOWNLOAD] HTTP %d for %s", resp.status_code, url)
            with self._lock:
                self._error_count += 1
            return

        ct = resp.headers.get("Content-Type", content_type or "application/octet-stream")
        cd = resp.headers.get("Content-Disposition", "")
        local_path = smart_local_path(resp.url, self.output_dir, ct, cd)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        # Stream to disk while computing content hash for dedup
        hasher = hashlib.sha256()
        total = 0
        try:
            with local_path.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=_STREAM_CHUNK):
                    if chunk:
                        fh.write(chunk)
                        hasher.update(chunk)
                        total += len(chunk)
        finally:
            resp.close()

        if total == 0:
            # Empty file – remove it
            local_path.unlink(missing_ok=True)
            return

        h = hasher.hexdigest()[:16]
        with self._lock:
            if h in self._seen_hashes:
                log.debug("[DOWNLOAD] Duplicate content – removing %s", url)
                local_path.unlink(missing_ok=True)
                return
            self._seen_hashes.add(h)

        with self._lock:
            self._download_count += 1
            self._downloaded_files.append(local_path)

        log.info("💾 %s %s → %s (%s)",
                 _c("[SAVED]", "green"), _c(url, "cyan"),
                 _c(local_path.relative_to(self.output_dir), "green"),
                 _c(self._human_size(total), "green"))

        # Periodic git push
        if self.git_repo_dir and self.git_push_every > 0:
            with self._lock:
                count = self._download_count
            if count % self.git_push_every == 0:
                self._git_push(f"Progress: {count} files downloaded")

        time.sleep(self.delay)

    # ── Link extraction ──────────────────────────────────────────────

    def _extract_download_links(self, html: str, page_url: str) -> set[str]:
        """Extract all potential download links from HTML content."""
        found: set[str] = set()

        # Standard HTML attributes
        for m in _DOWNLOAD_LINK_RE.finditer(html):
            found.add(m.group(1))

        # JavaScript URL strings
        for m in _JS_URL_RE.finditer(html):
            found.add(m.group(1).strip())

        # Meta refresh redirects
        for m in _META_REFRESH_RE.finditer(html):
            found.add(m.group(1))

        # <a> tags with download attribute
        download_attr_re = re.compile(
            r"""<a[^>]+download[^>]*href\s*=\s*['"]([^'"]+)['"]""", re.I,
        )
        for m in download_attr_re.finditer(html):
            found.add(m.group(1))

        # Also look for <a> tags with href before download attribute
        download_attr_re2 = re.compile(
            r"""<a[^>]+href\s*=\s*['"]([^'"]+)['"][^>]+download""", re.I,
        )
        for m in download_attr_re2.finditer(html):
            found.add(m.group(1))

        # data-* attributes often contain download URLs
        data_url_re = re.compile(
            r"""data-(?:download|file|url|href|link)\s*=\s*['"]([^'"]+)['"]""", re.I,
        )
        for m in data_url_re.finditer(html):
            found.add(m.group(1))

        # Resolve relative URLs
        resolved: set[str] = set()
        for raw in found:
            raw = raw.strip()
            if not raw or raw.startswith(("javascript:", "mailto:", "data:", "#")):
                continue
            if "\\/" in raw:
                raw = raw.replace("\\/", "/")
            abs_url = urllib.parse.urljoin(page_url, raw)
            resolved.add(abs_url)

        return resolved

    # ── File type detection ──────────────────────────────────────────

    def _is_downloadable(self, url: str, content_type: str) -> bool:
        """Check if a URL points to a downloadable file."""
        # Check by content type
        ct = content_type.split(";")[0].strip().lower() if content_type else ""
        if ct in BINARY_CONTENT_TYPES:
            return True
        if ct and ct.startswith(("application/", "audio/", "video/")):
            if ct not in ("application/json", "application/xml",
                          "application/xhtml+xml", "application/rss+xml",
                          "application/javascript", "application/x-javascript"):
                return True

        # Check by extension
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        # Get extension
        dot_pos = path.rfind(".")
        if dot_pos >= 0:
            ext = path[dot_pos + 1:]
            # Strip trailing slashes or query artifacts
            ext = ext.split("/")[0].split("?")[0].split("#")[0]
            if self._target_exts is None:
                # "all" mode – any file with an extension is downloadable
                return bool(ext)
            if ext in self._target_exts:
                return True

        # Check with regex if available
        if self._ext_re and self._ext_re.search(parsed.path):
            return True

        return False

    # ── Git push ─────────────────────────────────────────────────────

    def _git_push(self, message: str) -> None:
        """Commit and push downloaded files to the git repository."""
        if not self.git_repo_dir:
            return
        cwd = str(self.git_repo_dir.resolve())
        if not os.path.isdir(os.path.join(cwd, ".git")):
            log.debug("[GIT] No .git directory in %s – skipping push", cwd)
            return

        try:
            # Track large files with Git LFS
            self._git_lfs_track_large_files(cwd)

            # Stage all files
            subprocess.run(
                ["git", "add", "-A"],
                cwd=cwd, capture_output=True, timeout=60,
            )
            # Check if there are changes to commit
            result = subprocess.run(
                ["git", "diff", "--cached", "--quiet"],
                cwd=cwd, capture_output=True, timeout=30,
            )
            if result.returncode == 0:
                log.debug("[GIT] No changes to commit")
                return

            subprocess.run(
                ["git", "commit", "-m", message],
                cwd=cwd, check=True, capture_output=True, timeout=60,
            )
            subprocess.run(
                ["git", "-c", "lfs.locksverify=false", "push"],
                cwd=cwd, check=True, capture_output=True, timeout=300,
            )
            log.info("📤 %s Pushed: %s", _c("[GIT]", "magenta"), message)
        except subprocess.CalledProcessError as exc:
            msg = exc.stderr.decode(errors="replace").strip() if exc.stderr else str(exc)
            log.warning("⚠️  %s Push failed: %s", _c("[GIT]", "yellow"), msg)
        except FileNotFoundError:
            log.warning("⚠️  %s git not found – disabling push", _c("[GIT]", "yellow"))
            self.git_push_every = 0
        except Exception as exc:
            log.warning("⚠️  %s Error: %s", _c("[GIT]", "yellow"), exc)

    @staticmethod
    def _git_lfs_track_large_files(cwd: str) -> None:
        """Track files >50 MB with Git LFS."""
        try:
            for root, _dirs, files in os.walk(cwd):
                if ".git" in root:
                    continue
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        if os.path.getsize(fpath) > 50 * 1024 * 1024:
                            rel = os.path.relpath(fpath, cwd)
                            subprocess.run(
                                ["git", "lfs", "track", rel],
                                cwd=cwd, capture_output=True, timeout=30,
                            )
                    except OSError:
                        pass
            # Stage .gitattributes if it was modified
            gitattr = os.path.join(cwd, ".gitattributes")
            if os.path.exists(gitattr):
                subprocess.run(
                    ["git", "add", ".gitattributes"],
                    cwd=cwd, capture_output=True, timeout=30,
                )
        except Exception:
            pass

    # ── File index (site-module output) ─────────────────────────────

    def _write_file_index(
        self,
        module_name: str,
        entries: list,
    ) -> Path:
        """Write a file index Markdown table from site-module metadata.

        Parameters
        ----------
        module_name:
            Human-readable name of the site module (for the heading).
        entries:
            List of :class:`FileEntry` dicts from the site module's
            ``generate_index()`` method.

        Returns
        -------
        Path
            The path to the generated ``file_index.md``.
        """
        index_path = self.output_dir / "file_index.md"
        with index_path.open("w", encoding="utf-8") as fh:
            fh.write(f"# File Index — {module_name}\n\n")
            fh.write(f"Generated from: `{self.start_url}`\n\n")
            fh.write(f"**{len(entries)} files discovered**\n\n")
            fh.write("| # | Name | Version | Size | Release Date "
                     "| Category | OS | Source | Product | Download URL |\n")
            fh.write("|---|------|---------|------|-------------- "
                     "|----------|----|---------|---------|--------------|\n")
            for i, entry in enumerate(entries, 1):
                name = entry.get("name", "").replace("|", "\\|")
                version = entry.get("version", "")
                size = entry.get("size", "")
                release = entry.get("release_date", "")
                category = entry.get("category", "").replace("|", "\\|")
                os_name = entry.get("os", "")
                source = entry.get("source", "").replace("|", "\\|")
                product = entry.get("product", "").replace("|", "\\|")
                url = entry.get("url", "")
                fh.write(
                    f"| {i} | {name} | {version} | {size} | {release} "
                    f"| {category} | {os_name} | {source} | {product} "
                    f"| {url} |\n"
                )

            # Optional: description section for entries that have one
            descs = [
                (e.get("name", "?"), e.get("description", ""))
                for e in entries if e.get("description")
            ]
            if descs:
                fh.write("\n## Descriptions\n\n")
                for name, desc in descs[:_MAX_DESCRIPTIONS_IN_INDEX]:
                    fh.write(f"**{name}**: {desc}\n\n")

        # Track the catalog index separately from regular downloads
        with self._lock:
            self._catalog_index_path = index_path
            self._catalog_entry_count = len(entries)

        # Push index to git if configured
        if self.git_repo_dir and self.git_push_every > 0:
            self._git_push(f"File index: {len(entries)} entries from {module_name}")

        return index_path

    # ── Summary ──────────────────────────────────────────────────────

    def _write_summary(self) -> None:
        """Write a summary of downloaded files to disk."""
        summary_path = self.output_dir / "download_summary.md"
        with summary_path.open("w", encoding="utf-8") as fh:
            fh.write(f"# Download Summary\n\n")
            fh.write(f"| Setting | Value |\n")
            fh.write(f"|---------|-------|\n")
            fh.write(f"| URL | {self.start_url} |\n")
            fh.write(f"| Pages scanned | {self._page_count} |\n")
            fh.write(f"| Files downloaded | {self._download_count} |\n")
            if self._catalog_entry_count:
                fh.write(f"| Catalog entries | {self._catalog_entry_count} |\n")
            fh.write(f"| Errors | {self._error_count} |\n\n")

            # Catalog index (site module output — separate from downloads)
            with self._lock:
                cat_path = self._catalog_index_path
                cat_count = self._catalog_entry_count
            if cat_path and cat_path.exists():
                rel = cat_path.relative_to(self.output_dir)
                fh.write("## Catalog File Index\n\n")
                fh.write(f"The site module generated a catalog of "
                         f"**{cat_count}** files "
                         f"in [`{rel}`]({rel}).\n\n"
                         f"This index lists drivers, software, and firmware "
                         f"discovered via the site's APIs — it is separate "
                         f"from the downloaded HTML/CSS/JS files below.\n\n")

            if self._downloaded_files:
                fh.write("## Downloaded Files\n\n")
                fh.write("| # | File | Size |\n")
                fh.write("|---|------|------|\n")
                for i, fp in enumerate(self._downloaded_files, 1):
                    try:
                        size = fp.stat().st_size
                        rel = fp.relative_to(self.output_dir)
                        fh.write(f"| {i} | `{rel}` | {self._human_size(size)} |\n")
                    except Exception:
                        fh.write(f"| {i} | `{fp.name}` | ? |\n")

        log.info("📊 Summary written → %s", _c(summary_path, "green"))

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _url_key(url: str) -> str:
        """Normalise a URL into a dedup key (lowercase, no fragment)."""
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            "",
            parsed.query,
            "",
        ))

    @staticmethod
    def _human_size(size: int) -> str:
        """Format a byte count as a human-readable string."""
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        if size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        return f"{size / (1024 * 1024 * 1024):.2f} GB"
