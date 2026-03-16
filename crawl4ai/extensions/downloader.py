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
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator

import requests

from crawl4ai.extensions.bypass.session import build_session, random_headers
from crawl4ai.extensions.detection import detect_all
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
    content_hash,
)
from crawl4ai.extensions.settings import (
    REQUEST_TIMEOUT,
    STREAM_SIZE_THRESHOLD,
    BINARY_CONTENT_TYPES,
    CLOUD_STORAGE_HOSTS,
    auto_concurrency,
)

__all__ = ["SiteDownloader"]

log = logging.getLogger("crawl4ai.extensions.downloader")

# ── Network errors to catch ──────────────────────────────────────────────
_NETWORK_ERRORS = (
    requests.RequestException,
    ConnectionError,
    TimeoutError,
    OSError,
)

# ── Downloadable file extensions ─────────────────────────────────────────
# This is the master list of file extensions that the downloader will look
# for when scanning pages.  Can be overridden in the constructor.
DEFAULT_DOWNLOAD_EXTENSIONS: frozenset[str] = frozenset({
    # Archives
    "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "cab", "lzh",
    "arj", "ace", "zst",
    # Executables / Installers
    "exe", "msi", "msp", "msix", "appx", "dmg", "pkg", "deb", "rpm",
    "apk", "aab", "appimage", "snap", "flatpak",
    # Disk images
    "iso", "img", "bin", "cue", "nrg", "vhd", "vhdx", "vmdk", "qcow2",
    # Firmware
    "fw", "rom", "bios", "uf2", "hex", "srec",
    # Documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods",
    "odp", "rtf", "epub",
    # Java / JVM
    "jar", "war", "ear",
    # Data
    "sql", "sqlite", "db", "csv", "tsv", "json", "xml", "yaml", "yml",
    # Scripts / source
    "py", "sh", "bat", "ps1", "cmd", "rb", "pl",
    # Media (selectively – large media often desired)
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm",
    "mp3", "flac", "wav", "ogg", "aac", "m4a",
    # Other common downloads
    "torrent", "patch", "diff",
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

        # Thread-safe state
        self._lock = threading.Lock()
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()
        self._downloaded_files: list[Path] = []
        self._download_count = 0
        self._page_count = 0
        self._error_count = 0
        self._seen_hashes: set[str] = set()

    # ── Public API ───────────────────────────────────────────────────

    def run(self) -> dict:
        """Run the downloader.  Returns a summary dict."""
        log.info("Starting download from %s → %s", self.start_url, self.output_dir)
        log.info("  depth=%d  concurrency=%d  delay=%.2fs",
                 self.max_depth, self.concurrency, self.delay)
        if self._target_exts:
            log.info("  target extensions: %s", ", ".join(sorted(self._target_exts)))
        else:
            log.info("  target extensions: ALL files")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._queue.append((self.start_url, 0))
        t0 = time.time()

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

                # Wait for at least one to complete
                done, _ = as_completed(futures), None
                for fut in list(done):
                    try:
                        fut.result(timeout=0.1)
                    except Exception:
                        pass
                    if fut in futures:
                        del futures[fut]
                    break  # Process one and loop to submit more

        elapsed = time.time() - t0

        # Final git push
        if self.git_repo_dir and self.git_push_every > 0:
            self._git_push("Final push – download complete")

        # Write summary
        self._write_summary()

        summary = {
            "pages_scanned": self._page_count,
            "files_downloaded": self._download_count,
            "errors": self._error_count,
            "elapsed_seconds": round(elapsed, 1),
            "output_dir": str(self.output_dir),
        }
        log.info("Done: %d pages scanned, %d files downloaded, %d errors in %.1fs",
                 self._page_count, self._download_count, self._error_count, elapsed)
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
            log.info("[DETECT] %s: %s", url,
                     ", ".join(d.get("type", "?") for d in detections))

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

        log.info("[PAGE] %s → %d file links, %d page links",
                 url, new_file_links, new_page_links)
        time.sleep(self.delay)

    def _download_file(self, url: str, content_type: str, content_length: int) -> None:
        """Download a file and save it locally."""
        log.info("[DOWNLOAD] %s (%s, ~%s)",
                 url, content_type or "?",
                 self._human_size(content_length) if content_length else "?")

        try:
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                stream=True,
            )
        except _NETWORK_ERRORS as exc:
            log.warning("[DOWNLOAD] Failed: %s – %s", url, exc)
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

        # Deduplicate by content hash (first chunk)
        first_chunk = None
        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=_STREAM_CHUNK):
            if chunk:
                chunks.append(chunk)
                if first_chunk is None:
                    first_chunk = chunk

        if not chunks:
            resp.close()
            return

        full_data = b"".join(chunks)
        h = content_hash(full_data)
        with self._lock:
            if h in self._seen_hashes:
                log.debug("[DOWNLOAD] Duplicate content – skipping %s", url)
                return
            self._seen_hashes.add(h)

        # Save
        local_path.parent.mkdir(parents=True, exist_ok=True)
        save_file(local_path, full_data)

        with self._lock:
            self._download_count += 1
            self._downloaded_files.append(local_path)

        log.info("[SAVED] %s → %s (%s)",
                 url, local_path.relative_to(self.output_dir),
                 self._human_size(len(full_data)))

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
            log.info("[GIT] Pushed: %s", message)
        except subprocess.CalledProcessError as exc:
            msg = exc.stderr.decode(errors="replace").strip() if exc.stderr else str(exc)
            log.warning("[GIT] Push failed: %s", msg)
        except FileNotFoundError:
            log.warning("[GIT] git not found – disabling push")
            self.git_push_every = 0
        except Exception as exc:
            log.warning("[GIT] Error: %s", exc)

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
            fh.write(f"| Errors | {self._error_count} |\n\n")

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

        log.info("Summary written → %s", summary_path)

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
