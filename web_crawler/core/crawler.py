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
    BACKOFF_429_BASE,
    BACKOFF_429_MAX,
    BLOCKED_PATH_RE,
    CRAWLABLE_TYPES,
    DEFAULT_DELAY,
    HEADER_RETRY_MAX,
    HIDDEN_FILE_PROBES,
    REQUEST_TIMEOUT,
    RETRY_STATUS_CODES,
    SOFT_404_KEYWORDS,
    SOFT_404_MIN_KEYWORD_HITS,
    SOFT_404_SIZE_RATIO,
    USER_AGENTS,
    WAF_SIGNATURES,
    WP_DISCOVERY_PATHS,
    WP_PLUGIN_FILES,
    WP_PLUGIN_PROBES,
    WP_THEME_FILES,
    WP_THEME_PROBES,
)
from web_crawler.session import build_session, cache_bust_url, random_headers
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
        self._probed_dirs: set[str] = set()  # directories already probed for hidden files
        self._stats = {"ok": 0, "skip": 0, "err": 0, "dup": 0,
                       "soft404": 0, "waf": 0, "retry_ok": 0}

        # Soft-404 detection
        self._soft404_size: int | None = None
        self._soft404_hash: str | None = None

        # WordPress detection
        self._wp_detected: bool = False
        self._wp_probed: bool = False
        self._wp_confirmed_plugins: set[str] = set()
        self._wp_confirmed_themes: set[str] = set()

        # Cloudflare bypass state
        self._cf_bypass_done: bool = False

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

        # Build soft-404 baseline
        self._build_soft404_fingerprint()

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
            "Crawl complete. visited=%d  ok=%d  skip=%d  dup=%d  "
            "soft404=%d  waf=%d  retry_ok=%d  err=%d",
            len(self._visited),
            self._stats["ok"],
            self._stats["skip"],
            self._stats["dup"],
            self._stats["soft404"],
            self._stats["waf"],
            self._stats["retry_ok"],
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
        except requests.RequestException:
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
        log.info(
            "Soft-404 baseline: %d bytes, hash=%s (server returns 200 for missing pages)",
            self._soft404_size, self._soft404_hash,
        )

    def _is_soft_404(self, content: bytes, url: str) -> bool:
        """Return True if *content* looks like a soft-404 (false positive)."""
        if self._soft404_hash is None:
            return False

        # Exact match with baseline
        if content_hash(content) == self._soft404_hash:
            log.debug("  Soft-404 (exact match): %s", url)
            return True

        # Size-based heuristic + keyword check
        size = len(content)
        if self._soft404_size and self._soft404_size > 0:
            ratio = abs(size - self._soft404_size) / self._soft404_size
            if ratio <= SOFT_404_SIZE_RATIO:
                text = content.decode("utf-8", errors="replace").lower()
                hits = sum(1 for kw in SOFT_404_KEYWORDS if kw in text)
                if hits >= SOFT_404_MIN_KEYWORD_HITS:
                    log.debug(
                        "  Soft-404 (size+keywords, %d hits): %s", hits, url
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
            self._enqueue(self.base + path, 0)
        # Plugin enumeration (readme.txt to confirm existence)
        for slug in WP_PLUGIN_PROBES:
            self._enqueue(
                self.base + f"/wp-content/plugins/{slug}/readme.txt", 0
            )
        # Theme enumeration (style.css to confirm existence)
        for slug in WP_THEME_PROBES:
            self._enqueue(
                self.base + f"/wp-content/themes/{slug}/style.css", 0
            )
        # Author enumeration (users 1-10)
        for n in range(1, 11):
            self._enqueue(self.base + f"/?author={n}", 0)
        total = (len(WP_DISCOVERY_PATHS) + len(WP_PLUGIN_PROBES)
                 + len(WP_THEME_PROBES) + 10)
        log.info("WordPress detected – enqueued %d discovery URLs", total)

    def _deep_crawl_wp_plugin(self, slug: str, depth: int) -> None:
        """Enqueue internal files for a confirmed WordPress plugin."""
        if slug in self._wp_confirmed_plugins:
            return
        self._wp_confirmed_plugins.add(slug)
        base_path = f"/wp-content/plugins/{slug}/"
        for f in WP_PLUGIN_FILES:
            self._enqueue(self.base + base_path + f, depth + 1)
        log.info("  [WP-PLUGIN] Deep-crawling plugin '%s' (%d files)",
                 slug, len(WP_PLUGIN_FILES))

    def _deep_crawl_wp_theme(self, slug: str, depth: int) -> None:
        """Enqueue internal files for a confirmed WordPress theme."""
        if slug in self._wp_confirmed_themes:
            return
        self._wp_confirmed_themes.add(slug)
        base_path = f"/wp-content/themes/{slug}/"
        for f in WP_THEME_FILES:
            self._enqueue(self.base + base_path + f, depth + 1)
        log.info("  [WP-THEME] Deep-crawling theme '%s' (%d files)",
                 slug, len(WP_THEME_FILES))

    # ------------------------------------------------------------------
    # WAF / Cloudflare / CAPTCHA detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_protection(headers: dict[str, str], body: str) -> list[str]:
        """Return a list of detected WAF/protection names from *headers* and
        *body* content."""
        combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        combined += " " + body.lower()
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
                if resp.ok:
                    log.info(
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
                            log.info("  [CF-BYPASS] Succeeded for %s", url)
                            return resp2
                log.debug(
                    "  [RETRY %d/%d] HTTP %s for %s",
                    attempt, HEADER_RETRY_MAX, resp.status_code, url,
                )
            except requests.RequestException:
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

    def _probe_hidden_files(self, url: str, depth: int) -> None:
        """Enqueue hidden/config files for every new directory discovered."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        # Derive directory: strip filename if path doesn't end with /
        if path.endswith("/"):
            dir_path = path
        else:
            dir_path = path.rsplit("/", 1)[0] + "/"
        if not dir_path:
            dir_path = "/"

        if dir_path in self._probed_dirs:
            return
        self._probed_dirs.add(dir_path)

        for probe in HIDDEN_FILE_PROBES:
            probe_url = self.base + dir_path + probe
            self._enqueue(probe_url, depth + 1)

        log.debug("Probed %d hidden files at %s", len(HIDDEN_FILE_PROBES), dir_path)

    def _fetch_and_process(self, url: str, depth: int) -> None:
        key = url_key(url)
        if key in self._visited:
            return
        self._visited.add(key)

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

        # Skip already-downloaded files
        if not self.force and local.exists() and local.stat().st_size > 0:
            log.info("[SKIP] Already on disk: %s", url)
            self._stats["skip"] += 1
            added = self._parse_local_file(local, url)
            if added:
                log.debug("  +%d new URLs from cached %s", added, local.name)
            return

        log.info("[%d queued] GET %s", len(self._queue), url)

        # Rotate User-Agent per request
        self.session.headers["User-Agent"] = random.choice(USER_AGENTS)

        try:
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
        except requests.RequestException as exc:
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
                self._stats["err"] += 1
                return
            # WordPress protection: redirect to wp-login.php means
            # the page requires authentication – save the redirect
            # target but don't treat as error
            if "wp-login.php" in final_parsed.path:
                log.debug("  WP auth redirect to wp-login.php – skipping %s",
                          url)
                self._stats["err"] += 1
                return
            # Mark the final URL as visited too
            final_key = url_key(final_url)
            self._visited.add(final_key)
            log.debug("  Redirect: %s → %s", url, final_url)

        # Handle 429 (rate limiting) with exponential backoff + re-enqueue
        if resp.status_code == 429:
            self._handle_rate_limit(resp, url)
            self._visited.discard(key)
            self._enqueue(url, depth)
            return

        # Handle 403 / 402 – retry with rotated headers + cache busting
        if resp.status_code in RETRY_STATUS_CODES:
            log.info("  [%d] Blocked – retrying with rotated headers: %s",
                     resp.status_code, url)
            retry_resp = self._retry_with_headers(url)
            if retry_resp is not None:
                resp = retry_resp
            else:
                # Detect WAF / protection on the original blocked response
                body_text = resp.content.decode("utf-8", errors="replace")
                protections = self.detect_protection(
                    dict(resp.headers), body_text
                )
                if protections:
                    self._stats["waf"] += 1
                    log.warning(
                        "  [WAF] %s detected on %s",
                        ", ".join(protections), url,
                    )
                else:
                    log.warning("HTTP %s for %s – skipping",
                                resp.status_code, url)
                self._stats["err"] += 1
                return

        if not resp.ok:
            log.warning("HTTP %s for %s – skipping", resp.status_code, url)
            self._stats["err"] += 1
            return

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        content_disp = resp.headers.get("Content-Disposition", "")
        content = resp.content
        ct_lower = content_type.split(";")[0].strip().lower()

        log.debug(
            "  ← HTTP %s  CT: %s  %d bytes",
            resp.status_code, content_type, len(content),
        )

        # Detect WAF / Cloudflare / CAPTCHA on successful responses too
        if ct_lower in ("text/html", "application/xhtml+xml"):
            text = content.decode("utf-8", errors="replace")
            protections = self.detect_protection(dict(resp.headers), text)
            if protections:
                log.info("  [PROTECTION] %s on %s",
                         ", ".join(protections), url)

            # Soft-404 detection – skip false positives
            if self._is_soft_404(content, url):
                self._stats["soft404"] += 1
                log.info("  [SOFT-404] %s – not saving", url)
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
        if ch in self._hashes:
            log.debug("  Duplicate content for %s – not saving again", url)
            self._stats["dup"] += 1
        else:
            self._hashes.add(ch)
            local = smart_local_path(url, self.output_dir, content_type,
                                     content_disp)
            save_file(local, content)
            self._save_http_headers(local, resp, url)
            self._stats["ok"] += 1

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
            added = 0
            for link in new_links:
                k = url_key(link)
                if k not in self._visited:
                    self._enqueue(link, depth + 1)
                    added += 1
            if added:
                log.debug("  +%d new URLs enqueued", added)

        time.sleep(self.delay)

    # ------------------------------------------------------------------
    # WordPress deep-crawl helpers
    # ------------------------------------------------------------------

    _WP_NONCE_RE = re.compile(
        r"""(?:wp_rest_nonce|wpApiSettings[^}]*nonce)\W*[=:]\s*['"]([a-f0-9]+)['"]""",
        re.I,
    )

    def _extract_wp_nonce(self, html: str) -> None:
        """Extract a WP REST nonce from page HTML and set it on the session
        so subsequent REST API calls are authenticated."""
        m = self._WP_NONCE_RE.search(html)
        if m:
            nonce = m.group(1)
            self.session.headers["X-WP-Nonce"] = nonce
            log.debug("  WP nonce extracted: %s", nonce)

    def _check_wp_deep_crawl(self, path_lower: str, depth: int) -> None:
        """If a WP plugin/theme slug is confirmed (its readme.txt or
        style.css was fetched successfully), deep-crawl its internal
        files."""
        import re as _re
        # Plugin: /wp-content/plugins/<slug>/readme.txt
        m = _re.match(
            r"/wp-content/plugins/([a-z0-9_-]+)/readme\.txt$",
            path_lower,
        )
        if m:
            self._deep_crawl_wp_plugin(m.group(1), depth)
            return
        # Theme: /wp-content/themes/<slug>/style.css
        m = _re.match(
            r"/wp-content/themes/([a-z0-9_-]+)/style\.css$",
            path_lower,
        )
        if m:
            self._deep_crawl_wp_theme(m.group(1), depth)
