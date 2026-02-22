"""
huawei_crawler.crawler
=======================
BFS (Breadth-First Search) crawler for the Huawei HG8145V5 admin panel.

Features
--------
* No hardcoded URL list – seeds only from the post-login redirect URL.
  Every other page is discovered by recursively extracting links from
  downloaded content.
* Authenticated session with automatic re-login on expiry.
* X_HW_Token maintained throughout the session; 403 responses are
  retried once with a fresh token appended as a query parameter.
* Content-hash deduplication prevents saving the same bytes twice even
  if the router serves them under different URLs.
* Resume support – existing files are marked visited and parsed for links.
"""

from __future__ import annotations

import logging
import sys
import time
import urllib.parse
from collections import deque
from pathlib import Path

import requests

from .config import (
    REQUEST_TIMEOUT, DELAY_BETWEEN_REQUESTS, MAX_RELOGIN_ATTEMPTS,
    SESSION_HEARTBEAT_EVERY, CRAWLABLE_TYPES,
    BLOCKED_PATH_RE, AUTH_PAGE_PATHS, TOKEN_URL, LOGIN_PAGE,
)
from .auth import login, is_session_expired, refresh_token
from .session import build_session
from .utils import (
    base_url, url_key, url_to_local_path, smart_local_path,
    save_file, content_hash,
)
from .extract import extract_links

log = logging.getLogger("hg8145v5-crawler")

try:
    from tqdm import tqdm as _tqdm
    _TQDM_AVAILABLE = True
except ImportError:
    _TQDM_AVAILABLE = False


class Crawler:
    """
    Fully dynamic BFS crawler that discovers all router pages automatically.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        output_dir: Path,
        verify_ssl: bool = True,
        force: bool = False,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.output_dir = output_dir
        self.base = base_url(host)
        self.force = force
        self.session = build_session(verify_ssl=verify_ssl)

        self._visited: set[str]    = set()
        self._queue:   deque[str]  = deque()
        self._hashes:  set[str]    = set()
        self._relogin_count   = 0
        self._fetch_count     = 0
        self._current_token: str | None = None
        self._stats = {"ok": 0, "skip": 0, "err": 0, "dup": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        log.info("Output directory : %s", self.output_dir.resolve())
        log.info("Target router    : %s", self.base)
        log.info("Username         : %s", self.username)

        # Pre-download the login page BEFORE authenticating.
        # /index.asp is publicly accessible, contains all JS/CSS/image
        # references that seed the BFS, and must never be fetched post-auth
        # (it always returns the login form → false session-expiry detection).
        self._save_pre_auth(LOGIN_PAGE)

        post_login_url = login(self.session, self.host, self.username, self.password)
        if not post_login_url:
            sys.exit(1)

        # Set Referer to the router root ("/") for ALL subsequent requests.
        # Admin ASP pages are loaded inside the frameset at "/", so the router
        # expects Referer: http://192.168.100.1/ — not login.cgi.
        self.session.headers["Referer"] = self.base + "/"

        # Refresh X_HW_Token right after login.
        # The session cookie is preserved inside refresh_token() even if the
        # token endpoint is unavailable on this firmware version.
        self._current_token = refresh_token(
            self.session, self.host, self._current_token
        )

        # Resume: scan previously downloaded files
        if not self.force:
            n = self._resume_from_disk()
            if n:
                log.info("Resume: %d existing file(s) loaded from disk.", n)

        # Seed from "/" (the authenticated admin frameset) and post-login URL.
        # /index.asp was already handled pre-auth by _save_pre_auth() above.
        self._enqueue(self.base + "/")
        if post_login_url not in (self.base + "/",):
            self._enqueue(post_login_url)

        log.info("Seeding from / + post-login URL. Dynamic discovery begins.")

        if _TQDM_AVAILABLE:
            self._run_with_progress()
        else:
            while self._queue:
                url = self._queue.popleft()
                self._fetch_and_process(url)

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
        bar.total = len(self._queue) + len(self._visited)

        while self._queue:
            url = self._queue.popleft()
            prev_q = len(self._queue)
            self._fetch_and_process(url)
            new_items = len(self._queue) - prev_q
            if new_items > 0:
                bar.total += new_items
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

    _DISK_CT: dict[str, str] = {
        ".asp":  "text/html",
        ".html": "text/html",
        ".htm":  "text/html",
        ".js":   "application/javascript",
        ".css":  "text/css",
        ".json": "application/json",
        ".xml":  "application/xml",
    }

    def _parse_local_file(self, local_path: Path, url: str) -> int:
        """Read *local_path* from disk, extract links, and enqueue new ones."""
        ct = self._DISK_CT.get(local_path.suffix.lower())
        if ct is None:
            return 0
        try:
            content = local_path.read_bytes()
        except OSError as exc:
            log.debug("Could not read %s for link extraction: %s", local_path, exc)
            return 0
        added = 0
        for link in extract_links(content, ct, url, self.base):
            k = url_key(link)
            if k not in self._visited:
                self._queue.append(link)
                added += 1
        return added

    def _resume_from_disk(self) -> int:
        """
        Scan *output_dir* for previously downloaded files, mark them visited,
        and extract any un-followed links from their content.
        """
        if not self.output_dir.exists():
            return 0
        count = 0
        for local_path in sorted(self.output_dir.rglob("*")):
            if not local_path.is_file():
                continue
            rel = local_path.relative_to(self.output_dir)
            path_str = "/" + str(rel).replace("\\", "/")
            if path_str == "/index.html":
                path_str = "/"
            elif path_str.endswith("/index.html"):
                path_str = path_str[: -len("index.html")]
            url = self.base + path_str
            key = url_key(url)
            if key in self._visited:
                continue
            self._visited.add(key)
            count += 1
            log.debug("Resume: %s → %s", local_path.name, url)
            self._parse_local_file(local_path, url)
        return count

    def _enqueue(self, url: str) -> None:
        """Add *url* to the queue if it has not been visited yet."""
        key = url_key(url)
        if key not in self._visited:
            self._queue.append(url)

    def _save_pre_auth(self, path: str) -> None:
        """
        Download and save a page that is publicly accessible without
        authentication, before login().

        Called for the main login page (/index.asp).  Saves the file for
        offline analysis, marks the URL visited so the BFS never tries to
        fetch it post-auth (where it returns the login form → false
        session-expiry detection), and extracts seed links from its content.

        If the file already exists on disk it is parsed for links but not
        re-downloaded (unless --force is set).
        """
        url = self.base + path
        key = url_key(url)
        local = url_to_local_path(url, self.output_dir)

        if not self.force and local.exists() and local.stat().st_size > 0:
            self._visited.add(key)
            self._parse_local_file(local, url)
            log.debug("Pre-auth page already on disk: %s", path)
            return

        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
            if resp.ok:
                ct = resp.headers.get("Content-Type", "text/html")
                save_file(local, resp.content)
                self._visited.add(key)
                self._stats["ok"] += 1
                log.debug("Pre-auth saved: %s (%d bytes)", path, len(resp.content))
                for link in extract_links(resp.content, ct, url, self.base):
                    self._enqueue(link)
        except requests.RequestException as exc:
            log.debug("Could not pre-download %s: %s", path, exc)

    def _heartbeat(self) -> None:
        """POST to GetRandToken.asp to refresh session idle timer and token."""
        self._current_token = refresh_token(
            self.session, self.host, self._current_token
        )

    def _retry_with_token(self, url: str) -> "requests.Response | None":
        """
        Retry a 403 request by appending a fresh X_HW_Token as a query
        parameter.  Returns the new response, or None if no token available.
        """
        self._current_token = refresh_token(
            self.session, self.host, self._current_token
        )
        if not self._current_token:
            return None
        sep = "&" if "?" in url else "?"
        token_url = f"{url}{sep}x.X_HW_Token={self._current_token}"
        try:
            log.debug("403 retry with token: %s", token_url)
            return self.session.get(
                token_url, timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
        except requests.RequestException:
            return None

    def _fetch_and_process(self, url: str) -> None:
        key = url_key(url)
        if key in self._visited:
            return
        self._visited.add(key)

        # Never crawl write-action endpoints
        if BLOCKED_PATH_RE.search(urllib.parse.urlparse(url).path):
            log.debug("Blocked write-action URL, skipping: %s", url)
            return

        # Login-interface pages always return the login form after
        # authentication → would trigger is_session_expired() falsely.
        req_path = urllib.parse.urlparse(url).path.lower()
        if req_path in AUTH_PAGE_PATHS:
            local_auth = url_to_local_path(url, self.output_dir)
            if local_auth.exists() and local_auth.stat().st_size > 0:
                self._stats["skip"] += 1
                self._parse_local_file(local_auth, url)
                log.debug("Auth page on disk, links extracted: %s", url)
            else:
                log.debug("Skipping login-interface page (no post-auth fetch): %s", url)
            return

        local = smart_local_path(url, self.output_dir, "")

        # Skip already-downloaded files; parse them for new links
        if not self.force and local.exists() and local.stat().st_size > 0:
            log.info("[SKIP] Already on disk: %s", url)
            self._stats["skip"] += 1
            added = self._parse_local_file(local, url)
            if added:
                log.debug("  +%d new URLs from cached %s", added, local.name)
            return

        log.info("[%d queued] GET %s", len(self._queue), url)

        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            log.warning("Request failed for %s – %s", url, exc)
            self._stats["err"] += 1
            return

        # Session expiry detection & recovery
        if resp.status_code == 401 or is_session_expired(resp):
            log.warning("Session expired at %s – attempting re-login", url)
            if self._relogin_count < MAX_RELOGIN_ATTEMPTS:
                self._relogin_count += 1
                self.session.cookies.clear()
                new_login_url = login(
                    self.session, self.host, self.username, self.password
                )
                if new_login_url:
                    log.info("Re-login successful (attempt %d)", self._relogin_count)
                    self.session.headers["Referer"] = self.base + "/"
                    # Refresh token with session-cookie protection
                    self._current_token = refresh_token(
                        self.session, self.host, self._current_token
                    )
                    self._visited.discard(key)
                    self._queue.appendleft(url)
                    return
            log.error("Could not recover session after %d attempts", self._relogin_count)
            self._relogin_count = 0
            self._stats["err"] += 1
            return

        # 403 smart retry with X_HW_Token
        if resp.status_code == 403:
            log.debug("HTTP 403 for %s – retrying with token", url)
            retry = self._retry_with_token(url)
            if retry is not None and retry.ok:
                log.info("Token retry succeeded for %s", url)
                resp = retry
            else:
                log.warning("HTTP 403 for %s – skipping", url)
                self._stats["err"] += 1
                return

        if not resp.ok:
            log.warning("HTTP %s for %s – skipping", resp.status_code, url)
            self._stats["err"] += 1
            return

        # Successful response – reset the re-login counter
        self._relogin_count = 0
        self._fetch_count += 1
        if self._fetch_count % SESSION_HEARTBEAT_EVERY == 0:
            self._heartbeat()

        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        content_disp  = resp.headers.get("Content-Disposition", "")
        content = resp.content

        log.debug(
            "  ← HTTP %s  CT: %s  %d bytes",
            resp.status_code, content_type, len(content),
        )

        # Content-hash deduplication
        ch = content_hash(content)
        if ch in self._hashes:
            log.debug("  Duplicate content for %s – not saving again", url)
            self._stats["dup"] += 1
        else:
            self._hashes.add(ch)
            local = smart_local_path(url, self.output_dir, content_type, content_disp)
            save_file(local, content)
            self._stats["ok"] += 1

        # Extract links for further crawling
        ct = content_type.split(";")[0].strip().lower()
        is_asp = urllib.parse.urlparse(url).path.lower().endswith(".asp")
        if ct in CRAWLABLE_TYPES or is_asp:
            new_links = extract_links(content, content_type, url, self.base)
            added = 0
            for link in new_links:
                k = url_key(link)
                if k not in self._visited:
                    self._queue.append(link)
                    added += 1
            if added:
                log.debug("  +%d new URLs enqueued", added)

        time.sleep(DELAY_BETWEEN_REQUESTS)
