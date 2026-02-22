"""Core BFS Crawler class for the Huawei HG8145V5 router."""

import sys
import time
import urllib.parse
from collections import deque
from pathlib import Path

import requests

from .config import (
    CRAWLABLE_TYPES,
    DELAY_BETWEEN_REQUESTS,
    LOGIN_PAGE,
    MAX_RELOGIN_ATTEMPTS,
    REQUEST_TIMEOUT,
    SESSION_HEARTBEAT_EVERY,
    TOKEN_URL,
    _AUTH_PAGE_PATHS,
    _BLOCKED_PATH_RE,
)
from .logging_setup import log
from .session import base_url, build_session
from .auth.login import is_session_expired, login
from .extraction.links import extract_links
from .utils.files import content_hash, save_file
from .utils.url import smart_local_path, url_key, url_to_local_path


class Crawler:
    """
    Fully dynamic BFS crawler that discovers all router pages automatically.

    Key design decisions:
      • No hardcoded URL list – seeds only from the login page (/index.asp)
        and the post-login redirect URL.  Every other page is discovered by
        recursively extracting links from downloaded content.
      • Authenticated session with automatic re-login on expiry.
      • X_HW_Token maintained throughout the session; 403 responses are
        retried once with a fresh token appended as a query parameter.
      • Content-hash deduplication prevents saving the same bytes twice
        even if the router serves them under different URLs.
      • lxml-accelerated HTML parsing when the library is available.
      • tqdm live progress bar when the library is available.
      • Colored logging when colorlog is available.
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

        self._visited:   set[str]   = set()   # URL keys already processed
        self._queue:     deque[str] = deque() # BFS queue (absolute URLs)
        self._hashes:    set[str]   = set()   # content hashes seen (dedup)
        self._relogin_count   = 0
        self._fetch_count     = 0
        self._current_token:  str | None = None   # latest X_HW_Token
        self._stats = {"ok": 0, "skip": 0, "err": 0, "dup": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        # Import tqdm availability check here to keep it in cli.py's domain
        # but also support direct Crawler usage
        try:
            from tqdm import tqdm as _tqdm_cls
            tqdm_available = True
        except ImportError:
            _tqdm_cls = None
            tqdm_available = False

        log.info("Output directory : %s", self.output_dir.resolve())
        log.info("Target router    : %s", self.base)
        log.info("Username         : %s", self.username)

        # Pre-download the login page BEFORE authenticating.
        # /index.asp is publicly accessible (no auth required), contains ALL
        # JS/CSS/image references that seed the BFS, and must never be fetched
        # post-auth (it always returns the login form, which would trigger false
        # session-expiry detection).  Saving it here and marking it visited
        # ensures it is available for offline analysis without revisiting it.
        self._save_pre_auth(LOGIN_PAGE)
        # The root URL "/" typically serves the same content as /index.asp on
        # Huawei routers.  Pre-save it so it is available for link extraction
        # and marked visited, preventing false session-expiry detection.
        self._save_pre_auth("/")  # prevents infinite re-login loop (root = login page)

        post_login_url = login(self.session, self.host, self.username, self.password)
        if not post_login_url:
            sys.exit(1)

        # Set Referer to the router root ("/") for ALL subsequent requests.
        # Admin ASP pages are loaded inside the frameset at "/", so the router
        # expects Referer: http://192.168.100.1/ — not login.cgi.
        # Using login.cgi as Referer caused HTTP 403 on every admin page.
        self.session.headers["Referer"] = self.base + "/"

        # Fetch a fresh X_HW_Token right after login.
        # GetRandToken.asp also needs the correct Referer, which is now set.
        self._refresh_token()

        # Resume: scan previously downloaded files so we don't re-fetch them
        # and so we can discover links that were not followed before.
        if not self.force:
            n = self._resume_from_disk()
            if n:
                log.info("Resume: %d existing file(s) loaded from disk.", n)

        # --- Dynamic seeding ---
        # Do not seed URLs that are in _AUTH_PAGE_PATHS (/, /index.asp,
        # /login.asp) because they always return the login form and would
        # trigger false session-expiry detection.  Links discovered from
        # _save_pre_auth() already seed all JS/CSS/image resources.
        # Only seed the post-login URL if it resolves to a genuine admin page.
        post_path = urllib.parse.urlparse(post_login_url or "").path.lower()
        if post_login_url and post_path not in _AUTH_PAGE_PATHS:
            self._enqueue(post_login_url)

        log.info("Seeding from pre-auth pages + post-login URL. Dynamic discovery begins.")

        # Exhaust the queue with optional tqdm progress bar
        if tqdm_available:
            self._run_with_progress(_tqdm_cls)
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

    def _run_with_progress(self, _tqdm_cls) -> None:
        """BFS loop with a tqdm progress bar that tracks discovered vs visited."""
        bar = _tqdm_cls(
            desc="Crawling",
            unit="URL",
            dynamic_ncols=True,
            bar_format="{l_bar}{bar}| {n}/{total} [{elapsed}<{remaining}] {postfix}",
        )
        total_seen = len(self._queue) + len(self._visited)
        bar.total = total_seen

        while self._queue:
            url = self._queue.popleft()
            prev_q = len(self._queue)
            self._fetch_and_process(url)
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
        """
        Read *local_path* from disk, extract links, and enqueue new ones.
        Returns the number of newly enqueued URLs.
        """
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

    def _enqueue(self, url: str) -> None:
        """Add *url* to the queue if it has not been visited yet."""
        key = url_key(url)
        if key not in self._visited:
            self._queue.append(url)

    def _save_pre_auth(self, path: str) -> None:
        """
        Download and save a page that is publicly accessible without authentication.

        Called before login() for the main login page (/index.asp).  Saves the
        file for offline analysis, marks the URL visited so the BFS never tries to
        fetch it post-auth (where it returns the login form and triggers false
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
        """
        POST to GetRandToken.asp to refresh both the session idle timer and
        our cached X_HW_Token.
        """
        self._refresh_token()

    def _refresh_token(self) -> None:
        """
        POST to /html/ssmp/common/GetRandToken.asp to get a fresh X_HW_Token.
        The token is stored in _current_token for use in 403 retries.
        Falls back silently if the endpoint is unavailable (e.g. not yet logged in).
        """
        try:
            resp = self.session.post(
                self.base + TOKEN_URL,
                timeout=REQUEST_TIMEOUT,
            )
            token = resp.text.strip()
            if token and len(token) >= 8:
                self._current_token = token
                log.debug("X_HW_Token refreshed: %s…", token[:12])
        except requests.RequestException as exc:
            log.debug("Token refresh failed (non-fatal): %s", exc)

    def _retry_with_token(self, url: str) -> requests.Response | None:
        """
        Retry a 403 request by appending a fresh X_HW_Token as a query
        parameter.  Returns the new response, or None if no token available.

        Some Huawei admin pages check for a valid X_HW_Token even in GET
        requests when accessed directly rather than through the frameset.
        """
        self._refresh_token()
        if not self._current_token:
            return None
        sep = "&" if "?" in url else "?"
        token_url = f"{url}{sep}x.X_HW_Token={self._current_token}"
        try:
            log.debug("403 retry with token: %s", token_url)
            return self.session.get(
                token_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
        except requests.RequestException:
            return None

    def _fetch_and_process(self, url: str) -> None:
        key = url_key(url)
        if key in self._visited:
            return
        self._visited.add(key)

        # Never crawl write-action endpoints
        if _BLOCKED_PATH_RE.search(urllib.parse.urlparse(url).path):
            log.debug("Blocked write-action URL, skipping: %s", url)
            return

        # Login-interface pages (/index.asp, /login.asp) always return the login
        # form after authentication, which would trigger is_session_expired() and
        # start an infinite re-login loop.  They are downloaded pre-auth in run()
        # via _save_pre_auth().  If a local copy exists, parse it for links; do
        # NOT make an authenticated HTTP request to them (even with --force).
        req_path = urllib.parse.urlparse(url).path.lower()
        if req_path in _AUTH_PAGE_PATHS:
            local_auth = url_to_local_path(url, self.output_dir)
            if local_auth.exists() and local_auth.stat().st_size > 0:
                # File saved pre-auth: count as skip and extract its links.
                self._stats["skip"] += 1
                self._parse_local_file(local_auth, url)
                log.debug("Auth page on disk, links extracted: %s", url)
            else:
                # Not on disk (pre-auth download failed or --force run before any
                # pre-auth save).  Log and skip – we must not fetch post-auth.
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
            resp = self.session.get(
                url, timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
        except requests.RequestException as exc:
            log.warning("Request failed for %s – %s", url, exc)
            self._stats["err"] += 1
            return

        # --- Session expiry detection & recovery ---
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
                    # Always restore root as Referer — admin pages are accessed
                    # inside the frameset at "/" and need this header to return 200.
                    self.session.headers["Referer"] = self.base + "/"
                    self._refresh_token()
                    self._visited.discard(key)
                    self._queue.appendleft(url)
                    return
            log.error("Could not recover session after %d attempts", self._relogin_count)
            # Reset counter so the NEXT URL gets MAX_RELOGIN_ATTEMPTS fresh tries.
            self._relogin_count = 0
            self._stats["err"] += 1
            return

        # --- 403 smart retry with X_HW_Token ---
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

        # Content-hash deduplication: skip saving if we already have this
        # exact content (e.g. the same image served under two URLs).
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
