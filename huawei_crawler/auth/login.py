"""
Login functions for the Huawei HG8145V5 router.

Implements the two-step login flow:
  1. ``GET /index.asp`` → detect CfgMode (MEGACABLE2, DVODACOM2WIFI, …)
  2. ``POST /asp/GetRandCount.asp`` (or ``GetRandInfo.asp``) for a CSRF token
  3. ``POST /login.cgi`` with encoded credentials

Key fix vs. the original single-file crawler:
  • **Cookie cleanup before login** – the browser's ``LoginSubmit()`` function
    expires any existing cookies before setting the pre-login cookie.  The
    original crawler did not replicate this, leading to *duplicate* ``Cookie``
    entries in the cookie jar (one manually set, one from the server response).
    When both were sent together the router rejected the request, causing an
    infinite session-expiry / re-login loop.
  • **Session validation after following the JS redirect** – ensures the
    redirect target (``/``) does not itself return the login form (which would
    mean the credentials are wrong or the cookie was not accepted).
"""

import base64
import hashlib
import re
import urllib.parse

import requests

from huawei_crawler.config import (
    LOGIN_CGI,
    LOGIN_MARKERS,
    LOGIN_PAGE,
    RAND_COUNT_URL,
    RAND_INFO_URL,
    REQUEST_TIMEOUT,
)
from huawei_crawler.auth.session import base_url, is_session_expired
from huawei_crawler.utils.log import log


# ---------------------------------------------------------------------------
# Password encoding
# ---------------------------------------------------------------------------

def b64encode_password(password: str) -> str:
    """
    Replicate the router's ``base64encode(Password.value)`` from util.js.
    Standard RFC 4648 Base64 over the UTF-8 bytes of the password string.
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def pbkdf2_sha256_password(password: str, salt: str, iterations: int) -> str:
    """
    Replicate ``loginWithSha256()`` from index.asp (CfgMode DVODACOM2WIFI):

      1. PBKDF2(password, salt, keySize=8, SHA256, iterations)
      2. SHA-256 over the hex string of the PBKDF2 output
      3. Base64 of that SHA-256 hex string
    """
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=32,
    )
    pbkdf2_hex = dk.hex()
    sha256_hex = hashlib.sha256(pbkdf2_hex.encode("utf-8")).hexdigest()
    return base64.b64encode(sha256_hex.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Login helpers
# ---------------------------------------------------------------------------

def detect_login_mode(session: requests.Session, host: str) -> str:
    """
    Fetch ``/index.asp`` and parse the embedded JS to determine the CfgMode.

    Returns the CfgMode string (e.g. ``'MEGACABLE2'``) or ``""`` on failure.
    """
    try:
        resp = session.get(base_url(host) + LOGIN_PAGE, timeout=REQUEST_TIMEOUT)
        cfg_mode = re.search(r"""var\s+CfgMode\s*=\s*['"]([^'"]+)['"]""", resp.text)
        return cfg_mode.group(1) if cfg_mode else ""
    except Exception:
        return ""


def get_rand_token(session: requests.Session, host: str) -> str:
    """
    ``POST`` to ``/asp/GetRandCount.asp`` to obtain the one-time CSRF token.
    """
    url = base_url(host) + RAND_COUNT_URL
    resp = session.post(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    token = resp.text.strip()
    log.debug("X_HW_Token: %s", token)
    return token


# ---------------------------------------------------------------------------
# Main login entry point
# ---------------------------------------------------------------------------

def login(session: requests.Session, host: str, username: str, password: str) -> str | None:
    """
    Authenticate against the HG8145V5 admin interface.

    Returns the post-login redirect URL on success, or ``None`` on failure.

    **Session-cookie fix**: before submitting credentials the cookie jar is
    cleared and a single pre-login cookie is set, exactly replicating the
    browser's ``LoginSubmit()`` behaviour from ``index.asp``.  This prevents
    duplicate ``Cookie`` entries that confuse the router into treating the
    request as unauthenticated.
    """
    # Step 1 – detect router config mode
    cfg_mode = detect_login_mode(session, host)
    log.debug("Router CfgMode: %r", cfg_mode)

    use_sha256 = cfg_mode.upper() == "DVODACOM2WIFI"

    # ---------------------------------------------------------------
    # FIX: Clear *all* cookies before setting the pre-login cookie.
    #
    # The browser's LoginSubmit() does this (index.asp lines 448-453):
    #   var cookie = document.cookie;
    #   if ("" != cookie) {
    #       var date = new Date();
    #       date.setTime(date.getTime() - 10000);
    #       document.cookie = cookie + ";expires=" + date.toGMTString();
    #   }
    #
    # Without this step the requests session accumulates cookies from
    # detect_login_mode(), _save_pre_auth(), and previous login
    # attempts.  The server then receives conflicting Cookie headers
    # and rejects the session immediately after login.cgi returns.
    # ---------------------------------------------------------------
    session.cookies.clear()

    if use_sha256:
        # --- PBKDF2+SHA256 path (DVODACOM2WIFI) ---
        session.cookies.set(
            "Cookie",
            "body:Language:english:id=-1",
            domain=host,
            path="/",
        )
        try:
            info_resp = session.post(
                base_url(host) + RAND_INFO_URL + "?&1=1",
                data={"Username": username},
                timeout=REQUEST_TIMEOUT,
            )
            info_resp.raise_for_status()
            m = re.search(r"\[([^\]]+)\]", info_resp.text)
            if not m:
                log.error("Could not parse GetRandInfo response: %s", info_resp.text[:120])
                return None
            parts = [p.strip().strip("'\"") for p in m.group(1).split(",")]
            if len(parts) < 3:
                log.error("Unexpected GetRandInfo parts: %s", parts)
                return None
            token, salt, iterations_str = parts[0], parts[1], parts[2]
            iterations = int(iterations_str)
            encoded_pw = pbkdf2_sha256_password(password, salt, iterations)
            log.debug("PBKDF2 login: token=%s salt=%s iters=%d", token, salt, iterations)
        except (requests.RequestException, ValueError) as exc:
            log.error("GetRandInfo failed: %s", exc)
            return None
    else:
        # --- Base64 path (MEGACABLE2 and most other configs) ---
        # Set the pre-login cookie exactly as the browser does:
        #   var cookie2 = "Cookie=body:Language:english:id=-1;path=/";
        #   document.cookie = cookie2;
        session.cookies.set(
            "Cookie",
            "body:Language:english:id=-1",
            domain=host,
            path="/",
        )
        try:
            token = get_rand_token(session, host)
        except requests.RequestException as exc:
            log.error("Failed to get auth token: %s", exc)
            return None
        encoded_pw = b64encode_password(password)

    # Step 3 – submit credentials
    payload = {
        "UserName": username,
        "PassWord": encoded_pw,
        "Language": "english",
        "x.X_HW_Token": token,
    }

    try:
        resp = session.post(
            base_url(host) + LOGIN_CGI,
            data=payload,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        log.error("Login POST failed: %s", exc)
        return None

    if any(marker in resp.text for marker in LOGIN_MARKERS):
        log.error(
            "Login failed – router returned the login form. "
            "Check your credentials or try --debug for more info."
        )
        return None

    # ---------------------------------------------------------------
    # FIX: Ensure only the server-set session cookie remains.
    #
    # After a successful POST to login.cgi the server responds with a
    # Set-Cookie that replaces the pre-login id=-1 value with a real
    # session id.  However, due to domain-matching quirks in the
    # requests library, the manually-set cookie and the server-set
    # cookie can co-exist as *separate entries*.  Sending both causes
    # the router to reject the request.
    #
    # We keep ONLY the cookies the server has just set by rebuilding
    # the jar from the response if the server sent Set-Cookie headers.
    # ---------------------------------------------------------------
    if "Set-Cookie" in resp.headers:
        log.debug("Server set cookies in login response – cleaning jar")
        # Keep only server-set cookies (from all responses in the chain)
        _deduplicate_cookies(session, host)

    # Follow the JS redirect (e.g. top.location.replace('/'))
    redirect_path = "/"
    m_js = re.search(
        r"""var\s+pageName\s*=\s*['"]([^'"]+)['"]"""
        r"""|top\.location(?:\.replace)?\s*\(\s*['"]([^'"]+)['"]\s*\)""",
        resp.text,
        re.I,
    )
    if m_js:
        redirect_path = next(
            (g for g in (m_js.group(1), m_js.group(2)) if g is not None and g),
            "/",
        )

    redirect_url = urllib.parse.urljoin(base_url(host), redirect_path)
    try:
        follow_resp = session.get(
            redirect_url, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
        post_login_url = follow_resp.url

        # ---------------------------------------------------------------
        # FIX: Validate the session by checking the follow-up response.
        #
        # If the redirect target still shows the login form the session
        # cookie was not accepted.  Return None so the caller knows
        # login truly failed rather than entering a re-login loop.
        # ---------------------------------------------------------------
        if is_session_expired(follow_resp):
            log.error(
                "Session invalid immediately after login – the follow-up "
                "request to %s returned the login form. "
                "Cookie jar: %s",
                redirect_url,
                list(session.cookies.keys()),
            )
            return None

        log.debug("Followed JS redirect → %s", post_login_url)
    except requests.RequestException as exc:
        log.debug("Could not follow post-login redirect to %s: %s", redirect_url, exc)
        post_login_url = redirect_url

    method_name = "PBKDF2" if use_sha256 else "base64"
    log.info(
        "Login successful (HTTP %s, method=%s). Admin home: %s. "
        "Active cookies: %s",
        resp.status_code,
        method_name,
        post_login_url,
        list(session.cookies.keys()),
    )
    log.debug("Cookie values after login: %s", dict(session.cookies))
    return post_login_url


# ---------------------------------------------------------------------------
# Cookie deduplication helper
# ---------------------------------------------------------------------------

def _deduplicate_cookies(session: requests.Session, host: str) -> None:
    """
    Remove duplicate ``Cookie`` entries from the session jar.

    After ``login.cgi`` responds, the jar may contain both the manually-set
    pre-login cookie *and* the server-set session cookie under the same name
    ``Cookie`` but different internal domain representations.  We keep only the
    *last* value (the server-set one) and discard earlier duplicates.
    """
    cookies_named = []
    for cookie in session.cookies:
        if cookie.name == "Cookie":
            cookies_named.append(cookie)

    if len(cookies_named) > 1:
        log.debug(
            "Found %d 'Cookie' entries in jar – deduplicating", len(cookies_named)
        )
        # Keep the last one (from the server response) and remove earlier ones
        for c in cookies_named[:-1]:
            session.cookies.clear(c.domain, c.path, c.name)
