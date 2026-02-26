"""
huawei_crawler.auth
===================
Authentication helpers for the Huawei HG8145V5 router admin panel.

Responsibilities
----------------
* Detect the router's login mode (base64 vs PBKDF2+SHA256) from /index.asp.
* Obtain the one-time anti-CSRF token from GetRandCount.asp or GetRandInfo.asp.
* Submit credentials to /login.cgi and follow the JS post-login redirect.
* Refresh the X_HW_Token via GetRandToken.asp – **without** allowing that POST
  to reset the session cookie (the token endpoint may return Set-Cookie:
  Cookie=default for unauthenticated or missing endpoints, which would
  silently invalidate the live session).
* Detect session expiry in HTTP responses so the crawler can re-authenticate.
"""

import base64
import hashlib
import logging
import re
import urllib.parse

import requests

from .config import (
    LOGIN_PAGE, LOGIN_CGI, RAND_COUNT_URL, RAND_INFO_URL, TOKEN_URL,
    REQUEST_TIMEOUT, LOGIN_MARKERS, MAX_TOKEN_LENGTH,
)

log = logging.getLogger("hg8145v5-crawler")


# ---------------------------------------------------------------------------
# Password encoding
# ---------------------------------------------------------------------------

def b64encode_password(password: str) -> str:
    """
    Replicate the router's ``base64encode(Password.value)`` from util.js.
    Standard RFC 4648 Base64 over the UTF-8 bytes of the password string.
    Used when CfgMode != 'DVODACOM2WIFI'.
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def pbkdf2_sha256_password(password: str, salt: str, iterations: int) -> str:
    """
    Replicate ``loginWithSha256()`` from index.asp (CfgMode DVODACOM2WIFI):

    1. PBKDF2(password, salt, {keySize:8, hasher:SHA256, iterations:N}) → 32 bytes
    2. CryptoJS.SHA256(pbkdf2.toString())  where .toString() gives hex
    3. Base64(sha256_hex.encode('utf-8'))
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
# Login mode detection
# ---------------------------------------------------------------------------

def detect_login_mode(session: requests.Session, host: str) -> str:
    """
    Fetch ``/index.asp`` and parse the embedded JavaScript to determine
    which login method the router uses.

    Returns the CfgMode string (e.g. 'MEGACABLE2', 'DVODACOM2WIFI', …).
    Returns an empty string on failure (safe fallback = base64 path).
    """
    from .config import DEFAULT_HOST  # avoid circular
    base = f"http://{host}"
    try:
        resp = session.get(base + LOGIN_PAGE, timeout=REQUEST_TIMEOUT)
        cfg_mode = re.search(r"""var\s+CfgMode\s*=\s*['"]([^'"]+)['"]""", resp.text)
        return cfg_mode.group(1) if cfg_mode else ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Anti-CSRF token
# ---------------------------------------------------------------------------

def get_rand_token(session: requests.Session, host: str) -> str:
    """
    POST to ``/asp/GetRandCount.asp`` to obtain the one-time anti-CSRF token
    used as ``x.X_HW_Token`` in the login form.
    """
    url = f"http://{host}" + RAND_COUNT_URL
    resp = session.post(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    token = resp.text.strip()
    log.debug("X_HW_Token: %s", token)
    return token


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def login(
    session: requests.Session, host: str, username: str, password: str
) -> "str | None":
    """
    Authenticate against the HG8145V5 admin interface.

    Auto-detects the login method:
      • Most configs (e.g. MEGACABLE2):
          GET /index.asp → POST /asp/GetRandCount.asp for CSRF token
          POST /login.cgi  UserName / base64(Password) / Language / x.X_HW_Token
      • CfgMode == 'DVODACOM2WIFI':
          POST /asp/GetRandInfo.asp  to get [token, salt, iterations]
          PBKDF2+SHA256(password, salt, iterations) → base64
          POST /login.cgi  UserName / encoded_password / Language / x.X_HW_Token

    Returns the post-login redirect URL (the admin home page) on success,
    or None on failure.  The URL is used as the Referer header base.
    """
    base = f"http://{host}"

    # Step 1 – load login page; detect router config mode
    cfg_mode = detect_login_mode(session, host)
    log.debug("Router CfgMode: %r", cfg_mode)
    log.debug("Cookies after GET /index.asp: %s", dict(session.cookies))

    use_sha256 = cfg_mode.upper() == "DVODACOM2WIFI"

    if use_sha256:
        # --- PBKDF2+SHA256 path (index.asp loginWithSha256) ---
        try:
            info_resp = session.post(
                base + RAND_INFO_URL + "?&1=1",
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
        # --- Base64 path (standard for MEGACABLE2 and most other configs) ---
        # Set the pre-login cookie to mimic what the login page JS does:
        #   var cookie2 = "Cookie=body:Language:english:id=-1;path=/";
        #   document.cookie = cookie2;
        # NOTE: in document.cookie syntax ';path=/' is a COOKIE ATTRIBUTE,
        # not part of the value.  We specify it via the path= kwarg here so
        # the router receives the correct value: 'body:Language:english:id=-1'.
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

    # Step 2 – submit credentials (common to both paths)
    payload = {
        "UserName": username,
        "PassWord": encoded_pw,
        "Language": "english",
        "x.X_HW_Token": token,
    }

    try:
        resp = session.post(
            base + LOGIN_CGI,
            data=payload,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        log.error("Login POST failed: %s", exc)
        return None

    # A successful login redirects away from the login form.
    if any(marker in resp.text for marker in LOGIN_MARKERS):
        log.error(
            "Login failed – router returned the login form. "
            "Check your credentials or try --debug for more info."
        )
        return None

    # The router's login.cgi always returns HTTP 200 with a *JavaScript*
    # redirect (e.g. "var pageName = '/'; top.location.replace(pageName);").
    # requests does NOT execute JavaScript, so resp.url stays at login.cgi
    # and we would wrongly set Referer = login.cgi for all admin pages
    # (causing 403 on every admin ASP page).
    # We must manually follow the JS redirect to get the real admin home URL.
    redirect_path = "/"
    m_js = re.search(
        r"""var\s+pageName\s*=\s*['"]([^'"]+)['"]|top\.location(?:\.replace)?\s*\(\s*['"]([^'"]+)['"]\s*\)""",
        resp.text,
        re.I,
    )
    if m_js:
        redirect_path = next(
            (g for g in (m_js.group(1), m_js.group(2)) if g is not None and g),
            "/",
        )

    redirect_url = urllib.parse.urljoin(base, redirect_path)
    try:
        follow_resp = session.get(
            redirect_url, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
        post_login_url = follow_resp.url
        log.debug("Followed JS redirect → %s", post_login_url)
    except requests.RequestException as exc:
        log.debug("Could not follow post-login redirect to %s: %s", redirect_url, exc)
        post_login_url = redirect_url

    log.info(
        "Login successful (HTTP %s, method=%s). Admin home: %s. "
        "Active cookies: %s",
        resp.status_code,
        "PBKDF2" if use_sha256 else "base64",
        post_login_url,
        list(session.cookies.keys()),
    )
    log.debug("Cookie values after login: %s", dict(session.cookies))
    return post_login_url


# ---------------------------------------------------------------------------
# Token refresh (session-safe)
# ---------------------------------------------------------------------------

def refresh_token(
    session: requests.Session, host: str, current_token: "str | None" = None
) -> "str | None":
    """
    POST to ``GetRandToken.asp`` to refresh the X_HW_Token.

    **Session-safety**: saves the ``Cookie`` session value before the POST and
    restores it if the endpoint response resets it to ``default``.  The token
    endpoint may not exist on all firmware versions; when it is absent the
    router can respond with ``Set-Cookie: Cookie=default`` (the logged-out
    state), which would silently invalidate an otherwise healthy session.

    Returns the refreshed token string, or *current_token* if the refresh
    fails or the endpoint is unavailable.
    """
    # Snapshot the live session cookie so we can restore it if necessary.
    saved_cookie = session.cookies.get("Cookie")

    try:
        resp = session.post(
            f"http://{host}" + TOKEN_URL,
            timeout=REQUEST_TIMEOUT,
        )

        # If the token endpoint reset the session to the logged-out state,
        # restore the saved (authenticated) cookie value immediately.
        after_cookie = session.cookies.get("Cookie", "")
        if (
            saved_cookie
            and saved_cookie.lower() != "default"
            and after_cookie.lower() == "default"
        ):
            session.cookies.set("Cookie", saved_cookie, domain=host, path="/")
            log.debug("Session cookie restored after token refresh (endpoint reset it)")

        token = resp.text.strip()
        # Validate: a real X_HW_Token is a short alphanumeric string.
        # Reject HTML error pages (contain '<', spaces, etc.) returned when the
        # endpoint is absent or unauthenticated.
        if token and len(token) <= MAX_TOKEN_LENGTH and token.replace("-", "").isalnum():
            log.debug("X_HW_Token refreshed: %s…", token[:12])
            return token
    except requests.RequestException as exc:
        log.debug("Token refresh failed (non-fatal): %s", exc)

    return current_token


# ---------------------------------------------------------------------------
# Session expiry detection
# ---------------------------------------------------------------------------

def is_session_expired(resp: requests.Response) -> bool:
    """
    Return True only when the router has genuinely redirected to the login form.

    Avoids two classes of false positives:
      * URL-based: 'login' in url matches /Cuscss/login.css, safelogin.js, etc.
        → only checks specific login-page paths /index.asp and /login.asp.
      * Body-based: JS files contain login marker strings as DOM element IDs
        → ignores non-HTML content types and requires ALL markers together.

    Also detects the post-logout state where the session cookie is reset to
    ``Cookie=default`` (set by logout.html via ``document.cookie``).
    """
    # Response-set cookie value 'default' signals a logged-out session.
    cookie_val = resp.cookies.get("Cookie", "")
    if cookie_val.lower() == "default":
        return True

    # Redirect to the specific login-page paths is the most reliable signal.
    final_path = urllib.parse.urlparse(resp.url).path.lower()
    if final_path in ("/index.asp", "/login.asp"):
        return True

    # Non-HTML responses (JS, CSS, images) can legitimately contain
    # login-related identifier strings – skip the body check for them.
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if ct and ct not in ("text/html", "application/xhtml+xml"):
        return False

    # A genuine login form has ALL three markers present at the same time.
    return all(marker in resp.text for marker in LOGIN_MARKERS)
