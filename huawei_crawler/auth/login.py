"""Login, session-expiry detection, and login-mode detection."""

import re
import urllib.parse

import requests

from ..config import (
    LOGIN_CGI,
    LOGIN_PAGE,
    RAND_INFO_URL,
    REQUEST_TIMEOUT,
    _LOGIN_MARKERS,
)
from ..logging_setup import log
from ..session import base_url
from .password import b64encode_password, pbkdf2_sha256_password
from .token import get_rand_token


def detect_login_mode(session: requests.Session, host: str) -> str:
    """
    Fetch /index.asp and parse the embedded JavaScript to determine which
    login method the router uses.

    Returns the CfgMode string (e.g. 'MEGACABLE2', 'DVODACOM2WIFI', …).
    Returns an empty string on failure (safe fallback = base64 path).
    """
    try:
        resp = session.get(base_url(host) + LOGIN_PAGE, timeout=REQUEST_TIMEOUT)
        cfg_mode = re.search(r"""var\s+CfgMode\s*=\s*['"]([^'"]+)['"]""", resp.text)
        return cfg_mode.group(1) if cfg_mode else ""
    except Exception:
        return ""


def login(session: requests.Session, host: str, username: str, password: str) -> str | None:
    """
    Authenticate against the HG8145V5 admin interface.

    Auto-detects the login method from the login page:
      • Most configs (e.g. MEGACABLE2):
          GET /index.asp → POST /asp/GetRandCount.asp for CSRF token
          POST /login.cgi  UserName / base64(Password) / Language / x.X_HW_Token
      • CfgMode == 'DVODACOM2WIFI':
          POST /asp/GetRandInfo.asp  to get [token, salt, iterations]
          PBKDF2+SHA256(password, salt, iterations) → base64
          POST /login.cgi  UserName / encoded_password / Language / x.X_HW_Token

    Returns the post-login redirect URL (the admin home page) on success,
    or None on failure.  The URL is used as a seed and as the Referer header.
    """
    # Step 1 – load login page; also detect router config mode
    cfg_mode = detect_login_mode(session, host)
    log.debug("Router CfgMode: %r", cfg_mode)

    log.debug("Cookies after GET /index.asp: %s", dict(session.cookies))

    use_sha256 = cfg_mode.upper() == "DVODACOM2WIFI"

    if use_sha256:
        # --- PBKDF2+SHA256 path (index.asp loginWithSha256) ---
        # POST /asp/GetRandInfo.asp -> dealDataWithFun returns [token, salt, iters]
        try:
            info_resp = session.post(
                base_url(host) + RAND_INFO_URL + "?&1=1",
                data={"Username": username},
                timeout=REQUEST_TIMEOUT,
            )
            info_resp.raise_for_status()
            # Response is a JS function-call string like:
            #   function(){return ['TOKEN','SALT','1000'];}
            # Extract the array elements.
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

    # Step 3 – submit credentials (common to both paths)
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

    # A successful login redirects away from the login form.
    # If the response still contains the login form, credentials were wrong.
    if any(marker in resp.text for marker in _LOGIN_MARKERS):
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

    redirect_url = urllib.parse.urljoin(base_url(host), redirect_path)
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


def is_session_expired(resp: requests.Response) -> bool:
    """
    Return True only when the router has genuinely redirected to the login form.

    Avoids two classes of false positives that caused session-expiry loops:
      * URL-based false positive: 'login' in url matches /Cuscss/login.css, safelogin.js, etc.
        -> now checks only the specific login-page paths /index.asp and /login.asp.
      * Body-based false positive: JS files contain login marker strings as DOM element IDs
        (e.g. document.getElementById('txt_Password')), CSS contains .loginbutton.
        -> now ignores non-HTML content types and requires ALL markers together.

    Also detects the post-logout state: logout.html resets the session cookie to
    'Cookie=default' (document.cookie = 'Cookie=default;path=/') which is a clear
    sign the session has been terminated.
    """
    cookie_val = resp.cookies.get("Cookie", "")
    if cookie_val.lower() == "default":
        return True

    # A redirect to the specific login-page paths is the most reliable signal.
    # We only match the path (not substrings of other paths).
    final_path = urllib.parse.urlparse(resp.url).path.lower()
    if final_path in ("/index.asp", "/login.asp"):
        return True

    # Non-HTML responses (JS, CSS, images) can legitimately contain login-related
    # identifier strings – skip the body check for them entirely.
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if ct and ct not in ("text/html", "application/xhtml+xml"):
        return False

    # A genuine login form has ALL three markers present at the same time.
    # Using all() prevents a single marker in an HTML snippet from firing.
    return all(marker in resp.text for marker in _LOGIN_MARKERS)
