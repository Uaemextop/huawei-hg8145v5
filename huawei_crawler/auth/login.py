"""
Router login functionality.

Handles authentication with the Huawei HG8145V5 router admin interface,
supporting multiple login methods (base64 and PBKDF2+SHA256).
"""

import base64
import hashlib
import logging
import re
import urllib.parse

import requests

from huawei_crawler.network.client import base_url
from huawei_crawler.auth.session import is_session_expired


# Configuration constants
LOGIN_PAGE = "/index.asp"
LOGIN_CGI = "/login.cgi"
RAND_COUNT_URL = "/asp/GetRandCount.asp"
RAND_INFO_URL = "/asp/GetRandInfo.asp"  # used by DVODACOM2WIFI (PBKDF2 path)
REQUEST_TIMEOUT = 15  # seconds per HTTP request

# Signals that the session has expired – checked only against HTML responses
_LOGIN_MARKERS = ("txt_Username", "txt_Password", "loginbutton")

log = logging.getLogger("hg8145v5-crawler")


def b64encode_password(password: str) -> str:
    """
    Replicate the router's  base64encode(Password.value)  from util.js.
    Standard RFC 4648 Base64 over the UTF-8 bytes of the password string.
    Used when CfgMode != 'DVODACOM2WIFI'.

    Args:
        password: Plain text password

    Returns:
        Base64-encoded password string
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def pbkdf2_sha256_password(password: str, salt: str, iterations: int) -> str:
    """
    Replicate the loginWithSha256() function from index.asp (CfgMode DVODACOM2WIFI):

      1. PBKDF2(password, salt, {keySize:8, hasher:SHA256, iterations:N})
         → 32 bytes (keySize 8 = 8 × 32-bit words)
      2. CryptoJS.SHA256(pbkdf2.toString())  where .toString() gives hex
         → SHA-256 over the UTF-8 bytes of the PBKDF2 hex string
      3. Base64(sha256_hex.encode('utf-8'))  – CryptoJS Utf8.parse + Base64.stringify

    Args:
        password: Plain text password
        salt: Salt value from GetRandInfo.asp
        iterations: Number of PBKDF2 iterations

    Returns:
        Encoded password string
    """
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=32,  # keySize:8 means 8 * 32-bit words = 32 bytes
    )
    pbkdf2_hex = dk.hex()  # step 1 → hex string
    sha256_hex = hashlib.sha256(pbkdf2_hex.encode("utf-8")).hexdigest()  # step 2
    return base64.b64encode(sha256_hex.encode("utf-8")).decode("ascii")  # step 3


def detect_login_mode(session: requests.Session, host: str) -> str:
    """
    Fetch /index.asp and parse the embedded JavaScript to determine which
    login method the router uses.

    Args:
        session: Requests session instance
        host: Router IP address or hostname

    Returns:
        The CfgMode string (e.g. 'MEGACABLE2', 'DVODACOM2WIFI', …).
        Returns an empty string on failure (safe fallback = base64 path).
    """
    try:
        resp = session.get(base_url(host) + LOGIN_PAGE, timeout=REQUEST_TIMEOUT)
        cfg_mode = re.search(r"""var\s+CfgMode\s*=\s*['"]([^'"]+)['"]""", resp.text)
        return cfg_mode.group(1) if cfg_mode else ""
    except Exception:
        return ""


def get_rand_token(session: requests.Session, host: str) -> str:
    """
    POST to /asp/GetRandCount.asp to obtain the one-time anti-CSRF token
    used as 'x.X_HW_Token' in the login form.

    Args:
        session: Requests session instance
        host: Router IP address or hostname

    Returns:
        CSRF token string

    Raises:
        requests.RequestException: If the request fails
    """
    url = base_url(host) + RAND_COUNT_URL
    resp = session.post(url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    token = resp.text.strip()
    log.debug("X_HW_Token: %s", token)
    return token


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

    Args:
        session: Requests session instance
        host: Router IP address or hostname
        username: Admin username
        password: Admin password

    Returns:
        The post-login redirect URL (the admin home page) on success,
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
        # NOTE: We do NOT set domain= to allow the router's Set-Cookie response
        # to properly update this cookie value after successful authentication.
        # IMPORTANT: Clear existing cookies first to prevent duplicate Cookie entries
        # that cause CookieConflictError when the router sets the authenticated cookie.
        session.cookies.clear()
        session.cookies.set(
            "Cookie",
            "body:Language:english:id=-1",
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

    # Debug: Log response headers and cookies from login.cgi
    log.debug("login.cgi response status: %s", resp.status_code)
    log.debug("login.cgi Set-Cookie headers: %s", resp.headers.get('Set-Cookie'))
    log.debug("login.cgi response cookies: %s", dict(resp.cookies))

    # Deduplicate cookies to prevent CookieConflictError
    # If the router sets a cookie with domain while we have one without domain,
    # we can end up with duplicates. Keep only the most recent (authenticated) cookie.
    cookie_list = list(session.cookies)
    if len(cookie_list) > 1:
        # Find all cookies named "Cookie"
        cookie_entries = [c for c in cookie_list if c.name == "Cookie"]
        if len(cookie_entries) > 1:
            log.debug("Found %d duplicate 'Cookie' entries, keeping only the last one", len(cookie_entries))
            # Remove all but the last one (most recent, which should be the authenticated one)
            for cookie_to_remove in cookie_entries[:-1]:
                session.cookies.clear(cookie_to_remove.domain, cookie_to_remove.path, cookie_to_remove.name)

    log.debug("Session cookies after login.cgi POST: %s", dict(session.cookies))

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

    # Log cookies after login.cgi POST to debug session state
    log.debug("Cookies immediately after login.cgi POST: %s", dict(session.cookies))

    try:
        follow_resp = session.get(
            redirect_url, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
        post_login_url = follow_resp.url
        log.debug("Followed JS redirect → %s", post_login_url)
        log.debug("Cookies after following redirect: %s", dict(session.cookies))

        # Verify the redirect didn't send us back to the login page
        if is_session_expired(follow_resp):
            log.error(
                "The redirect to %s returned the login page. "
                "Session may not have been established. "
                "Cookie after redirect: %s",
                redirect_url,
                dict(session.cookies)
            )
            return None
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
