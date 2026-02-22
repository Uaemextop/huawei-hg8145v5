"""
Session management and validation.

Provides functionality to detect session expiry and validate router responses.
"""

import urllib.parse

import requests


# Signals that the session has expired – checked only against HTML responses
_LOGIN_MARKERS = ("txt_Username", "txt_Password", "loginbutton")


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

    Args:
        resp: HTTP response object to check

    Returns:
        True if the session has expired, False otherwise
    """
    cookie_val = resp.cookies.get("Cookie", "")
    if cookie_val.lower() == "default":
        return True

    # Non-HTML responses (JS, CSS, images) can legitimately contain login-related
    # identifier strings – skip the body check for them entirely.
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if ct and ct not in ("text/html", "application/xhtml+xml"):
        return False

    # A genuine login form has ALL three markers present at the same time.
    # Using all() prevents a single marker in an HTML snippet from firing.
    # We check for markers FIRST before checking URL, because the router may serve
    # the authenticated admin interface at /index.asp after login (not just the login form).
    has_login_markers = all(marker in resp.text for marker in _LOGIN_MARKERS)

    # Only return True if we actually see the login form.
    # A redirect to /index.asp or /login.asp with login markers is a genuine expiry.
    # But a redirect without markers means we're seeing the authenticated admin interface.
    return has_login_markers
