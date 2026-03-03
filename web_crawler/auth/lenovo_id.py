"""
Lenovo ID OAuth authentication client.

Implements the multi-step OAuth flow used by the LMSA desktop app to
obtain a WUST token from ``passport.lenovo.com`` and exchange it for a
LMSA JWT via ``lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml``.

OAuth flow (reverse-engineered from LMSA .NET assemblies + DotNetBrowserLog)
-----------------------------------------------------------------------------
1. GET  /wauthen5/gateway?…&lenovoid.realm=lmsaclient
         → 302 to /wauthen5/preLogin
         Collect session cookies: JSESSIONID, lenovoid.webLoginSignkey, _abck.

2. POST /wauthen5/userLogin  (form-encoded, replays cookies from step 1)
         Hidden fields: lenovoid.action, lenovoid.realm, lenovoid.cb, …
         lenovoid.cb = https://lmsa.prod.cloud.lenovo.com/Tips/lenovoIdSuccess.html
         On success: server redirects to the callback URL with
         ``?lenovoid.wust=<TOKEN>`` as a query parameter.
         LMSA's embedded Chromium (DotNetBrowser) intercepts this navigation
         before the request fires and extracts the WUST token from the URL.

3. POST lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml
         RequestModel body with dparams.wust + dparams.guid.
         On success: 200, code "0000", JWT in ``Authorization`` header.

Security notes
--------------
* Credentials must never be hard-coded.  Pass them at runtime via the
  ``LMSA_EMAIL`` / ``LMSA_PASSWORD`` environment variables or the
  ``--lmsa-email`` / ``--lmsa-password`` CLI flags.
* The Akamai _abck cookie is issued by the server and replayed
  transparently by the requests.Session cookie jar; no injection needed.
* passport.lenovo.com sets ``HttpOnly; Secure`` on all auth cookies so
  they are never readable from JavaScript.
"""

from __future__ import annotations

import os
import re
import uuid
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

import requests

from web_crawler.auth.lmsa import (
    LMSASession,
    LMSA_BASE_URL,
    _BASE_HEADERS,
    _CODE_OK,
    _log,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PASSPORT_BASE = "https://passport.lenovo.com"
# Real paths confirmed from DotNetBrowser log (LMSA 7.4.3.4)
_GATEWAY_PATH   = "/wauthen5/gateway"
_PRELOGIN_PATH  = "/wauthen5/preLogin"
_USERLOGIN_PATH = "/wauthen5/userLogin"
_LMSA_REALM = "lmsaclient"

# OAuth success callback URL (internal Lenovo host, never actually loaded).
# LMSA's embedded Chromium (DotNetBrowser) intercepts navigation to this URL
# and extracts lenovoid.wust from the query string before the request fires.
_LMSA_CB_URL = "https://lmsa.prod.cloud.lenovo.com/Tips/lenovoIdSuccess.html"

# Hidden form fields the LMSA app sets when initiating OAuth.
# Source: DotNetBrowserLog URLs observed in LMSA 7.4.3.4 session data.
_LMSA_FORM_DEFAULTS: dict[str, str] = {
    "lenovoid.action":       "uilogin",
    "lenovoid.realm":        _LMSA_REALM,
    "lenovoid.lang":         "en_US",
    "lenovoid.ctx":          "null",
    "lenovoid.uinfo":        "null",
    "lenovoid.cb":           _LMSA_CB_URL,
    "lenovoid.vb":           "null",
    "lenovoid.display":      "null",
    "lenovoid.idp":          "null",
    "lenovoid.source":       "lmsaclient",
    "lenovoid.thirdname":    "null",
    "lenovoid.idreinfo":     "null",
    "lenovoid.autologinname":"null",
    "lenovoid.userType":     "null",
    "lenovoid.sdk":          "null",
    "lenovoid.oauthstate":   "null",
    "lenovoid.options":      "null",
    "lenovoid.hidesocial":   "null",
    "lenovoid.deviceId":     "null",
}

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

_WUST_RE = re.compile(r"lenovoid\.wust=([^&\s\"']+)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_hidden_fields(html: str) -> dict[str, str]:
    """Return all ``<input type="hidden">`` name→value pairs from *html*."""
    fields: dict[str, str] = {}
    for m in re.finditer(
        r'<input[^>]+type=["\']?hidden["\']?[^>]+>', html, re.IGNORECASE
    ):
        tag = m.group(0)
        nm = re.search(r'name=["\']([^"\']+)["\']', tag)
        vm = re.search(r'value=["\']([^"\']*)["\']', tag)
        if nm:
            fields[nm.group(1)] = vm.group(1) if vm else ""
    return fields


def _find_wust(text: str) -> Optional[str]:
    """Extract WUST token from a URL or HTML fragment."""
    m = _WUST_RE.search(text)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# LenovoIDAuth
# ---------------------------------------------------------------------------

class LenovoIDAuth:
    """Lenovo ID OAuth client — obtains a WUST token and exchanges it for a
    LMSA JWT.

    Usage::

        auth = LenovoIDAuth()
        lmsa = auth.login(email="user@example.com", password="secret")
        if lmsa:
            firmware = lmsa.get_firmware("xt2553-2", region="US")

    Credentials can also be supplied via environment variables so that
    they never appear in source code::

        export LMSA_EMAIL=user@example.com
        export LMSA_PASSWORD=secret

    Then simply call ``LenovoIDAuth().login()`` with no arguments.
    """

    def __init__(
        self,
        lmsa_base_url: str = LMSA_BASE_URL,
        verify_ssl: bool = True,
    ) -> None:
        self._lmsa_base = lmsa_base_url.rstrip("/")
        self._verify_ssl = verify_ssl

        # Shared session preserves all cookies across redirect chains.
        self._sess = requests.Session()
        self._sess.verify = verify_ssl
        self._sess.headers.update({
            "User-Agent":      _BROWSER_UA,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept":          (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,*/*;q=0.8"
            ),
        })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def login(
        self,
        email: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Optional[LMSASession]:
        """Full login flow: Lenovo ID → WUST → LMSA JWT.

        Credentials default to ``LMSA_EMAIL`` / ``LMSA_PASSWORD`` env vars
        when not supplied.

        Returns an authenticated :class:`~web_crawler.auth.lmsa.LMSASession`
        on success, or ``None`` on failure.
        """
        email    = email    or os.environ.get("LMSA_EMAIL", "")
        password = password or os.environ.get("LMSA_PASSWORD", "")

        if not email or not password:
            _log(
                "[LenovoID] Email/password not provided.  "
                "Set LMSA_EMAIL and LMSA_PASSWORD env vars or pass via CLI."
            )
            return None

        wust = self._obtain_wust(email, password)
        if not wust:
            return None

        return self._exchange_wust_for_jwt(wust)

    def login_with_wust(self, wust: str) -> Optional[LMSASession]:
        """Skip OAuth and exchange an already-obtained WUST for a JWT.

        Use this when the WUST token is available from a previous session
        or an external source (e.g. LMSA app cookie export).
        """
        return self._exchange_wust_for_jwt(wust)

    # ------------------------------------------------------------------
    # Step 1+2: Lenovo ID OAuth → WUST token
    # ------------------------------------------------------------------

    def _obtain_wust(self, email: str, password: str) -> Optional[str]:
        """Run the Lenovo ID login form flow and return the WUST token.

        Uses the ``/wauthen5/`` endpoints confirmed by DotNetBrowserLog analysis
        of LMSA 7.4.3.4.  The callback URL points to the internal
        ``lmsa.prod.cloud.lenovo.com`` host; WUST is extracted from the redirect
        URL before the browser (or requests) actually loads it.
        """
        # --- Step 1: Gateway → preLogin (collects JSESSIONID + sign-key) ---
        gateway_url = (
            f"{PASSPORT_BASE}{_GATEWAY_PATH}"
            f"?lenovoid.action=uilogin&lenovoid.realm={_LMSA_REALM}"
            f"&lenovoid.lang=en_US"
            f"&lenovoid.cb={requests.utils.quote(_LMSA_CB_URL, safe='')}"
        )
        _log(f"[LenovoID] Loading OAuth gateway: {gateway_url}")
        try:
            r = self._sess.get(
                gateway_url,
                timeout=30,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            _log(f"[LenovoID] gateway request failed: {exc}")
            return None

        if r.status_code != 200:
            _log(f"[LenovoID] preLogin HTTP {r.status_code}")
            return None

        # Merge server-supplied hidden fields over our defaults.
        form_fields = dict(_LMSA_FORM_DEFAULTS)
        form_fields.update(_extract_hidden_fields(r.text))
        # Override lenovoid.cb to the real callback value in case the server
        # injected a different one.
        form_fields["lenovoid.cb"] = _LMSA_CB_URL
        form_fields["username"] = email
        form_fields["password"] = password

        post_url = urljoin(PASSPORT_BASE, _USERLOGIN_PATH)
        _log(f"[LenovoID] Submitting credentials: {post_url}")

        # --- Step 2: POST credentials, intercept WUST in redirect chain ---
        try:
            r2 = self._sess.post(
                post_url,
                data=form_fields,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer":      r.url,
                    "Origin":       PASSPORT_BASE,
                },
                timeout=30,
                # Don't auto-follow past the callback host — we intercept
                # the WUST from the Location header of the redirect.
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            _log(f"[LenovoID] userLogin POST failed: {exc}")
            return None

        # Follow redirects manually so we can inspect every URL in the chain.
        max_redirects = 12
        resp = r2
        history: list[str] = [post_url]
        for _ in range(max_redirects):
            loc = resp.headers.get("Location", "")
            if not loc:
                break
            # Resolve relative Location headers.
            if not loc.startswith("http"):
                loc = urljoin(PASSPORT_BASE, loc)
            history.append(loc)
            wust = _find_wust(loc)
            if wust:
                _log("[LenovoID] ✓ WUST token extracted from redirect URL")
                return wust
            # Stop if we hit the callback host (the LMSA app never loads it).
            if "lmsa.prod.cloud.lenovo.com" in loc:
                _log("[LenovoID] Reached LMSA callback URL but no WUST found")
                break
            try:
                resp = self._sess.get(
                    loc,
                    headers={"Referer": history[-2]},
                    timeout=20,
                    allow_redirects=False,
                )
            except requests.RequestException:
                break

        # Last resort: search body of final response.
        wust = _find_wust(resp.url) or _find_wust(resp.text)
        if wust:
            _log("[LenovoID] ✓ WUST token found in response body")
            return wust

        # Diagnose failure from final page body.
        body_lower = resp.text.lower()
        if "incorrect" in body_lower or "invalid" in body_lower or "wrong" in body_lower:
            _log("[LenovoID] ✗ Login failed: invalid credentials")
        elif "captcha" in body_lower or "verify" in body_lower or "robot" in body_lower:
            _log(
                "[LenovoID] ✗ Login blocked: CAPTCHA / bot-detection triggered.  "
                "Complete a browser login first so the Akamai session is trusted."
            )
        elif "locked" in body_lower or "suspended" in body_lower:
            _log("[LenovoID] ✗ Account locked or suspended")
        elif resp.status_code == 403:
            _log(
                "[LenovoID] ✗ 403 from passport server — session cookies may "
                "be stale or Akamai Bot Manager blocked the request"
            )
        else:
            _log(
                f"[LenovoID] ✗ Login failed: no WUST found "
                f"(HTTP {resp.status_code}, last URL: {resp.url})\n"
                f"  Redirect chain: {' → '.join(history[-4:])}"
            )
        return None

    # ------------------------------------------------------------------
    # Step 3: WUST → LMSA JWT
    # ------------------------------------------------------------------

    def _exchange_wust_for_jwt(self, wust: str) -> Optional[LMSASession]:
        """POST the WUST to ``lenovoIdLogin.jhtml`` and return an
        authenticated :class:`LMSASession`."""
        guid = str(uuid.uuid4()).upper()
        url = f"{self._lmsa_base}/Interface/user/lenovoIdLogin.jhtml"

        body = {
            "client":      {"version": "7.4.3.4"},
            "dparams":     {"wust": wust, "guid": guid},
            "language":    "en-US",
            "windowsInfo": "Windows 10, 64bit",
        }
        hdrs = {
            **_BASE_HEADERS,
            "guid": guid,
        }

        _log(f"[LenovoID] Exchanging WUST for JWT: {url}")
        try:
            r = requests.post(url, json=body, headers=hdrs,
                              timeout=30, verify=self._verify_ssl)
        except requests.RequestException as exc:
            _log(f"[LenovoID] lenovoIdLogin POST failed: {exc}")
            return None

        # JWT may arrive in the Authorization header.
        jwt = None
        auth_hdr = r.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            jwt = auth_hdr[len("Bearer "):]

        try:
            data = r.json()
        except ValueError:
            _log(f"[LenovoID] Non-JSON response from lenovoIdLogin: "
                 f"{r.text[:200]}")
            return None

        code = data.get("code", "")
        if code == "402":
            _log("[LenovoID] ✗ WUST rejected (expired or invalid)")
            return None
        if code == "403":
            _log("[LenovoID] ✗ Invalid token (server-side)")
            return None
        if code != _CODE_OK:
            _log(f"[LenovoID] ✗ lenovoIdLogin error {code}: "
                 f"{data.get('desc', '')}")
            return None

        # JWT may also be embedded in the response body.
        if not jwt:
            content = data.get("content") or data.get("data") or {}
            if isinstance(content, dict):
                jwt = content.get("token") or content.get("jwt")

        session = LMSASession(
            base_url=self._lmsa_base,
            guid=guid,
        )
        if jwt:
            # Inject token directly into the private field.
            session._jwt_token = jwt
            session._session.headers["Authorization"] = f"Bearer {jwt}"
            _log("[LenovoID] ✓ JWT token received — session ready")
        else:
            _log(
                "[LenovoID] ✓ lenovoIdLogin succeeded (code 0000) "
                "but no explicit JWT in response — session may be usable"
            )

        return session
