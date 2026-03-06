"""
Lenovo ID OAuth authentication client.

Implements the multi-step OAuth flow used by the LMSA desktop app to
obtain a WUST token from ``passport.lenovo.com`` and exchange it for a
LMSA JWT via ``lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml``.

OAuth flow (reverse-engineered from LMSA .NET assemblies + decompiled Software Fix.exe)
----------------------------------------------------------------------------------------
1. POST /Interface/dictionary/getApiInfo.jhtml  (key="TIP_URL")
         → Returns ``login_url`` = passport.lenovo.com/glbwebauthnv6/preLogin?...
           with ``lenovoid.cb=https://lsa.lenovo.com/Tips/lenovoIdSuccess.html``.

2. Load  login_url in a real browser (LMSA uses WebView2 / DotNetBrowser).
         User logs in; on success the browser is redirected to:
         ``https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?lenovoid.wust=<TOKEN>``
         LMSA's embedded browser intercepts this navigation and extracts the WUST.

3. POST lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml
         RequestModel body with dparams.wust + dparams.guid  (author: false).
         On success: 200, code "0000", JWT in ``Authorization`` response header.

Security notes
--------------
* Credentials must never be hard-coded.  Pass them at runtime via the
  ``LMSA_EMAIL`` / ``LMSA_PASSWORD`` environment variables or the
  ``--lmsa-email`` / ``--lmsa-password`` CLI flags.
* The Akamai _abck cookie is issued by the server and replayed
  transparently; Firefox (Playwright) is used to execute the JS challenge.
* passport.lenovo.com sets ``HttpOnly; Secure`` on all auth cookies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json as _json
import random as _rnd
import shutil
import subprocess
import uuid as _uuid

import os
import re
import uuid
from typing import Optional
from urllib.parse import urljoin

import requests

# curl_cffi – TLS fingerprint impersonation (bypasses Akamai TLS-layer block).
# Standard ``requests`` exposes Python/urllib3 TLS fingerprints that Akamai
# detects and blocks with a TLS reset.  curl_cffi's ``impersonate`` option
# replaces the TLS handshake with an exact copy of Edge's, which Akamai
# accepts and also causes it to set AKA_A2=A organically (confirmed from
# HAR HTTPToolkit_2026-03-03_18-12.har: AKA_A2=A present in /userLogin cookie).
try:
    from curl_cffi import requests as _cffi_requests  # type: ignore[import]
    _CURL_CFFI_AVAILABLE = True
except ImportError:
    _CURL_CFFI_AVAILABLE = False

# DrissionPage – headed Microsoft Edge via CDP for full Akamai JS-sensor bypass.
# Uses Microsoft Edge (headed, via Xvfb in CI) so Akamai's bmak sensor executes
# and validates _abck normally.  HAR confirmed the real LMSA app used Edge 146.
try:
    from DrissionPage import ChromiumPage as _ChromiumPage, ChromiumOptions as _ChromiumOptions  # type: ignore[import]
    _DRISSIONPAGE_AVAILABLE = True
except ImportError:
    _DRISSIONPAGE_AVAILABLE = False

from web_crawler.auth.lmsa import (
    LMSASession,
    LMSA_BASE_URL,
    CLIENT_VERSION,
    _BASE_HEADERS,
    _CODE_OK,
    _log,
)

# Optional Playwright import for Akamai Bot Manager bypass.
# The Lenovo ID login page is protected by Akamai and requires a real browser
# to solve the JS challenge and obtain a valid ``_abck`` cookie.
try:
    from playwright.sync_api import sync_playwright as _sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

# Optional playwright-stealth for anti-detection.
try:
    from playwright_stealth import Stealth as _Stealth
    _STEALTH_AVAILABLE = True
except ImportError:
    _STEALTH_AVAILABLE = False

# Optional zendriver import — a CDP-based "driverless" browser that achieves
# significantly better Akamai Bot Manager bypass rates than Playwright or
# Selenium because it communicates directly via Chrome DevTools Protocol
# without exposing any WebDriver fingerprints.
# Ref: https://pypi.org/project/zendriver/
try:
    import zendriver as _zendriver
    _ZENDRIVER_AVAILABLE = True
except ImportError:
    _ZENDRIVER_AVAILABLE = False

# ulixee/Hero availability check — detect whether Node.js is present and
# the hero_login.js companion script (with its node_modules) has been
# installed.  Hero uses a Human Emulator and a proprietary CDP tunnel that
# is NOT recognised as WebDriver by Akamai Bot Manager, giving it the best
# Akamai bypass rate of all available backends.
# Install: cd web_crawler/auth && npm install
_HERO_SCRIPT = os.path.join(os.path.dirname(__file__), "hero_login.js")
_HERO_AVAILABLE: bool = (
    shutil.which("node") is not None
    and os.path.isfile(_HERO_SCRIPT)
    and os.path.isdir(os.path.join(os.path.dirname(_HERO_SCRIPT), "node_modules"))
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PASSPORT_BASE = "https://passport.lenovo.com"
_LMSA_REALM = "lmsaclient"

# OAuth success callback URL.
# Confirmed from Software Fix.exe decompilation (LoginCallback method):
#   if (uri.LocalPath != "/Tips/lenovoIdSuccess.html") return;
# The host is lsa.lenovo.com (not lmsa.prod.cloud.lenovo.com — that was wrong).
_LMSA_CB_URL = "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html"

# Real login URL obtained from /Interface/dictionary/getApiInfo.jhtml (key=TIP_URL).
# Confirmed by decompiling Software Fix.exe (LenovoIdWindowViewModel):
#   login_url: passport.lenovo.com/glbwebauthnv6/preLogin?...&lenovoid.cb=lsa.lenovo.com/Tips/...
# The old wauthen5/gateway endpoint is legacy; glbwebauthnv6/preLogin is current.
_PRELOGIN_PATH  = "/glbwebauthnv6/preLogin"
_USERLOGIN_PATH = "/glbwebauthnv6/userLogin"

# Hidden form fields the LMSA app sets when initiating OAuth.
# Confirmed from glbwebauthnv6/preLogin page HTML (name attributes).
_LMSA_FORM_DEFAULTS: dict[str, str] = {
    "lenovoid.action":       "uilogin",
    "lenovoid.realm":        _LMSA_REALM,
    "lenovoid.lang":         "es_ES",
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
    # Confirmed from DotNetBrowserLog (LMSA 7.4.3.4):
    # http_header { name: "User-Agent" value: "Mozilla/5.0 (Windows NT 10.0; WOW64)
    #   AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36" }
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"
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


def _hash_password(password: str) -> str:
    """Hash a Lenovo ID password for form submission.

    Confirmed from ``login.98d3f3bb25a8.js`` on passport.lenovo.com:

        CryptoJS.MD5(CryptoJS.MD5(a).toString().toUpperCase())
                     .toString().toUpperCase()

    i.e. double MD5 with the intermediate result upper-cased before the
    second hash, and the final result upper-cased as well.
    """
    inner = hashlib.md5(password.encode("utf-8")).hexdigest().upper()
    return hashlib.md5(inner.encode("utf-8")).hexdigest().upper()


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
            "Accept-Language": "es-419,es;q=0.9",
            "Accept":          (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,*/*;q=0.8"
            ),
        })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_login_url(self) -> str:
        """Fetch the real Lenovo ID OAuth login URL from the LMSA API.

        Confirmed by decompiling ``Software Fix.exe`` (LenovoIdWindowViewModel):
            login_url comes from ``/Interface/dictionary/getApiInfo.jhtml``
            with ``key="TIP_URL"``.
        Falls back to a hardcoded URL if the API call fails.
        """
        _default = (
            f"{PASSPORT_BASE}{_PRELOGIN_PATH}"
            f"?lenovoid.action=uilogin&lenovoid.realm={_LMSA_REALM}"
            f"&lenovoid.cb={_LMSA_CB_URL}"
        )
        try:
            from web_crawler.auth.lmsa import _BASE_HEADERS
            guid = str(_uuid.uuid4()).lower()
            hdrs = dict(_BASE_HEADERS)
            hdrs["guid"] = guid
            body = {
                "client":      {"version": CLIENT_VERSION},
                "language":    "en-US",
                "windowsInfo": "Microsoft Windows 11 Pro, x64-based PC",
                "dparams":     {"key": "TIP_URL"},
            }
            r = requests.post(
                f"{self._lmsa_base}/dictionary/getApiInfo.jhtml",
                json=body, headers=hdrs, timeout=10,
                verify=self._verify_ssl,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("code") == "0000":
                    content = _json.loads(data["content"])
                    url = content.get("login_url", "")
                    if url:
                        _log(f"[LenovoID] Login URL from server: {url[:80]}")
                        return url
        except Exception as exc:
            _log(f"[LenovoID] getApiInfo failed ({exc}), using hardcoded login URL")
        _log(f"[LenovoID] Using hardcoded login URL: {_default[:80]}")
        return _default

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

        Fetches the real login URL from the LMSA API first (getApiInfo.jhtml),
        then tries backends in order of Akamai bypass effectiveness:
        1. **DrissionPage** (Microsoft Edge headed via Xvfb — full Akamai JS
           sensor execution, best bypass rate; HAR confirmed Edge is what the
           real LMSA app uses).
        2. **curl_cffi** (Edge TLS impersonation — gets AKA_A2=A organically;
           no browser needed but cannot validate _abck without JS).
        3. **Hero** (ulixee/Hero Node.js — Human Emulator + proprietary CDP
           tunnel; no WebDriver fingerprint).
        4. **zendriver** (Python CDP-based, good Akamai bypass).
        5. **Playwright** (traditional, with stealth patches).
        6. **Plain HTTP** requests (no Akamai bypass).
        """
        login_url = self._get_login_url()

        if _DRISSIONPAGE_AVAILABLE:
            wust = self._obtain_wust_drissionpage(email, password, login_url)
            if wust:
                return wust
            _log("[LenovoID] DrissionPage login failed – trying curl_cffi fallback")

        if _CURL_CFFI_AVAILABLE:
            wust = self._obtain_wust_curl_cffi(email, password, login_url)
            if wust:
                return wust
            _log("[LenovoID] curl_cffi login failed – trying Hero fallback")

        if _HERO_AVAILABLE:
            wust = self._obtain_wust_hero(email, password, login_url)
            if wust:
                return wust
            _log("[LenovoID] Hero login failed – trying zendriver fallback")

        if _ZENDRIVER_AVAILABLE:
            wust = self._obtain_wust_zendriver(email, password, login_url)
            if wust:
                return wust
            _log("[LenovoID] Zendriver login failed – trying Playwright fallback")

        if _PLAYWRIGHT_AVAILABLE:
            wust = self._obtain_wust_browser(email, password, login_url)
            if wust:
                return wust
            _log("[LenovoID] Browser login failed – trying plain HTTP fallback")

        return self._obtain_wust_requests(email, password, login_url)

    # ------------------------------------------------------------------
    # DrissionPage + Microsoft Edge backend (primary — full Akamai bypass)
    # ------------------------------------------------------------------

    @staticmethod
    def _start_xvfb() -> "Optional[subprocess.Popen[bytes]]":
        """Start a virtual framebuffer (Xvfb) on a free display if needed.

        Returns the ``Popen`` object so the caller can terminate it on cleanup,
        or ``None`` when a display is already set or Xvfb is not available.
        """
        if os.environ.get("DISPLAY"):
            return None  # real/virtual display already available
        if not shutil.which("Xvfb"):
            return None

        # Find a free display number (99 is conventional for CI).
        import socket as _socket
        for disp in range(99, 110):
            try:
                s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
                s.connect(f"/tmp/.X11-unix/X{disp}")
                s.close()
                continue  # display already in use
            except (FileNotFoundError, ConnectionRefusedError):
                pass  # display free
            try:
                proc = subprocess.Popen(
                    ["Xvfb", f":{disp}", "-screen", "0", "1280x800x24", "-ac",
                     "+extension", "GLX"],  # GLX required for Mesa WebGL / SwiftShader
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                import time as _t; _t.sleep(1)
                if proc.poll() is None:
                    os.environ["DISPLAY"] = f":{disp}"
                    _log(f"[LenovoID] DrissionPage: Xvfb started on display :{disp}")
                    return proc
            except Exception:
                pass
        return None

    def _obtain_wust_drissionpage(
        self, email: str, password: str, login_url: str,
    ) -> Optional[str]:
        """Use DrissionPage + Microsoft Edge (headed via Xvfb) to login.

        This backend uses a real Microsoft Edge browser (the same browser the
        LMSA native app wraps via WebView2) running headed on a virtual
        framebuffer.  Headed mode prevents Akamai's bmak sensor from detecting
        a headless/virtual environment, allowing ``_abck`` to be validated and
        POST /userLogin to succeed.

        HAR analysis (HTTPToolkit_2026-03-03_18-12.har) confirmed:

        * The real LMSA app used Edge 146 (``Edg/146.0.0.0``).
        * /userLogin 200 response body contains::

              var gateway = 'https://lsa.lenovo.com/.../lenovoIdSuccess.html
                             ?lenovoid.wust=TOKEN';
              window.location.href = gateway;

        * JWT/GUID are returned by
          ``POST https://lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml``
          in the ``Authorization`` and ``Guid`` response headers.

        Browser SPA flow:

        1. GET preLogin (eager load — don't wait for Akamai sensor long-polls).
        2. Fill ``#emailOrPhoneInput`` → click ``button.next-static`` (Next).
        3. Fill ``#emailOrPhonePswInput`` (password).
        4. Click ``button.loadingBtnHide`` via JavaScript (submit).
        5. Capture the ``/userLogin`` response via network listener.
        6. Extract WUST from ``var gateway`` or ``lenovoid.wust=`` in response.
        """
        _log("[LenovoID] Trying DrissionPage (Edge headed via Xvfb) login…")

        # Locate Microsoft Edge binary.
        _EDGE_PATHS = [
            "/usr/bin/microsoft-edge-stable",
            "/usr/bin/microsoft-edge",
            "/usr/bin/msedge",
            shutil.which("microsoft-edge-stable") or "",
            shutil.which("microsoft-edge") or "",
        ]
        edge_bin: str = ""
        for _p in _EDGE_PATHS:
            if _p and os.path.isfile(_p):
                edge_bin = _p
                break
        if not edge_bin:
            _log("[LenovoID] DrissionPage: Microsoft Edge binary not found — skipping")
            return None

        xvfb_proc = self._start_xvfb()
        page = None
        try:
            opts = _ChromiumOptions()
            opts.auto_port()
            opts.headless(False)    # headed — prevents Akamai headless detection
            opts.set_argument("--no-sandbox")
            opts.set_argument("--disable-setuid-sandbox")
            opts.set_argument("--disable-dev-shm-usage")
            opts.set_argument("--window-size=1280,800")
            # SwiftShader enables WebGL in virtual display (Xvfb / Mesa).
            # Confirmed by live test: with these flags + mouse movements,
            # Akamai's bmak sensor validates _abck to ~0~ even on Xvfb.
            opts.set_argument("--use-gl=swiftshader")
            opts.set_argument("--enable-webgl")
            opts.set_argument("--ignore-gpu-blocklist")
            opts.set_browser_path(edge_bin)

            page = _ChromiumPage(addr_or_opts=opts)
            # eager: DOM content loaded — don't wait for Akamai sensor long-polls
            # which never resolve in a virtual environment and would hang forever.
            page.set.load_mode.eager()

            # Listen for the lenovoIdSuccess callback URL where the server
            # redirects after successful login.  The WUST appears in the
            # query string: ?lenovoid.wust=TOKEN
            # Also listen for lenovoIdLogin (WUST in response body fallback).
            page.listen.start("lenovoIdSuccess")

            _log("[LenovoID] DrissionPage: GET preLogin…")
            page.get(login_url)

            import time as _time
            import json as _json_mod

            # ── Step A: poll for _abck ~0~ while doing mouse movements ─────
            # Akamai's bmak.js sensor tracks mouse events and browser
            # fingerprint.  With SwiftShader WebGL + genuine mouse movements
            # _abck validates to ~0~ in a fresh Edge+Xvfb session.
            # We poll every 5 s and move the mouse each tick to keep the
            # sensor active.  Maximum wait: 90 s.
            _log("[LenovoID] DrissionPage: waiting up to 90 s for Akamai _abck validation…")
            _pts = [
                (100, 100), (300, 200), (500, 150), (700, 250), (900, 300),
                (400, 350), (600, 200), (800, 300), (200, 400), (500, 300),
                (700, 150), (350, 400), (550, 100), (750, 350), (250, 300),
                (450, 200), (650, 300), (850, 200), (150, 350), (550, 250),
            ]
            _abck_ok = False
            for _tick in range(18):  # 18 × 5 s = 90 s max
                try:
                    page.actions.move_to(_pts[_tick % len(_pts)], duration=0.1)
                except Exception:
                    pass
                _time.sleep(5)
                _cks = {c["name"]: c.get("value", "") for c in page.cookies()}
                _abck_ok = "~0~" in _cks.get("_abck", "")
                if _tick % 3 == 0 or _abck_ok:
                    _log(
                        f"[LenovoID] DrissionPage: t={(_tick+1)*5}s "
                        f"_abck={'✓' if _abck_ok else '✗'}  "
                        f"AKA_A2={_cks.get('AKA_A2', '?')}"
                    )
                if _abck_ok:
                    _log(f"[LenovoID] DrissionPage: ✓ _abck validated at {(_tick+1)*5}s")
                    break
            if not _abck_ok:
                _log("[LenovoID] DrissionPage: ⚠ _abck not validated — proceeding anyway")

            # ── Step B: email ──────────────────────────────────────────────
            email_el = page.ele("#emailOrPhoneInput", timeout=15)
            if not getattr(email_el, "tag", None):
                _log("[LenovoID] DrissionPage: email input not found")
                return None
            email_el.click(by_js=True)
            _time.sleep(0.3)
            email_el.input(email, clear=True)
            _time.sleep(1)
            _log(f"[LenovoID] DrissionPage: email filled: {email_el.value}")

            # ── Step C: click Next ─────────────────────────────────────────
            # The SPA renders all login steps simultaneously; next-static is
            # the email-step Next button.  Use by_js because in Xvfb the
            # button may have no bounding rect (NoRectError on regular click).
            next_btn = page.ele(
                "css:button.next-static:not(.nextLoadingBtn)", timeout=5,
            )
            if not getattr(next_btn, "tag", None):
                _log("[LenovoID] DrissionPage: Next button not found")
                return None
            next_btn.click(by_js=True)
            _log("[LenovoID] DrissionPage: Next clicked — waiting 12 s for password step…")
            _time.sleep(12)

            # ── Step D: password ───────────────────────────────────────────
            pwd_el = page.ele("#emailOrPhonePswInput", timeout=10)
            if not getattr(pwd_el, "tag", None):
                _log("[LenovoID] DrissionPage: password field not found")
                return None
            pwd_el.click(by_js=True)
            _time.sleep(0.3)
            pwd_el.input(password, clear=True)

            # Give Akamai sensor time to update _abck after user interaction.
            # Continue moving the mouse while waiting.
            for _tick2 in range(6):  # 30 s extra
                try:
                    page.actions.move_to(_pts[(_tick2 + 10) % len(_pts)], duration=0.1)
                except Exception:
                    pass
                _time.sleep(5)
                _cks2 = {c["name"]: c.get("value", "") for c in page.cookies()}
                _abck_ok2 = "~0~" in _cks2.get("_abck", "")
                _log(
                    f"[LenovoID] DrissionPage: pwd-poll t={(_tick2+1)*5}s "
                    f"_abck={'✓' if _abck_ok2 else '✗'}"
                )
                if _abck_ok2:
                    _abck_ok = True
                    _log("[LenovoID] DrissionPage: ✓ _abck validated after password entry")
                    break

            # ── Step E: get reCAPTCHA GT token ─────────────────────────────
            # reCAPTCHA Enterprise v3 (invisible).  Execute asynchronously and
            # store in window._gt.  Typically resolves in < 2 s.
            # Site key: 6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub (passport.lenovo.com)
            _RCKEY = "6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub"
            _log("[LenovoID] DrissionPage: requesting reCAPTCHA GT token…")
            page.run_js(
                f"window._gt=null;window._gtErr=null;"
                f"if(window.grecaptcha&&window.grecaptcha.enterprise){{"
                f"window.grecaptcha.enterprise.execute('{_RCKEY}',{{action:'login'}})"
                f".then(function(t){{window._gt=t;}})"
                f".catch(function(e){{window._gt='';window._gtErr=String(e);}});"
                f"}}else{{window._gt='';window._gtErr='no grecaptcha.enterprise';}}"
            )
            _gt = ""
            for _gi in range(15):
                _time.sleep(1)
                _res = page.run_js("return {gt:window._gt,err:window._gtErr}")
                if _res.get("gt") is not None:
                    _gt = _res["gt"]
                    _log(f"[LenovoID] DrissionPage: ✓ GT token in {_gi+1}s len={len(_gt)}")
                    break
                if _res.get("err"):
                    _log(f"[LenovoID] DrissionPage: GT error: {_res['err']}")
                    break
            if not _gt:
                _log("[LenovoID] DrissionPage: ⚠ GT empty — submitting without token")

            # ── Step F: inject all form fields + submit ─────────────────────
            # We use json.dumps inlining (not *args) to safely pass values that
            # may contain special chars (e.g. @ $ # in email/password/gt).
            # Field mapping (HAR-verified):
            #   username      = email
            #   password      = hex_md5(hex_md5(raw_password))  (double MD5)
            #   gt            = reCAPTCHA Enterprise v3 token
            #   lenovoid.lang = "en_US"   (HAR shows en_US, form defaults null)
            #   bid           = already set by Fingerprint2 JS on page load
            _log(
                f"[LenovoID] DrissionPage: submitting form "
                f"(abck={'✓' if _abck_ok else '✗'} gt_len={len(_gt)})…"
            )
            _email_js = _json_mod.dumps(email)
            _pwd_js   = _json_mod.dumps(password)
            _gt_js    = _json_mod.dumps(_gt)
            page.run_js(f"""
(function(){{
    var em={_email_js}, rp={_pwd_js}, gt={_gt_js};
    // double-MD5 (hex_md5 loaded from passport.lenovo.com/login.js)
    var h1=(typeof hex_md5==='function')?hex_md5(rp):rp;
    var h2=(typeof hex_md5==='function')?hex_md5(h1):h1;
    // Find active (visible) userLogin form
    var forms=document.querySelectorAll('form[action*="userLogin"]');
    var form=null;
    for(var i=0;i<forms.length;i++){{
        if(forms[i].offsetParent!==null){{form=forms[i];break;}}
    }}
    if(!form)form=forms[0];
    if(!form){{window._ferr='no form';return;}}
    function setF(n,v){{
        var e=form.querySelector('input[name="'+n+'"]');
        if(!e){{e=document.createElement('input');e.type='hidden';e.name=n;form.appendChild(e);}}
        e.value=v;
    }}
    setF('username',em);
    setF('password',h2);
    setF('gt',gt);
    setF('lenovoid.lang','en_US');
    window._dbg={{user:em,passLen:h2.length,gt:gt.substring(0,20),hex:typeof hex_md5==='function'}};
    window._submitted=true;
    form.submit();
}})();
""")

            # ── Step G: extract WUST ───────────────────────────────────────
            # After successful /userLogin the browser is redirected to
            # lsa.lenovo.com/Tips/lenovoIdSuccess.html?lenovoid.wust=TOKEN
            # Our listener captures this GET and we read WUST from the URL.
            _log("[LenovoID] DrissionPage: waiting 40 s for lenovoIdSuccess redirect…")
            wust: Optional[str] = None
            try:
                packet = page.listen.wait(timeout=40)
            except Exception:
                packet = None

            if packet:
                _log(f"[LenovoID] DrissionPage: captured {packet.url[:100]}")
                wust = _find_wust(packet.url)
                if wust:
                    _log("[LenovoID] ✓ WUST from lenovoIdSuccess URL")
                    return wust

            # Fallback: final page URL after navigation.
            _time.sleep(5)
            try:
                final_url = page.url
                wust = _find_wust(final_url)
                if wust:
                    _log("[LenovoID] ✓ WUST from DrissionPage final URL")
                    return wust
            except Exception:
                final_url = ""

            # LPSWUST cookie (set by /userLogin 200 response).
            try:
                _cks3 = {c["name"]: c.get("value", "") for c in page.cookies(all_domains=True)}
                if _cks3.get("LPSWUST"):
                    wust = _cks3["LPSWUST"]
                    _log("[LenovoID] ✓ WUST from LPSWUST cookie")
                    return wust
            except Exception:
                pass

            # Page HTML (var gateway = '...?lenovoid.wust=TOKEN').
            try:
                body = page.html
                gw_m = re.search(r"var\s+gateway\s*=\s*'([^']+)'", body)
                if gw_m:
                    gw_url = gw_m.group(1).replace("\\/", "/")
                    wust = _find_wust(gw_url)
                    if wust:
                        _log("[LenovoID] ✓ WUST from DrissionPage page body (gateway)")
                        return wust
                wust = _find_wust(body)
                if wust:
                    _log("[LenovoID] ✓ WUST from DrissionPage page body")
                    return wust
            except Exception:
                body = ""

            try:
                _dbg = page.run_js("return window._dbg||{}")
                _log(f"[LenovoID] DrissionPage: JS debug={_dbg}")
            except Exception:
                pass

            _log(
                f"[LenovoID] DrissionPage: no WUST found — "
                f"final_url={final_url[:80]} "
                f"_abck={'✓' if _abck_ok else '✗'}"
            )
            return None

        except Exception as exc:
            _log(f"[LenovoID] DrissionPage: exception: {exc}")
            return None
        finally:
            if page is not None:
                try:
                    page.listen.stop()
                    page.close()
                except Exception:
                    pass
            if xvfb_proc is not None:
                try:
                    xvfb_proc.terminate()
                    os.environ.pop("DISPLAY", None)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # curl_cffi Edge-impersonation backend (fallback — lightest-weight)
    # ------------------------------------------------------------------

    def _obtain_wust_curl_cffi(
        self, email: str, password: str, login_url: str,
    ) -> Optional[str]:
        """Use curl_cffi (Edge TLS impersonation) to complete Lenovo ID OAuth.

        curl_cffi replaces Python/urllib3's TLS fingerprint with an exact copy
        of Microsoft Edge's JA3/JA4 fingerprint.  HAR analysis confirmed that:

        * The real LMSA app uses Edge (``Edg/146``).
        * ``edge101`` impersonation causes Akamai to set ``AKA_A2=A``
          *organically* during GET preLogin (chrome120 does not).
        * Without a validated ``_abck`` cookie (requires Akamai JS sensor),
          POST /userLogin returns HTTP/2 INTERNAL_ERROR (curl 92).  When this
          happens the DrissionPage backend (headed Edge via Xvfb) is used as
          fallback.

        HAR analysis (HTTPToolkit_2026-03-03_18-12.har) confirmed the exact
        request structure:

        1. GET preLogin  → JSESSIONID, AKA_A2=A, ak_bmsc cookies.
        2. POST ajaxUserRoam  → {"resultCode": 0}  (roaming account).
        3. POST /userLogin with double-MD5 password hash.
           Response: 200 HTML with::

               var gateway = 'https://lsa.lenovo.com/.../lenovoIdSuccess.html
                              ?lenovoid.wust=TOKEN';
               window.location.href = gateway;

        JWT/GUID are obtained via a separate POST to:
            ``https://lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml``
        which is handled by :meth:`_exchange_wust_for_jwt` after this method
        returns the WUST.
        """
        _log("[LenovoID] Trying curl_cffi (Edge TLS impersonation) login…")

        # Use Edge 146 UA and sec-ch-ua matching the real LMSA HAR session.
        _EDGE_UA = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
        )
        _LANG = "es-419,es;q=0.9,es-ES;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5"

        try:
            # edge101 impersonation: Akamai sets AKA_A2=A organically during
            # GET preLogin (confirmed in live tests — chrome120 does not get it).
            sess = _cffi_requests.Session(impersonate="edge101")
            sess.headers.update({
                "User-Agent": _EDGE_UA,
                "Accept-Language": _LANG,
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "sec-ch-ua": (
                    '"Not-A.Brand";v="24", "Microsoft Edge";v="146", '
                    '"Chromium";v="146"'
                ),
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            })

            # ── Step 1: GET preLogin ──────────────────────────────────────
            # With edge101 impersonation Akamai sets AKA_A2=A, ak_bmsc, and
            # _abck cookies organically in the preLogin response (confirmed in
            # live tests — no manual injection needed).
            _log("[LenovoID] curl_cffi: GET preLogin…")
            r_pre = sess.get(
                login_url,
                headers={
                    "Accept": (
                        "text/html,application/xhtml+xml,application/xml;"
                        "q=0.9,image/avif,image/webp,*/*;q=0.8"
                    ),
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                },
                timeout=30,
                allow_redirects=True,
            )
            _log(f"[LenovoID] curl_cffi: preLogin HTTP {r_pre.status_code} "
                 f"AKA_A2={dict(sess.cookies).get('AKA_A2','not set')}")
            if r_pre.status_code not in (200, 302):
                _log(
                    f"[LenovoID] curl_cffi: unexpected preLogin status "
                    f"{r_pre.status_code}"
                )
                return None

            # ── Step 2: POST ajaxUserRoam (roaming account pre-registration) ──
            # HAR confirmed: for eduardo@uaemex.top (roaming account),
            # ajaxUserExistedServlet → 400 (normal), then ajaxUserRoam must
            # return {"resultCode": 0} before /userLogin will authenticate.
            from urllib.parse import quote as _quote, urlparse as _urlparse
            import re as _re

            parsed = _urlparse(login_url)
            cb_match = _re.search(r'lenovoid\.cb=([^&]+)', login_url)
            cb_url = cb_match.group(1) if cb_match else _LMSA_CB_URL
            lang_match = _re.search(r'lenovoid\.lang=([^&]+)', login_url)
            lang = lang_match.group(1) if lang_match else "en_US"

            _AJAX_HDRS = {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Content-Length": "0",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "https://passport.lenovo.com",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": login_url,
            }
            roam_url = (
                f"{PASSPORT_BASE}/glbwebauthnv6/ajaxUserRoam"
                f"?username={_quote(email)}&areacode="
            )
            r_roam = sess.post(
                roam_url, data="", headers=_AJAX_HDRS, timeout=20,
            )
            _log(
                f"[LenovoID] curl_cffi: ajaxUserRoam HTTP {r_roam.status_code} "
                f"body={r_roam.text[:80]}"
            )

            # ── Step 3: POST /userLogin ────────────────────────────────────
            # Exact form body from HAR; lenovoid.lang MUST be en_US.
            hashed = _hash_password(password)
            post_data = {
                "lenovoid.action":     "uilogin",
                "lenovoid.realm":      _LMSA_REALM,
                "lenovoid.ctx":        "null",
                "lenovoid.lang":       "en_US",
                "lenovoid.uinfo":      "null",
                "lenovoid.cb":         cb_url,
                "lenovoid.vb":         "null",
                "lenovoid.display":    "null",
                "lenovoid.idp":        "null",
                "lenovoid.source":     _LMSA_REALM,
                "lenovoid.sdk":        "null",
                "lenovoid.prompt":     "null",
                "bid":                 "",
                "gt":                  "",
                "password":            hashed,
                "lenovoid.hidesocial": "null",
                "crossRealmDomains":   "null",
                "path":                "/glbwebauthnv6",
                "areacode":            "",
                "username":            email,
                "loginfinish":         "1",
                "autoLoginState":      "1",
            }
            _log("[LenovoID] curl_cffi: POST /userLogin…")
            r_login = sess.post(
                f"{PASSPORT_BASE}/glbwebauthnv6/userLogin",
                data=post_data,
                headers={
                    "Accept": (
                        "text/html,application/xhtml+xml,application/xml;"
                        "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
                    ),
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Origin": "https://passport.lenovo.com",
                    "Referer": login_url,
                },
                timeout=60,
                allow_redirects=True,
            )
            _log(
                f"[LenovoID] curl_cffi: /userLogin HTTP {r_login.status_code} "
                f"final_url={r_login.url[:80]}"
            )

            # ── Step 4: Extract WUST ─────────────────────────────────────
            # (a) WUST in final redirect URL (ideal path).
            wust = _find_wust(r_login.url)
            if wust:
                _log("[LenovoID] ✓ WUST found in redirect URL")
                return wust

            # (b) WUST in ``var gateway = '...?lenovoid.wust=TOKEN'`` JS.
            # HAR shows POST /userLogin returns 200 with HTML body containing:
            #   var gateway = 'https://lsa.lenovo.com/.../lenovoIdSuccess.html
            #                  ?lenovoid.wust=TOKEN';
            #   window.location.href = gateway;
            gw_m = _re.search(r"var\s+gateway\s*=\s*'([^']+)'", r_login.text)
            if gw_m:
                gw_url = gw_m.group(1).replace("\\/", "/")
                _log(f"[LenovoID] curl_cffi: gateway URL={gw_url[:120]}")
                wust = _find_wust(gw_url)
                if wust:
                    _log("[LenovoID] ✓ WUST extracted from gateway JS variable")
                    return wust

            # (c) WUST anywhere in response body (fallback regex scan).
            wust = _find_wust(r_login.text)
            if wust:
                _log("[LenovoID] ✓ WUST found in response body")
                return wust

            # Diagnose failure.
            if r_login.status_code == 504:
                _log(
                    "[LenovoID] curl_cffi: 504 from /userLogin — "
                    "Akamai TLS fingerprint not accepted (try Hero backend)"
                )
            elif "incorrect" in r_login.text.lower() or "invalid" in r_login.text.lower():
                _log("[LenovoID] curl_cffi: invalid credentials")
            else:
                _log(
                    f"[LenovoID] curl_cffi: no WUST in response "
                    f"(HTTP {r_login.status_code})"
                )
            return None

        except Exception as exc:
            # curl_cffi raises CurlError (a subclass of RequestsError) for
            # curl errors.  HTTP/2 INTERNAL_ERROR (curl code 92) means Akamai
            # RST the stream — the session needs more trust signals (AKA_A2).
            msg = str(exc)
            if "92" in msg or "INTERNAL_ERROR" in msg:
                _log(
                    "[LenovoID] curl_cffi: Akamai HTTP/2 RST_STREAM on "
                    "/userLogin — session needs AKA_A2 cookie trust signal"
                )
            else:
                _log(f"[LenovoID] curl_cffi: exception: {exc}")
            return None

    def _obtain_wust_hero(
        self, email: str, password: str, login_url: str,
    ) -> Optional[str]:
        """Use ulixee/Hero (Node.js) to complete the Lenovo ID OAuth.

        Hero (https://github.com/ulixee/hero) uses a built-in Human Emulator
        that generates realistic mouse movements, scroll events, and typing
        delays.  It communicates with the browser via a proprietary CDP-over-
        WebSocket tunnel rather than the standard WebDriver protocol, so it
        does not expose the ``webdriver`` navigator property that Akamai Bot
        Manager checks.  This makes Hero the most effective backend for
        bypassing the Akamai ``_abck`` cookie challenge on passport.lenovo.com.

        Requires Node.js ≥ 18 and the ``@ulixee/hero-playground`` npm package
        to be installed in the ``web_crawler/auth/`` directory::

            cd web_crawler/auth && npm install

        Availability is checked at module load time via :data:`_HERO_AVAILABLE`.
        The login script is ``web_crawler/auth/hero_login.js``.
        """
        _log("[LenovoID] Launching Hero (ulixee/Hero Node.js) for Akamai-protected login…")
        try:
            result = subprocess.run(
                ["node", _HERO_SCRIPT, login_url, email, password],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=os.path.dirname(_HERO_SCRIPT),
            )
        except subprocess.TimeoutExpired:
            _log("[LenovoID] Hero: timed out after 300 s")
            return None
        except (OSError, FileNotFoundError) as exc:
            _log(f"[LenovoID] Hero: could not start Node.js: {exc}")
            return None
        except Exception as exc:
            _log(f"[LenovoID] Hero: unexpected error: {exc}")
            return None

        # Forward the last few lines of stderr for diagnostics.
        if result.stderr:
            for line in result.stderr.strip().splitlines()[-15:]:
                _log(f"[LenovoID] Hero: {line}")

        if not result.stdout:
            _log("[LenovoID] Hero: no output from script")
            return None

        # Parse the last JSON line written to stdout.
        try:
            last_line = result.stdout.strip().splitlines()[-1]
            data = _json.loads(last_line)
        except (ValueError, IndexError):
            _log(f"[LenovoID] Hero: unexpected output: {result.stdout[:200]}")
            return None

        wust = data.get("wust")
        if wust:
            _log("[LenovoID] ✓ WUST obtained via Hero")
            return wust

        err = data.get("error", "unknown error")
        _log(f"[LenovoID] Hero: {err}")
        return None

    # ------------------------------------------------------------------
    # Zendriver (CDP-based) browser backend
    # ------------------------------------------------------------------

    def _obtain_wust_zendriver(
        self, email: str, password: str, login_url: str,
    ) -> Optional[str]:
        """Use zendriver (CDP-based) to complete the Lenovo ID OAuth.

        Zendriver communicates with the browser directly via Chrome DevTools
        Protocol without any WebDriver binary, which avoids the automation
        fingerprints that Akamai Bot Manager detects.  In benchmark tests
        zendriver successfully bypasses Akamai where Playwright and Selenium
        fail (see: baseline comparison by dimakynal on Medium).

        The method loads the Akamai-protected login page, waits for the
        ``bmak`` sensor, reCAPTCHA Enterprise token (GT), and Fingerprint2
        browser ID (bid) to initialise, then performs the two-step SPA login
        flow (email → password → submit → WUST redirect).
        """
        _log("[LenovoID] Launching zendriver (CDP) for Akamai-protected login…")

        async def _run() -> Optional[str]:
            captured: list[str] = []
            hashed = _hash_password(password)

            browser = await _zendriver.start(
                headless=True,
                sandbox=False,
                browser_connection_timeout=2.0,
                browser_connection_max_tries=30,
            )
            try:
                page = await browser.get(login_url)

                # Wait for Akamai sensor + reCAPTCHA + page JS to initialise.
                await asyncio.sleep(15)

                # Wait for global-loader overlay to disappear.
                loader_vis = await page.evaluate(
                    "(() => { const l = document.getElementById('global-loader');"
                    " return l ? l.offsetParent !== null : false; })()"
                )
                if loader_vis:
                    for _i in range(30):
                        await asyncio.sleep(1)
                        hidden = await page.evaluate(
                            "!document.getElementById('global-loader')"
                            " || document.getElementById('global-loader')"
                            ".offsetParent === null"
                        )
                        if hidden:
                            break
                    else:
                        await page.evaluate(
                            "document.getElementById('global-loader')?.remove()"
                        )

                await asyncio.sleep(2)

                # --- Fill email ---
                el = await page.select("#emailOrPhoneInput")
                if el:
                    await el.click()
                    await asyncio.sleep(0.3)
                    await el.send_keys(email)
                else:
                    _log("[LenovoID] zendriver: email field not found")
                    return None

                await asyncio.sleep(1)

                # --- Click Next ---
                btn = await page.select("div.loginClass1 button")
                if btn:
                    await btn.click()
                else:
                    await page.evaluate(
                        "document.querySelector('div.loginClass1 button')?.click()"
                    )

                # --- Wait for password field ---
                await asyncio.sleep(5)
                pw_appeared = False
                for _i in range(15):
                    vis = await page.evaluate(
                        "(() => { const e = document.querySelector("
                        "'#emailOrPhonePswInput');"
                        " return e && e.offsetParent !== null; })()"
                    )
                    if vis:
                        pw_appeared = True
                        break
                    await asyncio.sleep(1)

                if pw_appeared:
                    # --- SPA flow: fill password ---
                    _log("[LenovoID] zendriver: password step appeared (SPA OK)")
                    pwd_el = await page.select("#emailOrPhonePswInput")
                    if pwd_el:
                        await pwd_el.click()
                        await asyncio.sleep(0.2)
                        for ch in password:
                            await pwd_el.send_keys(ch)
                            await asyncio.sleep(_rnd.uniform(0.05, 0.12))

                    await asyncio.sleep(5)

                    # Click submit
                    sub = await page.select("button.loadingBtnHide")
                    if sub:
                        await sub.click()
                    else:
                        await page.evaluate(
                            "document.querySelector("
                            "'div.loginClass2 button')?.click()"
                        )

                    # Wait for WUST redirect
                    for _i in range(25):
                        url = page.url or ""
                        if "lenovoid.wust" in url or "lenovoIdSuccess" in url:
                            break
                        await asyncio.sleep(1)
                else:
                    # --- Direct form submission fallback ---
                    _log("[LenovoID] zendriver: SPA blocked, direct form submit")
                    gt = (await page.evaluate(
                        "(async () => {"
                        " if (typeof grecaptcha !== 'undefined'"
                        " && grecaptcha.enterprise) {"
                        "  try { return await grecaptcha.enterprise.execute("
                        "   '6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub',"
                        "   {action: 'LOGIN'});"
                        "  } catch(e) { return ''; }"
                        " } return '';"
                        "})()"
                    )) or ""
                    bid = (await page.evaluate(
                        "document.querySelector('.jsBid')?.value || ''"
                    )) or ""

                    # Zendriver's page.evaluate() maps directly to
                    # CDP Runtime.evaluate which does NOT support passing
                    # arguments.  Inline the values via json.dumps() which
                    # produces safe JS string literals (handles quotes,
                    # backslashes, newlines, etc.).
                    _email_js = _json.dumps(email)
                    _hashed_js = _json.dumps(hashed)
                    _gt_js = _json.dumps(gt)
                    await page.evaluate(
                        "(() => {"
                        " const f = document.querySelector('.loginClass2 form');"
                        " if (!f) return;"
                        " f.querySelectorAll('input[name=\"username\"]')"
                        f"     .forEach(e => e.value = {_email_js});"
                        " f.querySelectorAll('.emailAddressInput')"
                        f"     .forEach(e => e.value = {_email_js});"
                        " f.querySelectorAll('input[name=\"password\"]')"
                        f"     .forEach(e => e.value = {_hashed_js});"
                        " f.querySelectorAll('input[name=\"loginfinish\"]')"
                        "     .forEach(e => e.value = '1');"
                        " let g = f.querySelector('input[name=\"gt\"]');"
                        " if (!g) {"
                        "     g = document.createElement('input');"
                        "     g.type = 'hidden'; g.name = 'gt';"
                        "     f.appendChild(g);"
                        " }"
                        f" g.value = {_gt_js};"
                        " f.submit();"
                        "})()"
                    )
                    await asyncio.sleep(10)

                # --- Extract WUST ---
                wust = _find_wust(page.url or "")
                if not wust:
                    body = await page.evaluate(
                        "document.documentElement?.outerHTML || ''"
                    )
                    wust = _find_wust(body)

                if wust:
                    _log("[LenovoID] ✓ WUST obtained via zendriver")
                return wust
            except Exception as exc:
                _log(f"[LenovoID] zendriver error: {exc}")
                return None
            finally:
                try:
                    await browser.stop()
                except Exception:
                    pass

        try:
            return asyncio.run(_run())
        except Exception as exc:
            _log(f"[LenovoID] zendriver asyncio error: {exc}")
            return None

    def _obtain_wust_browser(
        self, email: str, password: str, login_url: str
    ) -> Optional[str]:
        """Use Playwright (headless Firefox) to complete the Lenovo ID OAuth.

        The Lenovo passport is protected by Akamai Bot Manager which sets an
        ``_abck`` cookie that can only be validated by executing JavaScript in
        a real browser context.  This method launches a headless Firefox instance,
        navigates to the real login URL (from getApiInfo.jhtml), fills in
        credentials, and intercepts the WUST from the redirect URL.

        When the normal SPA flow fails (Akamai blocks the AJAX email-validation
        call), a direct form-submission fallback is attempted: the loginClass2
        form is filled programmatically (username, double-MD5 password,
        reCAPTCHA token, browser fingerprint) and submitted directly, bypassing
        the SPA email-validation step entirely.
        """
        _log("[LenovoID] Launching headless browser for Akamai-protected login…")
        wust: Optional[str] = None
        captured: list[str] = []

        try:
            # Use playwright-stealth context manager when available — it
            # patches browser APIs (navigator.webdriver, plugins, WebGL,
            # etc.) to reduce Akamai Bot Manager detection rates.
            pw_cm = _sync_playwright()
            if _STEALTH_AVAILABLE:
                # Language matches the LMSA client form defaults
                # (lenovoid.lang=es_ES) and the browser context locale below.
                _stealth = _Stealth(
                    navigator_languages_override=("es-419", "es"),
                    navigator_platform_override="Win32",
                    webgl_vendor_override="Intel Inc.",
                    webgl_renderer_override="Intel Iris OpenGL Engine",
                )
                pw_cm = _stealth.use_sync(pw_cm)

            with pw_cm as p:
                # Try Firefox first — it has a different TLS fingerprint from
                # Playwright's Chromium and avoids the HTTP/2 protocol error that
                # Akamai triggers against automated Chromium instances.
                try:
                    browser = p.firefox.launch(headless=True)
                    _log("[LenovoID] Using Firefox browser engine")
                except Exception:
                    browser = p.chromium.launch(
                        headless=True,
                        args=[
                            "--no-sandbox",
                            "--disable-setuid-sandbox",
                            "--disable-dev-shm-usage",
                            "--disable-http2",
                            "--disable-blink-features=AutomationControlled",
                        ],
                    )
                    _log("[LenovoID] Using Chromium browser engine (Firefox unavailable)")
                ctx = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent=_BROWSER_UA,
                    locale="es-419",
                    ignore_https_errors=True,
                    extra_http_headers={
                        "Accept-Language": "es-419,es;q=0.9",
                        "Upgrade-Insecure-Requests": "1",
                    },
                )
                page = ctx.new_page()

                # Hide webdriver property (defence-in-depth; playwright-stealth
                # also patches this when available).
                if not _STEALTH_AVAILABLE:
                    page.add_init_script(
                        "Object.defineProperty(navigator, 'webdriver', "
                        "{get: () => undefined})"
                    )

                # Intercept every navigation and capture WUST from callback URL.
                # LoginCallback in Software Fix.exe checks for path /Tips/lenovoIdSuccess.html
                def _on_nav(frame: object) -> None:
                    url: str = frame.url  # type: ignore[attr-defined]
                    if "/Tips/lenovoIdSuccess.html" in url or "lenovoid.wust" in url:
                        captured.append(url)

                page.on("framenavigated", _on_nav)

                _log(f"[LenovoID] Browser → login: {login_url[:80]}")
                try:
                    page.goto(login_url, timeout=60_000,
                              wait_until="domcontentloaded")
                except Exception as exc:
                    _log(f"[LenovoID] Browser goto error (Akamai may be blocking): {exc}")
                    browser.close()
                    return None

                # Allow JS challenges to run (Akamai sensor_data generation +
                # reCAPTCHA Enterprise invisible token acquisition).
                # Simulate realistic user mouse movements to help the Akamai
                # sensor collect valid interaction data.
                page.wait_for_timeout(5000)
                for _i in range(15):
                    page.mouse.move(_rnd.randint(100, 900),
                                    _rnd.randint(100, 600))
                    page.wait_for_timeout(_rnd.randint(30, 120))
                page.wait_for_timeout(3000)

                # The Lenovo ID page (glbwebauthnv6) is a two-step SPA:
                # Step A: type email in #emailOrPhoneInput then click the
                #         "Siguiente" (Next) button in div.loginClass1.
                # Step B: wait for #emailOrPhonePswInput to become visible
                #         then fill password → click the submit button
                #         (button.loadingBtnHide) in div.loginClass2.
                # Confirmed from Chrome DevTools recording on glbwebauthnv6/preLogin.
                filled_email = False
                for sel in [
                    '#emailOrPhoneInput',
                    'input.noneTheme1',
                    'input[type="text"]:visible',
                    'input[type="email"]:visible',
                ]:
                    try:
                        loc = page.locator(sel).first
                        loc.wait_for(state="visible", timeout=5000)
                        loc.click(timeout=3000)
                        # Type slowly (60 ms/char) so the SPA's JS event
                        # handlers (input, keydown, keyup) fire as they would
                        # for a real user — required for the Next button to
                        # become active and submit the email to the server.
                        loc.type(email, delay=60)
                        filled_email = True
                        break
                    except Exception:
                        continue

                if not filled_email:
                    _log("[LenovoID] Browser: could not locate email field")

                # Click the "Siguiente" (Next) button to advance to the
                # password step.  The button lives inside div.loginClass1.
                # Confirmed from Chrome DevTools recording selectors.
                _clicked_next = False
                for sel in [
                    'div.loginClass1 button:has-text("Siguiente")',
                    'div.loginClass1 button:first-of-type',
                    'button:has-text("Siguiente")',
                    'button:has-text("Next")',
                ]:
                    try:
                        btn = page.locator(sel).first
                        btn.wait_for(state="visible", timeout=3000)
                        btn.click(timeout=3000)
                        _clicked_next = True
                        break
                    except Exception:
                        continue
                if not _clicked_next:
                    # Fallback: press Enter if no button found.
                    page.keyboard.press("Enter")

                page.wait_for_timeout(2000)

                # Wait for password field (SPA transition after email submit).
                _password_appeared = False
                try:
                    page.wait_for_selector(
                        '#emailOrPhonePswInput, input[type="password"]:visible',
                        timeout=10000,
                    )
                    _password_appeared = True
                except Exception:
                    _log("[LenovoID] Browser: password field never appeared "
                         "(Akamai may have blocked the request)")

                # ----- Direct form-submission fallback -----
                # When Akamai blocks the AJAX email-validation call
                # (ajaxUserExistedServlet), the SPA never transitions to
                # the password step.  In this case we bypass the SPA
                # entirely: programmatically fill the loginClass2 hidden
                # form (double-MD5 password + reCAPTCHA token + bid) and
                # submit it directly.
                if not _password_appeared:
                    _log("[LenovoID] Browser: attempting direct form submission "
                         "(bypassing SPA email validation)")
                    wust = self._direct_form_submit(
                        page, ctx, email, password, captured,
                    )
                    if wust:
                        browser.close()
                        return wust
                    # If direct submit also fails, continue with the normal
                    # flow in case the password field is present but hidden.

                # Fill password field.  Use type() instead of fill() so that
                # the JS input/keyup/keydown handlers fire for every keystroke
                # (the page's nextHandler reads the visible value, hashes it
                # with CryptoJS.MD5, then writes it to the hidden password field).
                _filled_password = False
                try:
                    for sel in ['#emailOrPhonePswInput',
                                "div.loginClass2 input[type='password']",
                                'input[type="password"]:visible']:
                        try:
                            loc = page.locator(sel).first
                            loc.wait_for(state="visible", timeout=4000)
                            loc.click(timeout=3000)
                            loc.type(password, delay=60)
                            _filled_password = True
                            break
                        except Exception:
                            continue
                except Exception:
                    _log("[LenovoID] Browser: could not fill password field")

                if not _filled_password and not _password_appeared:
                    # Neither the SPA flow nor the password field worked.
                    _log("[LenovoID] Browser: no password field accessible")
                    browser.close()
                    return wust  # may be None or set by _direct_form_submit

                # Wait for reCAPTCHA Enterprise token (GT variable) and
                # Akamai bot-ID (bid) to be populated by page JS.
                page.wait_for_timeout(3000)

                # Click the submit "Siguiente" button.  The submit button
                # in the password step has class loadingBtnHide and lives
                # inside div.loginClass2.
                # Confirmed from Chrome DevTools recording selectors.
                _clicked_submit = False
                for sel in [
                    'button.loadingBtnHide',
                    'div.loginClass2 button:has-text("Siguiente")',
                    'button:has-text("Siguiente")',
                    'button:has-text("Next")',
                ]:
                    try:
                        btn = page.locator(sel).first
                        btn.wait_for(state="visible", timeout=3000)
                        btn.click(timeout=3000)
                        _clicked_submit = True
                        break
                    except Exception:
                        continue
                if not _clicked_submit:
                    # Fallback: press Enter if no button found.
                    page.keyboard.press("Enter")

                # Wait for the JS to hash password, append GT, poll for bid,
                # and submit the form (bid poll interval = 500ms).
                page.wait_for_timeout(3000)

                # Wait for redirect / WUST extraction.  The server validates
                # credentials and redirects to lenovoIdSuccess.html?lenovoid.wust=...
                try:
                    page.wait_for_url(
                        "**/Tips/lenovoIdSuccess.html*",
                        timeout=15000,
                    )
                except Exception:
                    # Redirect might not match the pattern; fall through
                    # to check captured URLs and page URL below.
                    page.wait_for_timeout(5000)

                # Check captured navigation events.
                for url in captured:
                    w = _find_wust(url)
                    if w:
                        wust = w
                        _log("[LenovoID] ✓ WUST token captured from browser redirect")
                        break

                if not wust:
                    wust = _find_wust(page.url)
                    if wust:
                        _log("[LenovoID] ✓ WUST token found in final browser URL")

                if not wust:
                    body = ""
                    try:
                        body = page.content()
                    except Exception:
                        pass
                    body_lower = body.lower()
                    # Specific phrases from Lenovo ID error messages (not generic "invalid")
                    if any(p in body_lower for p in (
                        "incorrect password", "wrong password",
                        "account or password is incorrect",
                        "contraseña incorrecta",
                    )):
                        _log("[LenovoID] Browser: invalid credentials")
                    elif "captcha" in body_lower or "robot" in body_lower:
                        _log("[LenovoID] Browser: CAPTCHA detected — "
                             "attempting AI solver")
                        wust = self._solve_captcha_with_ai(page, captured)
                    elif "blocked" in body_lower and "akamai" in body_lower:
                        _log("[LenovoID] Browser: blocked by Akamai Bot Manager")
                    elif "network access error" in body_lower:
                        _log("[LenovoID] Browser: Akamai blocked AJAX calls "
                             "(Network access error)")
                    else:
                        _log(f"[LenovoID] Browser: no WUST — final URL: {page.url[:80]}")

                browser.close()
        except Exception as exc:
            _log(f"[LenovoID] Browser login exception: {exc}")

        return wust

    def _direct_form_submit(
        self,
        page: object,
        ctx: object,
        email: str,
        password: str,
        captured: list[str],
    ) -> Optional[str]:
        """Bypass SPA email-validation and submit the loginClass2 form directly.

        When Akamai blocks the ``ajaxUserExistedServlet`` AJAX call (showing
        "Network access error"), the normal two-step SPA flow cannot proceed.
        This method fills all hidden form fields programmatically (username,
        double-MD5 hashed password, reCAPTCHA Enterprise token, Fingerprint2
        browser ID) and submits the form directly.

        Returns the WUST token on success, ``None`` on failure.
        """
        hashed = _hash_password(password)

        # Generate reCAPTCHA Enterprise token from the browser context.
        gt = ""
        try:
            gt = page.evaluate(  # type: ignore[union-attr]
                """() => {
                return new Promise((resolve) => {
                    if (typeof grecaptcha !== 'undefined' && grecaptcha.enterprise) {
                        grecaptcha.enterprise.ready(() => {
                            grecaptcha.enterprise.execute(
                                '6Ld_eBkmAAAAAKGzqykvtH0laOzfRdELmh-YBxub',
                                {action: 'LOGIN'}
                            ).then(resolve).catch(() => resolve(''));
                        });
                    } else { resolve(''); }
                });
            }"""
            )
        except Exception:
            pass
        _log(f"[LenovoID] Direct form: reCAPTCHA token "
             f"{'obtained' if gt else 'unavailable'}")

        # Read the bid (Fingerprint2 browser ID) the page JS already computed.
        bid = ""
        try:
            bid = page.evaluate(  # type: ignore[union-attr]
                """() => {
                const el = document.querySelector('.jsBid, input[name="bid"]');
                return el ? el.value : '';
            }"""
            )
        except Exception:
            pass

        # Fill the loginClass2 form and submit.
        try:
            page.evaluate(  # type: ignore[union-attr]
                """(args) => {
                const form = document.querySelector('.loginClass2 form');
                if (!form) return;
                form.querySelectorAll('input[name="username"]')
                    .forEach(el => { el.value = args.email; });
                form.querySelectorAll('.emailAddressInput')
                    .forEach(el => { el.value = args.email; });
                form.querySelectorAll('input[name="password"]')
                    .forEach(el => { el.value = args.hashed; });
                form.querySelectorAll('input[name="loginfinish"]')
                    .forEach(el => { el.value = '1'; });

                // Append GT (reCAPTCHA) token
                let gtEl = form.querySelector('input[name="gt"]');
                if (!gtEl) {
                    gtEl = document.createElement('input');
                    gtEl.type = 'hidden';
                    gtEl.name = 'gt';
                    gtEl.className = 'GT';
                    const jsBid = form.querySelector('.jsBid');
                    if (jsBid) jsBid.after(gtEl);
                    else form.appendChild(gtEl);
                }
                gtEl.value = args.gt;

                // Ensure bid is set
                const bidEl = form.querySelector('.jsBid, input[name="bid"]');
                if (bidEl && !bidEl.value) bidEl.value = args.bid;
            }""",
                {"email": email, "hashed": hashed, "gt": gt, "bid": bid},
            )
        except Exception as exc:
            _log(f"[LenovoID] Direct form: could not fill form: {exc}")
            return None

        _log("[LenovoID] Direct form: submitting loginClass2 form…")
        try:
            page.evaluate(  # type: ignore[union-attr]
                "document.querySelector('.loginClass2 form').submit()"
            )
            page.wait_for_timeout(10000)  # type: ignore[union-attr]
        except Exception as exc:
            _log(f"[LenovoID] Direct form: submit error: {exc}")

        # Check for WUST in captured navigation or final URL.
        for url in captured:
            w = _find_wust(url)
            if w:
                _log("[LenovoID] ✓ WUST captured from direct form redirect")
                return w

        try:
            w = _find_wust(page.url)  # type: ignore[union-attr]
            if w:
                _log("[LenovoID] ✓ WUST found in URL after direct form submit")
                return w
        except Exception:
            pass

        try:
            body = page.content()  # type: ignore[union-attr]
            w = _find_wust(body)
            if w:
                _log("[LenovoID] ✓ WUST found in body after direct form submit")
                return w
            body_lower = body.lower()
            if "secure connection failed" in body_lower or "neterror" in body_lower:
                _log("[LenovoID] Direct form: TLS error (Akamai reset "
                     "connection — _abck cookie not validated in headless mode)")
            elif "incorrect" in body_lower or "wrong" in body_lower:
                _log("[LenovoID] Direct form: invalid credentials")
            elif "captcha" in body_lower or "robot" in body_lower:
                _log("[LenovoID] Direct form: CAPTCHA/robot block")
            else:
                _log(f"[LenovoID] Direct form: no WUST — URL: "
                     f"{page.url[:80]}")  # type: ignore[union-attr]
        except Exception:
            pass

        return None

    def _solve_captcha_with_ai(
        self,
        page: object,
        captured: list[str],
    ) -> Optional[str]:
        """Use the AI CAPTCHA solver to solve a CAPTCHA on the Lenovo ID
        login page and capture the WUST token from the redirect.

        Called when ``_obtain_wust_browser`` detects a CAPTCHA challenge.
        Requires ``GITHUB_TOKEN`` env var to be set for the GitHub Models
        vision API.

        Returns the WUST token on success, ``None`` on failure.
        """
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if not github_token:
            _log("[LenovoID] GITHUB_TOKEN not set — cannot use AI CAPTCHA solver")
            return None

        try:
            from web_crawler.ai.github_models import GitHubModelsClient
            from web_crawler.ai.captcha_solver import AICaptchaSolver
            import base64 as _b64
        except ImportError as exc:
            _log(f"[LenovoID] AI module not available: {exc}")
            return None

        ai_model = os.environ.get("AI_MODEL", "openai/gpt-4o")
        ai_client = GitHubModelsClient(token=github_token, model=ai_model)
        max_attempts = 3
        solver = AICaptchaSolver(ai_client=ai_client, max_attempts=max_attempts)

        _log("[LenovoID] [AI-CAPTCHA] Attempting to solve CAPTCHA…")

        # Take a full-page screenshot for diagnostic analysis before
        # attempting to solve.  This ensures the image is always sent
        # to the AI model even when element-based detection fails.
        try:
            raw_screenshot = page.screenshot(full_page=True)  # type: ignore[union-attr]
            page_b64 = _b64.b64encode(raw_screenshot).decode("ascii")
            analysis = ai_client.analyze_page_captcha(page_b64)
            if analysis:
                _log(f"[LenovoID] [AI-CAPTCHA] Page analysis: {analysis[:200]}")
        except Exception as exc:
            _log(f"[LenovoID] [AI-CAPTCHA] Page screenshot/analysis error: {exc}")
            page_b64 = ""

        for attempt in range(1, max_attempts + 1):
            solution = solver.solve_captcha_on_page(page)  # type: ignore[arg-type]
            if not solution:
                # Fallback: use the pre-captured full-page screenshot
                # directly with the fullpage recogniser.
                if page_b64:
                    _log(f"[LenovoID] [AI-CAPTCHA] Attempt {attempt}: "
                         "element detection failed — trying fullpage screenshot")
                    result = ai_client.recognize_captcha_fullpage(page_b64)
                    if result.get("isSuccess"):
                        solution = result["verificationCode"]
                        upper = solution.upper()
                        if upper in ("NO_CAPTCHA", "NOCAPTCHA",
                                     "SLIDER", "CHECKBOX"):
                            _log(f"[LenovoID] [AI-CAPTCHA] Attempt {attempt}: "
                                 f"AI detected '{upper}' — cannot auto-solve")
                            solution = None

            if not solution:
                _log(f"[LenovoID] [AI-CAPTCHA] Attempt {attempt}: no solution")
                continue

            _log(f"[LenovoID] [AI-CAPTCHA] Attempt {attempt}: solution='{solution}'")

            # Fill the CAPTCHA input and submit
            captcha_filled = False
            for sel in [
                "input[id*='captcha' i]",
                "input[name*='captcha' i]",
                "input[id*='verify' i]",
                "input[name*='verify' i]",
                "input[placeholder*='code' i]",
                "input[placeholder*='captcha' i]",
            ]:
                try:
                    el = page.query_selector(sel)  # type: ignore[union-attr]
                    if el and el.is_visible():
                        el.fill("")
                        el.type(solution, delay=50)
                        el.dispatch_event("input")
                        el.dispatch_event("change")
                        captcha_filled = True
                        break
                except Exception:
                    continue

            if not captcha_filled:
                _log("[LenovoID] [AI-CAPTCHA] Could not find CAPTCHA input field")
                continue

            page.keyboard.press("Enter")  # type: ignore[union-attr]
            page.wait_for_timeout(5000)  # type: ignore[union-attr]

            # Check if WUST was captured after CAPTCHA submit
            for url in captured:
                w = _find_wust(url)
                if w:
                    _log("[LenovoID] [AI-CAPTCHA] ✓ WUST captured after solving CAPTCHA")
                    return w

            w = _find_wust(page.url)  # type: ignore[union-attr]
            if w:
                _log("[LenovoID] [AI-CAPTCHA] ✓ WUST found in URL after CAPTCHA")
                return w

            _log(f"[LenovoID] [AI-CAPTCHA] Attempt {attempt}: no WUST after submit")

        _log("[LenovoID] [AI-CAPTCHA] All attempts failed")
        return None

    def _obtain_wust_requests(
        self, email: str, password: str, login_url: str
    ) -> Optional[str]:
        """Requests-based fallback for ``_obtain_wust_browser``.

        Only succeeds when the Akamai ``_abck`` cookie is not required
        (e.g. on lsatest.lenovo.com or when the session is already trusted).
        Uses the real login URL from ``getApiInfo.jhtml``.
        """
        # --- Step 1: preLogin — collects JSESSIONID + sign-key ---
        _log(f"[LenovoID] Loading OAuth login page: {login_url[:80]}")
        try:
            r = self._sess.get(
                login_url,
                timeout=30,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            _log(f"[LenovoID] login page request failed: {exc}")
            return None

        if r.status_code != 200:
            _log(f"[LenovoID] preLogin HTTP {r.status_code}")
            return None

        # Merge server-supplied hidden fields over our defaults.
        form_fields = dict(_LMSA_FORM_DEFAULTS)
        form_fields.update(_extract_hidden_fields(r.text))
        # Ensure callback URL is always correct.
        form_fields["lenovoid.cb"] = _LMSA_CB_URL
        form_fields["username"] = email
        form_fields["password"] = _hash_password(password)
        # loginfinish=1 signals the email+password form (loginClass2).
        # gt is the reCAPTCHA Enterprise v3 token — normally injected by
        # JS but we send an empty value for the HTTP-only fallback path.
        form_fields.setdefault("loginfinish", "1")
        form_fields.setdefault("gt", "")

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
            # Stop if we reach the callback URL (LMSA never loads it).
            if "/Tips/lenovoIdSuccess.html" in loc:
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
        authenticated :class:`LMSASession`.

        HAR-confirmed flow (HTTPToolkit_2026-03-03_18-12.har, entry [37]):

        * URL:  ``POST https://lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml``
        * Auth: ``author: false`` → NO ``guid`` or ``Authorization`` request headers.
        * Body: ``{"client":{"version":"7.5.4.2"},"dparams":{"wust":"…","guid":"…"},
          "language":"en-US","windowsInfo":"Microsoft Windows 11 Pro, x64-based PC"}``
        * JWT : returned in **response** ``Authorization`` header (raw, no "Bearer " prefix).
        * GUID: echoed back in response ``Guid`` header (must match request body guid).

        Subsequent API calls (card.jhtml, languagePack.jhtml, …) add::

            Authorization: Bearer <JWT>
            guid: <GUID>

        to every request header.
        """
        guid = str(uuid.uuid4()).lower()
        # _lmsa_base is already "https://lsa.lenovo.com/Interface"
        # so we must NOT add another "/Interface" prefix here.
        # URL confirmed by HAR entry [37]: POST lsa.lenovo.com/Interface/user/lenovoIdLogin.jhtml
        url = f"{self._lmsa_base}/user/lenovoIdLogin.jhtml"

        body = {
            "client":      {"version": CLIENT_VERSION},
            "dparams":     {"wust": wust, "guid": guid},
            "language":    "en-US",
            "windowsInfo": "Microsoft Windows 11 Pro, x64-based PC",
        }
        # author: false in C# source — do NOT send guid request header
        hdrs = dict(_BASE_HEADERS)

        _log(f"[LenovoID] Exchanging WUST for JWT via {url}")
        try:
            r = requests.post(url, json=body, headers=hdrs,
                              timeout=30, verify=self._verify_ssl)
        except requests.RequestException as exc:
            _log(f"[LenovoID] lenovoIdLogin POST failed: {exc}")
            return None

        # JWT arrives in Authorization response header when server echoes GUID.
        # HAR entry [37] confirmed: response Authorization is a raw token (no
        # "Bearer " prefix).  C# source (RequestBase, WebApiHttpRequest.cs):
        #   if (Guid_header == WebApiContext.GUID && Authorization_header != "")
        #       JWT_TOKEN = Authorization_header;
        jwt = None
        guid_resp = r.headers.get("Guid", "")
        auth_hdr  = r.headers.get("Authorization", "")
        if guid_resp.lower() == guid and auth_hdr:
            # Primary path (HAR-confirmed): server echoes our GUID back.
            jwt = auth_hdr.removeprefix("Bearer ").strip()
        elif auth_hdr:
            # Fallback: accept any non-empty Authorization regardless of GUID echo
            # (handles edge-case server responses that include "Bearer " prefix).
            jwt = auth_hdr.removeprefix("Bearer ").strip()

        try:
            data = r.json()
        except ValueError:
            _log(f"[LenovoID] Non-JSON response from lenovoIdLogin: "
                 f"{r.text[:200]}")
            return None

        _log(f"[LenovoID] lenovoIdLogin HTTP {r.status_code}, code={data.get('code')}, "
             f"desc={data.get('desc','')[:100]}")

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

        # JWT may also be embedded in the response body content.
        if not jwt:
            content = data.get("content") or data.get("data") or {}
            if isinstance(content, dict):
                jwt = content.get("token") or content.get("jwt")

        session = LMSASession(
            base_url=self._lmsa_base,
            guid=guid,
        )
        if jwt:
            # Inject token directly into the private field and into the
            # session's permanent headers (needed for direct GET calls that
            # bypass _post() / _request_headers()).
            session._jwt_token = jwt
            session._session.headers["Authorization"] = f"Bearer {jwt}"
            session._session.headers["guid"] = guid
            _log("[LenovoID] ✓ JWT token received — session ready")
        else:
            _log(
                "[LenovoID] ✓ lenovoIdLogin succeeded (code 0000) "
                "but no explicit JWT in response — session may be usable"
            )

        return session
