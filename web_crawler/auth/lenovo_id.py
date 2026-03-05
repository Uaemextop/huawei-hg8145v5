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

import hashlib
import json as _json
import uuid as _uuid

import os
import re
import uuid
from typing import Optional
from urllib.parse import urljoin

import requests

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
        then tries Playwright browser automation (bypasses Akamai Bot Manager),
        falling back to plain HTTP requests when Playwright is not installed.
        """
        login_url = self._get_login_url()

        if _PLAYWRIGHT_AVAILABLE:
            wust = self._obtain_wust_browser(email, password, login_url)
            if wust:
                return wust
            _log("[LenovoID] Browser login failed – trying plain HTTP fallback")

        return self._obtain_wust_requests(email, password, login_url)

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
                import random as _rnd
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

        Confirmed by decompiling ``Software Fix.exe``:
        - ``author: false`` → NO ``guid`` header in the HTTP request.
        - ``dparams`` contains ``{wust: WUST, guid: PLAIN_GUID}``.
        - JWT is extracted from the ``Authorization`` response header
          when the server echoes back the client GUID in the ``Guid``
          response header.
        """
        guid = str(uuid.uuid4()).lower()
        # _lmsa_base is already "https://lsa.lenovo.com/Interface"
        # so we must NOT add another "/Interface" prefix here.
        url = f"{self._lmsa_base}/user/lenovoIdLogin.jhtml"

        body = {
            "client":      {"version": CLIENT_VERSION},
            "dparams":     {"wust": wust, "guid": guid},
            "language":    "en-US",
            "windowsInfo": "Microsoft Windows 11 Pro, x64-based PC",
        }
        # author: false in C# source — do NOT send guid request header
        hdrs = dict(_BASE_HEADERS)

        _log(f"[LenovoID] Exchanging WUST for JWT: {url}")
        try:
            r = requests.post(url, json=body, headers=hdrs,
                              timeout=30, verify=self._verify_ssl)
        except requests.RequestException as exc:
            _log(f"[LenovoID] lenovoIdLogin POST failed: {exc}")
            return None

        # JWT arrives in Authorization response header when server echoes GUID.
        # From RequestBase in WebApiHttpRequest.cs (decompiled):
        #   if (Guid_header == WebApiContext.GUID && Authorization_header != "")
        #       JWT_TOKEN = Authorization_header;
        jwt = None
        guid_resp = r.headers.get("Guid", "")
        auth_hdr  = r.headers.get("Authorization", "")
        if guid_resp.lower() == guid and auth_hdr:
            jwt = auth_hdr
        elif auth_hdr.startswith("Bearer "):
            jwt = auth_hdr[len("Bearer "):]

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
