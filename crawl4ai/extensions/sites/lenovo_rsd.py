"""
crawl4ai.extensions.sites.lenovo_rsd – Site module for rsdsecure-test.lenovo.com.

Lenovo Rescue & Smart Doctor (RSD / "Software Fix") hosts firmware images,
flash tools, and flash-flow configuration files on an S3+CloudFront
bucket behind AWS Signature V4 pre-signed URLs.

The files are NOT reachable by direct link — they require an authenticated
session through the ``lsatest.lenovo.com`` LMSA back-end, which in turn
delegates authentication to the Lenovo ID OAuth 2 + PKCE identity provider
at ``passport-sit.lenovo.com``.

Discovery flow (replicated from the LMSA desktop client, as observed in
the captured HAR traffic — 43 entries, sorted chronologically):

Phase 1 — Bootstrap (lsatest.lenovo.com, unauthenticated)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
These calls do NOT require an ``Authorization`` header.  They use the
LMSA desktop-client UA and ``Request-Tag: lmsa`` header.

1. ``POST /Interface/apk/download.jhtml``
   Body: ``{"client":{"version":"7.5.5.3"}, "dparams":{"versionCode":0}, …}``
   → ``{"code":"1000","desc":"APK not exist.","content":null}``
2. ``POST /Interface/rescueDevice/modelReadConfigration.jhtml``
   Body: ``{"client":{"version":"7.5.5.3"}, "dparams":null, …}``
   → JSON with device → prop-name mapping list.
3. ``POST /Interface/notice/getBroadcast.jhtml`` → broadcast list.
4. ``POST /Interface/client/getNextUpdateClient.jhtml``
   Body: ``dparams.country = "MX"`` → ``{"code":"1000","desc":"No results"}``
5. ``POST /Interface/dictionary/getApiInfo.jhtml``
   Body: ``dparams.key = "TIP_URL"``
   → ``{"code":"0000","content":"https://passport-sit.lenovo.com/v1.0/
   utility/lenovoid/oauth2/authorize?state=…&client_id=127cbff4…
   &response_type=code&redirect_uri=https://lsatest.lenovo.com/Tips/
   lenovoIdSuccess.html&scope=openid&code_challenge=…
   &code_challenge_method=S256"}``

Phase 2 — Authenticate (passport-sit.lenovo.com)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The LMSA client opens the browser to the OAuth2 URL.  The redirect chain:

6. ``GET /v1.0/utility/lenovoid/oauth2/authorize?…`` → 302 to gateway.
   Response sets ``lenovoid.realm``, ``lang`` cookies.
7. ``GET /glbwebauthnv6/gateway?…`` → 302 to preLogin.
   Sets ``JSESSIONID``, ``lenovoid.webLoginSignkey``,
   ``lenovoid.diyoptions.w5`` cookies.
8. ``GET /glbwebauthnv6/preLogin?…`` → 200 HTML login page.
   Full login form with jQuery, reCAPTCHA Enterprise, theme JS.

After user types credentials:

9. ``POST /glbwebauthnv6/ajaxUserExistedServlet?username=…`` → 400
   (check if user exists; 400 = user exists).
10. ``POST /glbwebauthnv6/ajaxUserRoam?username=…`` → ``{"resultCode":0}``
11. ``POST /glbwebauthnv6/userLogin`` (form-encoded) →
    Sets ``LPSState=1``, ``LPSWUST=…``, ``LPSWUTGT=…``,
    ``LenovoID.UN``, ``LenovoID.UNENC``, ``LenovoID.usertype=LenovoID2C``,
    ``location=MX``, ``loginSource``, ``lenovoid_lastlogin`` cookies.
    Body is HTML with JS redirect to oauth2/callback.

12. ``GET /v1.0/utility/lenovoid/oauth2/callback?lenovoid.wust=…`` → 200
    HTML page with JS: ``window.location.href = "https://lsatest.lenovo.com/
    Tips/lenovoIdSuccess.html?code=<AUTH_CODE>&scope=openid&state=…"``
    **Key**: the auth code is embedded in the HTML/JS as a redirect URL.

Phase 3 — Token exchange (lsatest.lenovo.com)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
13. Browser loads ``/Tips/lenovoIdSuccess.html?code=…`` (static HTML).
14. JS calls ``GET /Tips/lmsa/tips/getOauth2Url.jhtml`` →
    ``{"msg":"https://lsatest.lenovo.com/Interface/user/oauth2/callback.jhtml"}``
15. JS calls ``GET /Interface/user/oauth2/callback.jhtml?code=…&scope=openid``
    → ``{"code":"0000","content":"softwareFix://callback?fullName=…
    &Authorization=<BEARER_TOKEN>"}``
    **The Authorization value is the Bearer token for all subsequent API calls.**

Phase 4 — Authenticated API calls (lsatest.lenovo.com)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
All subsequent calls use ``Authorization: Bearer <token>`` header along
with the LMSA headers (``Request-Tag: lmsa``, ``clientVersion: 7.5.5.3``).

16. ``GET /Interface/user/getSFUserInfo.jhtml`` → user info + userId.
17. ``GET /Interface/vip/card.jhtml`` → VIP card / pricing info.
18. ``POST /Interface/client/languagePack.jhtml`` → language pack.
19. ``POST /Interface/priv/getPrivInfo.jhtml`` → privilege info.
20. ``POST /Interface/registeredModel/addModels.jhtml`` → register models.
21. ``POST /Interface/feedback/getFeedbackIssueInfo.jhtml`` → issue tree.
22. ``POST /Interface/notice/getNoticeInfo.jhtml`` → notices.
23. ``POST /Interface/survey/getAllQuestions.jhtml`` → survey questions.
24. ``POST /Interface/feedback/getFeedbackList.jhtml`` → feedback.
25. ``POST /Interface/rescueDevice/getModelNames.jhtml``
    Body: ``dparams.country="Mexico", dparams.category="Phone"``
    → ``{"content":{"models":[…]}}`` — 42 models (Motorola, Lenovo, ZUK).
26. ``POST /Interface/rescueDevice/getResource.jhtml``
    Body: ``dparams.modelName="XT2523-2", dparams.marketName="Moto g05 5G"``
    → ``{"content":[{…, "romResource":{"uri":"https://rsdsecure-test.lenovo.com/
    …?X-Amz-Algorithm=AWS4-HMAC-SHA256&…"}, "toolResource":{…},
    "flashFlow":"https://rsdsecure-test.lenovo.com/…?X-Amz-…"}]}``

Phase 5 — File downloads (rsdsecure-test.lenovo.com)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
27-30. ``GET /<filename>.zip?X-Amz-Algorithm=…`` → ``200``
    - S3 + CloudFront pre-signed URLs.  ``X-Amz-Expires=604800`` (7 days).
    - Response: ``Content-Type: application/octet-stream``
    - ``x-amz-meta-sha256``: file checksum in response header.
    - ``x-amz-meta-s3b-last-modified``: file modification timestamp.
    - ROM images can exceed 5 GB (e.g. ``Content-Length: 5727295273``).
    - Tools are ~34 MB.  FlashFlow configs are JSON files (~few KB).

Cookie-based authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~
To avoid replaying the full login flow (which requires reCAPTCHA and a
password hash), this module supports importing existing session cookies
from ``passport-sit.lenovo.com`` via the ``LENOVO_RSD_COOKIES`` env var
(JSON array of cookie objects from a browser extension export).

The critical cookies that enable SSO token issuance are:
- ``LPSWUST`` — session token (set by ``userLogin``).
- ``LPSWUTGT`` — TGT token (set by ``userLogin``).
- ``LPSState=1`` — login state flag.
- ``JSESSIONID`` — server session.
- ``lenovoid.realm=lenovo.mbg.service.lmsa`` — OAuth realm.
- ``lenovoid.webLoginSignkey`` — anti-CSRF key.

With these cookies loaded into the session cookie jar, calling the
``getApiInfo → oauth2/authorize → callback`` chain works without
re-entering credentials.

Infrastructure:
- **lsatest.lenovo.com** — LMSA Java back-end, base64-encoded JSON bodies.
- **passport-sit.lenovo.com** — Lenovo ID OAuth2 + PKCE, Spring Security.
- **rsdsecure-test.lenovo.com** — S3 (``us-east-1``) + CloudFront, AWS
  Signature V4 pre-signed URLs with 7-day TTL (``X-Amz-Expires=604800``).
  Response headers include ``x-amz-meta-sha256`` (file hash) and
  ``x-amz-meta-s3b-last-modified`` (modification timestamp).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
import urllib.parse
from http.cookiejar import Cookie
from typing import TYPE_CHECKING, Any

from .base import BaseSiteModule, FileEntry

if TYPE_CHECKING:
    import requests

__all__ = ["LenovoRSDModule"]

log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────

_LSATEST_HOST = "lsatest.lenovo.com"
_PASSPORT_HOST = "passport-sit.lenovo.com"
_RSD_HOSTS = {"rsdsecure-test.lenovo.com"}

_LSATEST_BASE = f"https://{_LSATEST_HOST}"
_PASSPORT_BASE = f"https://{_PASSPORT_HOST}"

_CLIENT_VERSION = "7.5.5.3"
_WINDOWS_INFO = "Microsoft Windows 11 Pro, x64-based PC"
_LANGUAGE = "en-US"

# Standard LMSA desktop-client headers (from HAR entries 1-5, 22-33).
_LMSA_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
    ),
    "Content-Type": "application/json",
    "Request-Tag": "lmsa",
    "clientVersion": _CLIENT_VERSION,
    "windowsInfo": "Microsoft Windows 11 Pro",
    "language": _LANGUAGE,
    "Cache-Control": "no-store,no-cache",
    "Pragma": "no-cache",
}

# Browser UA used for the passport OAuth2 redirect chain (HAR entries 7-17).
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

_CATEGORIES = ["Phone", "Tablet"]
_COUNTRIES = ["Mexico"]

# Delay between API calls (seconds) to avoid rate-limiting.
_REQUEST_DELAY = 0.5

# ── Hardcoded passport-sit.lenovo.com session cookies ────────────────────
# These cookies allow skipping the interactive login flow (reCAPTCHA +
# password hash).  They are loaded into the requests session cookie jar
# when no ``LENOVO_RSD_COOKIES`` env-var override is provided.
#
# The critical cookies for SSO auto-login are:
# - LPSWUST / LPSWUTGT — session tokens from ``POST userLogin``
# - LPSState=1 — login state flag
# - JSESSIONID — server session
# - lenovoid.realm — OAuth realm
# - lenovoid.webLoginSignkey — anti-CSRF key
_DEFAULT_PASSPORT_COOKIES: list[dict[str, object]] = [
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.action", "value": "", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": "passport-sit.lenovo.com", "name": "JSESSIONID", "value": "3CFDC96074D7B0AD46AADE3E5E3DBA36", "path": "/", "secure": True, "httpOnly": True, "hostOnly": True},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.diyoptions.w5", "value": "eyJsZW5vdm9pZC5oaWRlZGlzY29yZCI6IjEiLCJsZW5vdm9pZC5oaWRlZmFjZWJvb2siOiIxIiwibGVub3ZvaWQuaGlkZWdvb2dsZSI6IjEiLCJsZW5vdm9pZC5oaWRlbGFuZ3VhZ2UiOiIxIiwibGVub3ZvaWQuaGlkZXBob25lbG9naW4iOiIxIiwibGVub3ZvaWQuaGlkZWxvZ2lucmVnIjoiMSIsImxlbm92b2lkLmhpZGVtaWNyb3NvZnQiOiIxIiwibGVub3ZvaWQuaGlkZXN0ZWFtIjoiMSIsImxlbm92b2lkLmhpZGVyZWdwaG9uZSI6IjEiLCJsZW5vdm9pZC5oaWRldHdpdGNoIjoiMSIsImxlbm92b2lkLnByaXZhY3kiOm51bGwsImxlbm92b2lkLlRlcm1zIjpudWxsLCJsZW5vdm9pZC56b29tIjoiMSIsImxlbm92b2lkLnRoZW1lIjoiaWQiLCJsZW5vdm9pZC5zZGsiOm51bGx9", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": ".passport-sit.lenovo.com", "name": "LenovoID.UNENC", "value": "eduardo%40uaemex.top", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850226},
    {"domain": ".passport-sit.lenovo.com", "name": "lang", "value": "en_US", "path": "/", "secure": False, "httpOnly": False, "hostOnly": False, "expirationDate": 1774851002},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.theme", "value": "", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.diyoptions", "value": "eyJsZW5vdm9pZC5oaWRld2VjaGF0IjoiMSIsImxlbm92b2lkLmhpZGVxcSI6IjEiLCJsZW5vdm9pZC5oaWRlc2luYSI6IjEiLCJsZW5vdm9pZC5oaWRlbGFuZ3VhZ2UiOiIxIiwibGVub3ZvaWQuaGlkZWF1dG9sb2dpbiI6IjEiLCJsZW5vdm9pZC5oaWRlcmVnZW1haWwiOiIxIiwibGVub3ZvaWQuaGlkZXJlZ21vYmlsZSI6IjEiLCJsZW5vdm9pZC5oaWRlc21zbG9naW4iOiIxIiwibGVub3ZvaWQuaGlkZXFybG9naW4iOiIxIiwibGVub3ZvaWQud2Vic3RhdGUiOiIwIiwibGVub3ZvaWQuaGlkZWxvZ2lucmVnIjoiMSIsImxlbm92b2lkLmhpZGVtYWlsbG9naW4iOiIxIiwibGVub3ZvaWQuYXV0aG5zZXEiOiIwIiwibGVub3ZvaWQuaGlkZW1pY3Jvc29mdCI6IjAifQ", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": ".passport-sit.lenovo.com", "name": "LPSState", "value": "1", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850226},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.realm", "value": "lenovo.mbg.service.lmsa", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850952},
    {"domain": ".passport-sit.lenovo.com", "name": "LenovoID.UN", "value": "eduardo@uaemex.top", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850226},
    {"domain": ".passport-sit.lenovo.com", "name": "LenovoID.usertype", "value": "LenovoID2C", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850226},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.webLoginBindPath", "value": "cnwebauthnv3", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.webLoginSignkey", "value": "1773986952719%23CA4OCgABDwAMCw4IAA%3D%3D", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid.zoom", "value": "", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": ".passport-sit.lenovo.com", "name": "lenovoid_lastlogin", "value": "cnwebauthnv3", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False},
    {"domain": ".passport-sit.lenovo.com", "name": "location", "value": "MX", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850226},
    {"domain": ".passport-sit.lenovo.com", "name": "loginSource", "value": "wauthen2", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850861},
    {"domain": ".passport-sit.lenovo.com", "name": "LPSWUST", "value": "ZAgEAAAAAAGE9MTMwMDAwMTYxODI1OSZiPTImYz0xJmQ9MCZlPTYyRTcwNjI4MTcwNUE0MTM5N0I5MjhGNDEzRTczODVGMCZoPTE3NzM5ODYyMjc0NDgmaT0zNDU2MDAwJm89ZDllZGFlMjRiNzk5NWMzMTUxODFkMjA4MzU3MWY5ZDQmcD13YXV0aCZxPTAmcj0xJmFtcj1wd2QmdXNlcm5hbWU9ZWR1YXJkb0B1YWVtZXgudG9w5sQOryIwiKHoRqZRh4vytg", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850226},
    {"domain": ".passport-sit.lenovo.com", "name": "LPSWUTGT", "value": "ZAgEAAAAAAGE9MTMwMDAwMTYxODI1OSZiPTImYz0xJmQ9MCZlPTYyRTcwNjI4MTcwNUE0MTM5N0I5MjhGNDEzRTczODVGMCZoPTE3NzM5ODYyMjc0NDgmaT0zNDU2MDAwJm89ZDllZGFlMjRiNzk5NWMzMTUxODFkMjA4MzU3MWY5ZDQmcD13YXV0aCZxPTAmcj0xJmFtcj1wd2QmdXNlcm5hbWU9ZWR1YXJkb0B1YWVtZXgudG9w5sQOryIwiKHoRqZRh4vytg", "path": "/", "secure": True, "httpOnly": True, "hostOnly": False, "expirationDate": 1774850226},
]


# ── Helpers ──────────────────────────────────────────────────────────────

def _b64decode_json(text: str) -> Any:
    """Decode a base64-encoded JSON response body from lsatest.

    The lsatest.lenovo.com API encodes JSON responses as base64.  This is
    observed in ALL ``application/json;charset=UTF-8`` responses in the HAR
    (entries 1-5, 10, 20-33, 42).  We try base64 first; if it fails
    (e.g. the ``oauth2/callback`` HTML response in entry 17), fall back to
    plain JSON.
    """
    try:
        raw = base64.b64decode(text)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        # Not base64 — try plain JSON.
        return json.loads(text)


def _make_lmsa_body(
    dparams: Any = None,
    language: str = _LANGUAGE,
) -> dict[str, Any]:
    """Build the standard LMSA request body envelope.

    Every POST to ``lsatest.lenovo.com/Interface/…`` uses this envelope::

        {"client":{"version":"7.5.5.3"}, "dparams":…,
         "language":"en-US", "windowsInfo":"Microsoft Windows 11 Pro, x64-based PC"}

    Observed in HAR entries 1-5, 10, 24-26, 28-33, 42.
    """
    return {
        "client": {"version": _CLIENT_VERSION},
        "dparams": dparams,
        "language": language,
        "windowsInfo": _WINDOWS_INFO,
    }


def _import_cookies_to_jar(
    session: "requests.Session",
    cookies_json: list[dict[str, Any]],
) -> None:
    """Import browser-exported cookies into a requests session cookie jar.

    Accepts the JSON array format exported by browser extensions like
    "Cookie Editor" or "EditThisCookie".  Each object has:
    ``domain``, ``name``, ``value``, ``path``, ``secure``, ``httpOnly``,
    ``expirationDate`` (optional), ``hostOnly`` (optional).
    """
    for c in cookies_json:
        domain = c.get("domain", "")
        name = c.get("name", "")
        value = c.get("value", "")
        path = c.get("path", "/")
        secure = c.get("secure", False)
        expires = c.get("expirationDate")
        host_only = c.get("hostOnly", False)

        # Convert expirationDate (unix timestamp float) to int or None.
        if expires is not None:
            try:
                expires = int(expires)
            except (ValueError, TypeError):
                expires = None

        # domain_specified = not hostOnly (i.e. the cookie applies to
        # sub-domains when the domain starts with ".").
        domain_specified = not host_only
        domain_dot = domain.startswith(".")
        # If hostOnly, the domain must be exact (no leading dot).
        if host_only and domain_dot:
            domain = domain.lstrip(".")

        cookie = Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=domain_specified,
            domain_initial_dot=domain_dot,
            path=path,
            path_specified=bool(path),
            secure=secure,
            expires=expires,
            discard=expires is None,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": ""} if c.get("httpOnly") else {},
        )
        session.cookies.set_cookie(cookie)


# ── Module ───────────────────────────────────────────────────────────────


class LenovoRSDModule(BaseSiteModule):
    """Crawl ``rsdsecure-test.lenovo.com`` firmware catalog via LMSA APIs.

    Authentication options (checked in order):

    1. **Cookie import** (recommended) — Set ``LENOVO_RSD_COOKIES`` env var
       to a JSON array of browser-exported cookies from
       ``passport-sit.lenovo.com``.  The module loads them into the session
       cookie jar and uses the existing SSO session to obtain a Bearer token
       via the OAuth2 authorize → callback chain — no password needed.

    2. **Username/password** — Set ``LENOVO_RSD_USERNAME`` and
       ``LENOVO_RSD_PASSWORD`` (MD5 uppercase hex hash of the password, as
       sent by the LMSA client).  The module replays the full login flow.

    3. **Anonymous** — If neither is set, the module attempts unauthenticated
       discovery.  ``getModelNames`` works without auth, but ``getResource``
       will likely fail, producing an index with model metadata only.
    """

    name = "LenovoRSDModule"
    hosts = list(_RSD_HOSTS | {_LSATEST_HOST})

    def __init__(self, session: "requests.Session | None" = None) -> None:
        super().__init__(session=session)
        self._auth_token: str | None = None

    # ── Interface ────────────────────────────────────────────────────

    def matches(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        return host in _RSD_HOSTS or host == _LSATEST_HOST

    def generate_index(self, url: str) -> list[FileEntry]:
        """Discover all firmware resources and return file metadata."""
        import requests as _requests

        if self.session is None:
            self.session = _requests.Session()

        entries: list[FileEntry] = []

        # ── Step 1: Import cookies if available ──────────────────────
        self._load_cookies()

        # ── Step 2: Authenticate ─────────────────────────────────────
        log.info("── LenovoRSD: Starting authentication flow ──")
        self._authenticate()
        if self._auth_token:
            log.info("  Authentication successful — Bearer token acquired")
        else:
            log.info("  No auth token — proceeding with limited access")

        # ── Step 3: Discover models ──────────────────────────────────
        log.info("── LenovoRSD: Discovering device models ──")
        models = self._discover_models()
        log.info("  Found %d models across all categories", len(models))

        # ── Step 4: Fetch resources for each model ───────────────────
        log.info("── LenovoRSD: Fetching resources for %d models ──",
                 len(models))
        for i, model in enumerate(models):
            model_name = model.get("modelName", "")
            market_name = model.get("marketName", "")
            brand = model.get("brand", "")
            platform = model.get("platform", "")
            category = model.get("category", "")

            log.info(
                "  [%d/%d] %s %s (%s) [%s]",
                i + 1, len(models), brand, market_name or model_name,
                model_name, platform,
            )

            resources = self._get_resources(model_name, market_name)
            if not resources:
                log.info("    → no resources")
                continue

            for res in resources:
                model_entries = self._extract_file_entries(res, category)
                entries.extend(model_entries)
                if model_entries:
                    log.info("    → %d file(s)", len(model_entries))

            time.sleep(_REQUEST_DELAY)

        log.info("── LenovoRSD: Index complete — %d file entries ──",
                 len(entries))
        return entries

    # ── Cookie loading ───────────────────────────────────────────────

    def _load_cookies(self) -> None:
        """Load passport cookies into the session.

        Priority:
        1. ``LENOVO_RSD_COOKIES`` env var (JSON array from browser export).
        2. ``_DEFAULT_PASSPORT_COOKIES`` hardcoded in this module.
        """
        assert self.session is not None

        # Try env var first.
        cookies_raw = os.environ.get("LENOVO_RSD_COOKIES", "").strip()
        if cookies_raw:
            try:
                cookies = json.loads(cookies_raw)
                if isinstance(cookies, list):
                    _import_cookies_to_jar(self.session, cookies)
                    log.info("  Loaded %d cookies from LENOVO_RSD_COOKIES",
                             len(cookies))
                    return
            except json.JSONDecodeError as exc:
                log.warning("  LENOVO_RSD_COOKIES JSON parse error: %s", exc)

        # Fall back to hardcoded cookies.
        _import_cookies_to_jar(self.session, _DEFAULT_PASSPORT_COOKIES)
        log.info("  Loaded %d hardcoded passport cookies",
                 len(_DEFAULT_PASSPORT_COOKIES))

    # ── Authentication ───────────────────────────────────────────────

    def _authenticate(self) -> None:
        """Run the OAuth2+PKCE authentication flow.

        Uses cookies (if loaded) to skip the login form.  Falls back to
        username/password if cookies are not present.

        Flow (matching HAR entries 5, 7-8, 9, 16, 17, 19, 20, 21):

        1. ``POST getApiInfo(TIP_URL)`` → get OAuth2 authorize URL.
        2. ``GET authorize`` → 302 → ``GET gateway`` → 302 →
           ``GET preLogin`` OR (with cookies) auto-redirect to callback.
        3. If cookies present: callback HTML contains auth code in JS.
           If not: need to POST ``userLogin`` with credentials, then
           follow redirect to callback.
        4. ``GET /Interface/user/oauth2/callback.jhtml?code=…`` →
           extract ``Authorization`` Bearer token.
        """
        assert self.session is not None

        # 1. Get the OAuth2 authorize URL (HAR entry 5 / 10).
        oauth_url = self._get_oauth_url()
        if not oauth_url:
            log.warning("  Failed to retrieve OAuth2 URL from getApiInfo")
            return

        log.info("  Got OAuth2 authorize URL")

        # 2. Follow the passport redirect chain.
        #    With valid cookies (LPSWUST, LPSWUTGT), the chain is:
        #    authorize → gateway → (auto-login) → callback page with code.
        #    Without cookies: authorize → gateway → preLogin (login form).
        redirect_qs = self._follow_oauth_chain(oauth_url)

        # 3. If no code from cookie-based flow, try username/password.
        if not redirect_qs:
            username = os.environ.get("LENOVO_RSD_USERNAME", "")
            password = os.environ.get("LENOVO_RSD_PASSWORD", "")

            if username and password:
                log.info("  Cookie auth failed, trying username/password")
                # Need a fresh OAuth URL (new state/code_challenge).
                oauth_url = self._get_oauth_url()
                if oauth_url:
                    prelogin_ok = self._passport_prelogin(oauth_url)
                    if prelogin_ok:
                        login_ok = self._passport_login(username, password)
                        if login_ok:
                            redirect_qs = self._get_auth_code_from_callback()
            else:
                log.info("  No cookies and no credentials — unauthenticated mode")

        if not redirect_qs:
            log.warning("  Could not obtain authorization code")
            return

        log.info("  Got authorization code")

        # 4. Exchange the code for a Bearer token (HAR entry 21).
        token = self._exchange_code(redirect_qs)
        if token:
            self._auth_token = token
        else:
            log.warning("  Code exchange failed — no Bearer token")

    def _get_oauth_url(self) -> str | None:
        """``POST getApiInfo`` with ``key=TIP_URL`` (HAR entries 5, 10).

        Returns the full OAuth2 authorize URL including ``client_id``,
        ``state``, ``code_challenge``, ``redirect_uri``.
        """
        assert self.session is not None
        body = _make_lmsa_body(dparams={"key": "TIP_URL"})
        try:
            resp = self.session.post(
                f"{_LSATEST_BASE}/Interface/dictionary/getApiInfo.jhtml",
                json=body,
                headers=_LMSA_HEADERS,
                timeout=30,
            )
            data = _b64decode_json(resp.text)
            if data.get("code") == "0000":
                return data.get("content")
        except Exception as exc:
            log.debug("  getApiInfo error: %s", exc)
        return None

    def _follow_oauth_chain(self, oauth_url: str) -> str | None:
        """Follow the OAuth2 redirect chain and extract the auth code.

        The chain is: authorize (302) → gateway (302) → preLogin (200).

        Two possible outcomes at preLogin:

        A) **Cookies valid (auto-login)** — The server recognizes the
           LPSWUST/LPSWUTGT cookies and renders an HTML page with a JS
           variable ``gateway`` containing the full callback URL::

               var gateway = 'https://passport-sit.lenovo.com/v1.0/
               utility/lenovoid/oauth2/callback?lenovoid.wust=…';
               window.location.href = gateway;

           We extract this ``gateway`` URL and follow it to the callback
           page (HAR entry 17), which contains the auth code in its JS.

        B) **Cookies expired** — The server renders the login form
           (``<title>Sign In</title>``).  Return ``None``.
        """
        assert self.session is not None
        headers = {
            "User-Agent": _BROWSER_UA,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Language": "es-US,es-419;q=0.9,es;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        }
        try:
            # Follow the authorize → gateway → preLogin chain.
            resp = self.session.get(
                oauth_url, headers=headers, timeout=30,
                allow_redirects=True,
            )
            if resp.status_code != 200:
                log.debug("  OAuth chain ended with status %d",
                          resp.status_code)
                return None

            body = resp.text

            # ── Case A: Auto-login page with gateway JS variable ─────
            # HAR entry 16 (userLogin response) pattern:
            #   var gateway = 'https://…/oauth2/callback?lenovoid.wust=…';
            #   window.location.href = gateway;
            # The server may escape slashes as \/ in the JS string.
            gateway_match = re.search(
                r"var\s+gateway\s*=\s*'([^']+)'", body,
            )
            if gateway_match:
                gateway_url = gateway_match.group(1)
                # Unescape JS slash escapes: \/ → /
                gateway_url = gateway_url.replace("\\/", "/")
                if gateway_url.startswith("http"):
                    log.info("  Found gateway redirect URL (auto-login)")
                    # Follow the gateway URL to the callback page.
                    resp2 = self.session.get(
                        gateway_url, headers=headers, timeout=30,
                        allow_redirects=True,
                    )
                    if resp2.status_code == 200:
                        # The callback page (HAR entry 17) has JS:
                        # window.location.href = "…lenovoIdSuccess.html?
                        #   code=…&scope=openid&state=…"
                        # We need ALL params (code, scope, state) for the
                        # token exchange — 'state' is mandatory.
                        redirect_match = re.search(
                            r'lenovoIdSuccess\.html\?([^"\']+)',
                            resp2.text,
                        )
                        if redirect_match:
                            return redirect_match.group(1)
                        # Also check for code in the final URL.
                        url_match = re.search(
                            r'[?&]code=([^&]+)', resp2.url,
                        )
                        if url_match:
                            return f"code={url_match.group(1)}"

            # ── Direct callback check (rare: full redirect chain) ────
            # Check if we landed directly on the callback page.
            redirect_match = re.search(
                r'lenovoIdSuccess\.html\?([^"\']+)', body,
            )
            if redirect_match:
                return redirect_match.group(1)

            # Check the final URL for code parameter.
            url_match = re.search(r'[?&]code=([^&]+)', resp.url)
            if url_match:
                return f"code={url_match.group(1)}"

            # ── Case B: Login form — cookies didn't work ─────────────
            if "preLogin" in resp.url or "Sign In" in body[:500]:
                log.debug("  Landed on login page — cookies not sufficient")
                return None

        except Exception as exc:
            log.debug("  OAuth chain error: %s", exc)
        return None

    def _passport_prelogin(self, oauth_url: str) -> bool:
        """Follow the redirect chain: authorize → gateway → preLogin.

        Uses browser-like headers matching HAR entries 7-9.
        """
        assert self.session is not None
        headers = {
            "User-Agent": _BROWSER_UA,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "es-US,es-419;q=0.9,es;q=0.8",
        }
        try:
            resp = self.session.get(
                oauth_url, headers=headers, timeout=30,
                allow_redirects=True,
            )
            return resp.status_code == 200
        except Exception as exc:
            log.debug("  preLogin redirect chain error: %s", exc)
            return False

    def _passport_login(self, username: str, password: str) -> bool:
        """``POST /glbwebauthnv6/userLogin`` (HAR entry 16).

        Sends form-encoded credentials.  The ``password`` parameter is
        the MD5 uppercase hex hash as sent by the LMSA client (HAR shows
        ``password=95D7203D10C54F63A97B51548FE91D43``).
        """
        assert self.session is not None

        realm = "lenovo.mbg.service.lmsa"
        realm_cookie = self.session.cookies.get(
            "lenovoid.realm", domain=f".{_PASSPORT_HOST}",
        )
        if realm_cookie:
            realm = realm_cookie

        form_data = {
            "lenovoid.action": "uilogin",
            "lenovoid.realm": realm,
            "lenovoid.ctx": "",
            "lenovoid.lang": "en_US",
            "lenovoid.uinfo": "null",
            "lenovoid.cb": (
                f"{_PASSPORT_BASE}/v1.0/utility/lenovoid/oauth2/callback"
            ),
            "lenovoid.vb": "null",
            "lenovoid.display": "null",
            "lenovoid.idp": "null",
            "lenovoid.source": "Software Fix",
            "lenovoid.sdk": "null",
            "lenovoid.prompt": "login",
            "lenovoid.hidesocial": "null",
            "crossRealmDomains": "null",
            "path": "/glbwebauthnv6",
            "areacode": "",
            "username": username,
            "password": password,
            "loginfinish": "1",
            "autoLoginState": "1",
        }

        headers = {
            "User-Agent": _BROWSER_UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": _PASSPORT_BASE,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        }

        try:
            resp = self.session.post(
                f"{_PASSPORT_BASE}/glbwebauthnv6/userLogin",
                data=form_data,
                headers=headers,
                timeout=30,
                allow_redirects=True,
            )
            return resp.status_code == 200
        except Exception as exc:
            log.debug("  userLogin error: %s", exc)
            return False

    def _get_auth_code_from_callback(self) -> str | None:
        """Follow the OAuth2 callback chain after login (HAR entry 17).

        After ``userLogin``, the session has the LPSWUST/LPSWUTGT cookies.
        We call the ``oauth2/callback`` endpoint which returns HTML with
        the auth code embedded in a JS redirect URL.

        Returns the full query string (``code=…&scope=…&state=…``) or None.
        """
        assert self.session is not None

        callback_url = (
            f"{_PASSPORT_BASE}/v1.0/utility/lenovoid/oauth2/callback"
        )
        headers = {
            "User-Agent": _BROWSER_UA,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
        }
        try:
            resp = self.session.get(
                callback_url, headers=headers, timeout=30,
                allow_redirects=True,
            )
            if resp.status_code != 200:
                return None

            # Extract full redirect URL params from HTML/JS.
            redirect_match = re.search(
                r'lenovoIdSuccess\.html\?([^"\']+)', resp.text,
            )
            if redirect_match:
                return redirect_match.group(1)

            # Check final URL too.
            code_match = re.search(r'[?&]code=([^&]+)', resp.url)
            if code_match:
                return f"code={code_match.group(1)}"
        except Exception as exc:
            log.debug("  auth code extraction error: %s", exc)
        return None

    def _exchange_code(self, redirect_qs: str) -> str | None:
        """Exchange the auth code for a Bearer token (HAR entry 21).

        ``GET /Interface/user/oauth2/callback.jhtml?code=…&scope=openid&state=…``
        → ``{"code":"0000","content":"softwareFix://callback?fullName=…
        &Authorization=<BEARER_TOKEN>"}``

        Parameters
        ----------
        redirect_qs:
            The full query string from the callback redirect URL, e.g.
            ``code=…&scope=openid&state=…``.  The ``state`` param is
            **required** by the server to match the original OAuth flow.
        """
        assert self.session is not None
        # Parse the query string to get code, scope, state.
        qs = urllib.parse.parse_qs(redirect_qs)
        params = {
            "code": qs.get("code", [""])[0],
            "scope": qs.get("scope", ["openid"])[0],
        }
        state = qs.get("state", [""])[0]
        if state:
            params["state"] = state

        headers = {
            "User-Agent": _BROWSER_UA,
            "Accept": "application/json, text/plain, */*",
            "Cache-Control": "no-cache",
        }
        try:
            resp = self.session.get(
                f"{_LSATEST_BASE}/Interface/user/oauth2/callback.jhtml",
                params=params,
                headers=headers,
                timeout=30,
            )
            data = _b64decode_json(resp.text)
            if data.get("code") != "0000":
                log.debug("  code exchange: code=%s desc=%s",
                          data.get("code"), data.get("desc"))
                return None

            content = data.get("content", "")
            # Parse: "softwareFix://callback?fullName=…&Authorization=TOKEN"
            match = re.search(r"Authorization=([^&]+)", content)
            if match:
                return match.group(1)
        except Exception as exc:
            log.debug("  code exchange error: %s", exc)
        return None

    # ── Catalog discovery ────────────────────────────────────────────

    def _api_headers(self) -> dict[str, str]:
        """Return LMSA headers with optional Bearer auth (HAR entries 22-33)."""
        headers = dict(_LMSA_HEADERS)
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers

    def _discover_models(self) -> list[dict[str, Any]]:
        """Fetch all device models (HAR entry 32).

        ``POST /Interface/rescueDevice/getModelNames.jhtml``
        Body: ``{"dparams":{"country":"Mexico","category":"Phone"}, …}``
        → ``{"code":"0000","content":{"models":[…]}}``

        Returns models with fields: ``category``, ``brand``, ``modelName``,
        ``marketName``, ``platform`` (MTK/Qcom/Samsung/Unisoc),
        ``readSupport``, ``readFlow``.
        """
        assert self.session is not None
        all_models: list[dict[str, Any]] = []
        seen: set[str] = set()

        for country in _COUNTRIES:
            for category in _CATEGORIES:
                body = _make_lmsa_body(
                    dparams={"country": country, "category": category},
                )
                try:
                    resp = self.session.post(
                        f"{_LSATEST_BASE}/Interface/rescueDevice/"
                        "getModelNames.jhtml",
                        json=body,
                        headers=self._api_headers(),
                        timeout=30,
                    )
                    data = _b64decode_json(resp.text)
                    if data.get("code") != "0000":
                        log.info(
                            "    getModelNames %s/%s → code=%s desc=%s",
                            country, category,
                            data.get("code"), data.get("desc"),
                        )
                        continue

                    content = data.get("content") or {}
                    models = content.get("models") or []
                    new_count = 0
                    for m in models:
                        key = m.get("modelName", "")
                        if key and key not in seen:
                            seen.add(key)
                            all_models.append(m)
                            new_count += 1

                    log.info(
                        "    getModelNames %s/%s → %d models (%d new)",
                        country, category, len(models), new_count,
                    )
                except Exception as exc:
                    log.info(
                        "    getModelNames %s/%s error: %s",
                        country, category, exc,
                    )

                time.sleep(_REQUEST_DELAY)

        return all_models

    def _get_resources(
        self, model_name: str, market_name: str,
    ) -> list[dict[str, Any]]:
        """``POST getResource`` for a single model (HAR entry 33).

        Body: ``{"dparams":{"modelName":"XT2523-2","marketName":"Moto g05 5G"}, …}``
        → ``{"code":"0000","content":[{…, "romResource":{…},
        "toolResource":{…}, "flashFlow":"https://rsdsecure-test…", …}]}``

        Each resource in the ``content`` list contains:
        - ``brand``, ``category``, ``modelName``, ``realModelName``
        - ``platform`` (MTK, Qcom, Samsung, Unisoc)
        - ``fingerPrint`` (Android build fingerprint)
        - ``romResource`` — ROM image (``uri``, ``name``, ``type``,
          ``publishDate``, ``fromS3``, ``unZip``, ``md5``)
        - ``toolResource`` — flash tool (same fields)
        - ``flashFlow`` — JSON config URL (string, not object)
        - ``otaResource`` — OTA update (optional)
        - ``romMatchId`` — match identifier
        - ``marketName`` — human-readable device name
        """
        assert self.session is not None
        body = _make_lmsa_body(
            dparams={"modelName": model_name, "marketName": market_name},
        )
        try:
            resp = self.session.post(
                f"{_LSATEST_BASE}/Interface/rescueDevice/getResource.jhtml",
                json=body,
                headers=self._api_headers(),
                timeout=30,
            )
            data = _b64decode_json(resp.text)
            if data.get("code") != "0000":
                log.debug(
                    "    getResource %s → code=%s desc=%s",
                    model_name, data.get("code"), data.get("desc"),
                )
                return []

            return data.get("content") or []
        except Exception as exc:
            log.debug("    getResource %s error: %s", model_name, exc)
            return []

    # ── File-entry extraction ────────────────────────────────────────

    @staticmethod
    def _extract_file_entries(
        resource: dict[str, Any],
        category: str,
    ) -> list[FileEntry]:
        """Convert a resource API object into ``FileEntry`` dicts.

        Each resource may contain up to four downloadable items:

        - ``romResource`` — ROM firmware image (from S3, 5+ GB).
          Response headers: ``Content-Type: application/octet-stream``,
          ``x-amz-meta-sha256``, ``x-amz-meta-s3b-last-modified``,
          ``x-amz-storage-class: INTELLIGENT_TIERING``.
        - ``toolResource`` — Flash tool ZIP (~34 MB).
          ``x-amz-storage-class: GLACIER_IR``.
        - ``flashFlow`` — Flash-flow JSON config (plain URL string).
        - ``otaResource`` — OTA update (optional).

        All URLs are S3 pre-signed (``X-Amz-Algorithm=AWS4-HMAC-SHA256``,
        ``X-Amz-Expires=604800`` = 7 days).  Files are NOT downloaded
        (ROM images exceed 5 GB) — only metadata is recorded.
        """
        entries: list[FileEntry] = []
        brand = resource.get("brand", "")
        model_name = resource.get("modelName", "")
        market_name = resource.get("marketName", "")
        platform = resource.get("platform", "")
        fingerprint = resource.get("fingerPrint", "")
        product_label = f"{brand} {market_name or model_name}".strip()

        def _clean_url(url: str) -> str:
            """Strip S3 query-string for a clean display name."""
            return url.split("?")[0] if url else url

        # ── ROM resource (HAR entry 34: 5,727,295,273 bytes) ─────────
        rom = resource.get("romResource")
        if rom and rom.get("uri"):
            entries.append(FileEntry(
                name=rom.get("name", ""),
                url=rom["uri"],
                category=f"{category}/ROM",
                os=fingerprint,
                version=rom.get("name", ""),
                release_date=rom.get("publishDate", ""),
                description=(
                    f"ROM image for {product_label} ({platform})"
                    f" [fromS3={rom.get('fromS3')}"
                    f", unZip={rom.get('unZip')}]"
                ),
                product=product_label,
                source=(
                    f"getResource → romResource "
                    f"[{_clean_url(rom['uri'])}]"
                ),
            ))

        # ── Tool resource (HAR entry 36: 34,378,109 bytes) ──────────
        tool = resource.get("toolResource")
        if tool and tool.get("uri"):
            entries.append(FileEntry(
                name=tool.get("name", ""),
                url=tool["uri"],
                category=f"{category}/Tool",
                version=tool.get("name", ""),
                release_date=tool.get("publishDate", ""),
                description=(
                    f"Flash tool for {product_label} ({platform})"
                    f" [id={tool.get('id')}"
                    f", fromS3={tool.get('fromS3')}]"
                ),
                product=product_label,
                source=(
                    f"getResource → toolResource "
                    f"[{_clean_url(tool['uri'])}]"
                ),
            ))

        # ── Flash-flow JSON config ───────────────────────────────────
        flash_flow = resource.get("flashFlow")
        if flash_flow:
            ff_name = urllib.parse.urlparse(flash_flow).path.rsplit("/", 1)[-1]
            entries.append(FileEntry(
                name=ff_name,
                url=flash_flow,
                category=f"{category}/FlashFlow",
                description=(
                    f"Flash-flow config for {product_label} ({platform})"
                ),
                product=product_label,
                source=(
                    f"getResource → flashFlow "
                    f"[{_clean_url(flash_flow)}]"
                ),
            ))

        # ── OTA resource (not present in HAR sample) ─────────────────
        ota = resource.get("otaResource")
        if ota and ota.get("uri"):
            entries.append(FileEntry(
                name=ota.get("name", ""),
                url=ota["uri"],
                category=f"{category}/OTA",
                version=ota.get("name", ""),
                release_date=ota.get("publishDate", ""),
                description=(
                    f"OTA update for {product_label} ({platform})"
                ),
                product=product_label,
                source=(
                    f"getResource → otaResource "
                    f"[{_clean_url(ota['uri'])}]"
                ),
            ))

        return entries
