"""
LMSA (Lenovo Moto Smart Assistant) authentication and firmware-download client.

Reverse-engineered from LMSA .NET assemblies and confirmed against live HAR
traffic capture (HTTPToolkit, 2026-03-03):
  - Software Fix.exe
  - lenovo.mbg.service.common.webservices.dll
  - lenovo.mbg.service.framework.download.dll
  - lenovo.mbg.service.lmsa.flash.dll

Authentication flow
-------------------
1. POST /user/lenovoIdLogin.jhtml (WUST + GUID, author: false)
      → JWT token in ``Authorization`` response header when ``Guid`` header
        matches the request GUID.  Token rotates on every subsequent call.
2. POST /rescueDevice/getResource.jhtml  → firmware metadata + pre-signed S3 URL
3. GET  <pre-signed S3 URL>              → firmware binary on
                                           rsddownload-secure.lenovo.com

Configuration confirmed from HAR traffic (LMSA 7.5.4.2):

    BASE_URL        = "https://lsa.lenovo.com"
    CLIENT_VERSION  = "7.5.4.2"
    AES_KEY         = "jdkei3ffkjijut46#$%6y7U8km4p<mdT"  (from exe.config)
    AES_IV          = "52,*u^yhNjk<./O0"                   (from exe.config)
    DEFAULT_PASSWORD= "OSD"

HTTP headers confirmed from HAR (replaces earlier decompile analysis):

    User-Agent    : Mozilla/5.0 (Windows NT 6.3; WOW64) ...Chrome/51...
    Content-Type  : application/json
    Cache-Control : no-store,no-cache
    Pragma        : no-cache
    Request-Tag   : lmsa
    clientVersion : 7.5.4.2          (separate header, also in body)
    guid          : <UUID>            (authenticated requests)
    Authorization : Bearer <JWT>      (rotates per response)
    Connection    : Close             (KeepAlive = false per source)

Note: ``ConnectionField`` and ``Accept`` headers are NOT sent by the actual
LMSA app (confirmed by HAR — they were present in older decompile analysis
but absent from all live authenticated traffic).
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from typing import Any, Optional
from urllib.parse import urljoin

import requests

# ---------------------------------------------------------------------------
# Attempt to import pycryptodome.  The library is optional – without it the
# RSA-encrypt step (needed for token initialisation) is skipped, but the rest
# of the API (e.g. anonymous firmware queries) still works.
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad, unpad
    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants extracted from decompiled assemblies
# ---------------------------------------------------------------------------

#: Production API server — the LMSA webapp is deployed under ``/Interface/``.
#: Confirmed live by curl: /Interface/common/rsa.jhtml → 200, code 0000.
LMSA_BASE_URL = "https://lsa.lenovo.com/Interface"

#: LMSA desktop application version.
#: Confirmed from live HAR traffic capture (LMSA 7.5.4.2, 2026-03-03).
CLIENT_VERSION = "7.5.4.2"

# AES-128-CBC parameters from ``Software Fix.exe.config``.
AES_KEY: bytes = b"jdkei3ffkjijut46#$%6y7U8km4p<mdT"[:16]   # first 16 bytes → AES-128
AES_IV: bytes  = b"52,*u^yhNjk<./O0"

#: Password used to decrypt ROM archives (``OSD`` constant in flash DLL).
ROM_PASSWORD = "OSD"

# User-Agent used by HttpDownload.OpenRequest() for actual S3 file downloads.
# Source: GlobalVar.UserAgent in lenovo.mbg.service.common.utilities.dll:
#   public static string UserAgent =
#       "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0;
#        SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729;
#        Media Center PC 6.0; .NET4.0C; .NET4.0E)";
# The download request uses only this UA + KeepAlive=false; no extra headers.
DOWNLOAD_USER_AGENT = (
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; "
    "SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; "
    "Media Center PC 6.0; .NET4.0C; .NET4.0E)"
)

# ---------------------------------------------------------------------------
# Endpoint paths (from ``WebApiUrl.cs`` and ``WebServicesContext.cs``, both
# confirmed against live HAR and decompiled LMSA 7.5.4.2 assemblies)
# ---------------------------------------------------------------------------
_EP_RSA_KEY             = "/common/rsa.jhtml"
_EP_INIT_TOKEN          = "/client/initToken.jhtml"
_EP_DELETE_TOKEN        = "/client/deleteToken.jhtml"
_EP_RENEW_LINK          = "/client/renewFileLink.jhtml"
_EP_GET_RESOURCE        = "/rescueDevice/getNewResource.jhtml"   # auto-match by hw params
_EP_GET_RESOURCE_BY_IMEI= "/rescueDevice/getNewResourceByImei.jhtml"
_EP_GET_RESOURCE_BY_SN  = "/rescueDevice/getNewResourceBySN.jhtml"
_EP_GET_MODEL_NAMES     = "/rescueDevice/getModelNames.jhtml"    # all models
_EP_GET_MARKET_NAMES    = "/rescueDevice/getRescueModelNames.jhtml"  # rescue-only
_EP_GET_RESOURCE_V2     = "/rescueDevice/getResource.jhtml"      # manual match
_EP_GET_RECIPE          = "/rescueDevice/getRescueModelRecipe.jhtml"
_EP_ROM_LIST            = "/priv/getRomList.jhtml"               # full ROM catalogue
_EP_ROM_MATCH_PARAMS    = "/rescueDevice/getRomMatchParams.jhtml"

# All categories and regions known to be used by LMSA (from HAR + decompile).
# getModelNames returns both Phone and Tablet. Each response also contains a
# ``moreModels`` list with additional/legacy models.
_FIRMWARE_CATEGORIES = ("Phone", "Tablet")
_FIRMWARE_COUNTRIES  = (
    "Mexico", "US", "Brazil", "Argentina", "Colombia", "Chile",
    "Peru", "Ecuador", "Guatemala", "Paraguay", "Dominican Republic",
    "India", "Germany", "UK", "France", "Italy", "Spain", "Australia",
    "Canada", "Japan", "China",
)

# Maximum recursion depth for _resolve_resource() paramProperty chains.
# The deepest observed chain is 3 steps (simCount → country → resolved).
_MAX_RESOLVE_DEPTH = 4

# Hosts whose firmware URLs are publicly accessible (no presigning needed).
# Confirmed by live HEAD request: HTTP 200 without any auth headers.
_PUBLIC_FIRMWARE_HOSTS = frozenset({
    "download.lenovo.com",
})

# ---------------------------------------------------------------------------
# HTTP headers confirmed from live HAR traffic capture (LMSA 7.5.4.2)
# ---------------------------------------------------------------------------
_BASE_HEADERS: dict[str, str] = {
    "User-Agent": (
        # Confirmed from WebApiHttpRequest.cs and HAR traffic:
        # httpWebRequest.UserAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64) ...Chrome/51..."
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
    ),
    "Content-Type":  "application/json",
    # Confirmed from HAR: "Cache-Control: no-store,no-cache" (not just no-cache)
    "Cache-Control": "no-store,no-cache",
    # Confirmed from HAR: Pragma header is always present
    "Pragma":        "no-cache",
    "Request-Tag":   "lmsa",
    # Confirmed from HAR: clientVersion is sent as a separate request header
    # in addition to being in the request body's client.version field.
    "clientVersion": CLIENT_VERSION,
    "Connection":    "Close",   # KeepAlive = false in source; HAR shows "Close"
    # Note: "ConnectionField" and "Accept" headers are NOT sent by the actual
    # LMSA app — confirmed absent in all HAR-captured authenticated requests.
}

# Standard API response code for success.
_CODE_OK = "0000"


# ---------------------------------------------------------------------------
# RSA helpers
# ---------------------------------------------------------------------------

def _parse_rsa_key(key_b64: str) -> Optional[RSA.RsaKey]:
    """Parse the server-returned RSA public key.

    The LMSA server returns a PKCS#8 SubjectPublicKeyInfo key encoded as
    Base64 (confirmed by decompiling ``lenovo.mbg.service.common.webservices.dll``
    and calling ``RSAPublicKeyJava2DotNet`` on it).  The key arrives in the
    JSON ``desc`` field, e.g.::

        {"code": "0000", "desc": "MIGfMA0GCSqGSIb3DQEBAQUAA4GN…"}

    Returns ``None`` when *pycryptodome* is not installed or parsing fails.
    """
    if not _CRYPTO_AVAILABLE:
        return None
    try:
        key_der = base64.b64decode(key_b64.strip())
        return RSA.import_key(key_der)
    except Exception:
        return None


def rsa_encrypt_guid(guid_str: str, rsa_key: RSA.RsaKey) -> str:
    """Encrypt *guid_str* with PKCS#1 v1.5 and return a Base64 string.

    This matches the ``EncryptGuid`` method in the LMSA .NET source.
    """
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(guid_str.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


# ---------------------------------------------------------------------------
# AES helpers
# ---------------------------------------------------------------------------

def aes_decrypt(ciphertext_b64: str) -> str:
    """AES-128-CBC decrypt a Base64-encoded ciphertext using the extracted key.

    Used to decrypt ROM file download links and firmware metadata returned by
    ``getNewResource.jhtml``.
    """
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "pycryptodome is required for AES decryption: pip install pycryptodome"
        )
    raw = base64.b64decode(ciphertext_b64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return unpad(cipher.decrypt(raw), AES.block_size).decode("utf-8")


def aes_encrypt(plaintext: str) -> str:
    """AES-128-CBC encrypt *plaintext* and return a Base64 string."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "pycryptodome is required for AES encryption: pip install pycryptodome"
        )
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return base64.b64encode(
        cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    ).decode("ascii")


# ---------------------------------------------------------------------------
# Main session class
# ---------------------------------------------------------------------------

class LMSASession:
    """LMSA API session manager.

    Handles authentication and firmware-download queries against the LMSA
    production API (``https://lsa.lenovo.com``).

    Typical usage::

        session = LMSASession()
        if session.authenticate():
            info = session.get_firmware(model_name="xt2553-2", region="US")
            urls = session.get_download_urls(info)

    Parameters
    ----------
    base_url:
        Override the production API base URL (useful for testing against
        ``lsatest.lenovo.com``).
    guid:
        Device GUID.  A random UUID is generated when omitted.
    language:
        BCP-47 language tag sent in every request model (default ``en-US``).
    windows_info:
        ``windowsInfo`` string sent in every request model.
    verify_ssl:
        Pass ``False`` to disable TLS verification (not recommended).
    """

    def __init__(
        self,
        base_url: str = LMSA_BASE_URL,
        guid: Optional[str] = None,
        language: str = "en-US",
        windows_info: str = "Microsoft Windows 11 Pro, x64-based PC",
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.guid = guid or str(uuid.uuid4()).lower()
        self.language = language
        self.windows_info = windows_info
        self._verify_ssl = verify_ssl

        self._jwt_token: Optional[str] = None
        self._rsa_key: Optional[Any] = None   # RSA.RsaKey when crypto available

        self._session = requests.Session()
        self._session.headers.update(_BASE_HEADERS)
        self._session.verify = verify_ssl

    @classmethod
    def from_jwt(
        cls,
        jwt: str,
        guid: str,
        base_url: str = LMSA_BASE_URL,
        verify_ssl: bool = True,
    ) -> "LMSASession":
        """Create an already-authenticated session from a known JWT and GUID.

        Use this when you have captured a live token from a HAR / proxy
        capture and want to skip the OAuth login step entirely.

        Parameters
        ----------
        jwt:
            The ``Authorization`` header value (without the ``Bearer `` prefix)
            from a recent LMSA API response.  The token is valid for the
            current session GUID and rotates on every API call.
        guid:
            The device GUID that was used to obtain *jwt*.  Must match what
            the server has on record; using a different GUID yields 403.
        base_url:
            Override the production API base URL.
        verify_ssl:
            Pass ``False`` to disable TLS certificate verification.

        Example::

            # Extracted from HTTPToolkit HAR capture:
            session = LMSASession.from_jwt(
                jwt="Ek6TINIruEV6jLTn…",
                guid="98e2895b-2e0a-4830-b5fe-eab0ab2c3f84",
            )
        """
        sess = cls(base_url=base_url, guid=guid, verify_ssl=verify_ssl)
        # Strip "Bearer " prefix if present so we store only the raw token.
        sess._jwt_token = jwt.removeprefix("Bearer ").strip()
        sess._session.headers["Authorization"] = f"Bearer {sess._jwt_token}"
        sess._session.headers["guid"] = guid
        return sess

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, endpoint: str) -> str:
        return self.base_url + endpoint

    def _build_request_model(self, params: dict[str, Any]) -> dict[str, Any]:
        """Wrap *params* in the LMSA ``RequestModel`` envelope.

        All caller-supplied fields go under ``dparams``; authentication
        credentials (``guid``, JWT) are injected automatically.
        """
        dparams: dict[str, Any] = dict(params)
        dparams.setdefault("guid", self.guid)

        return {
            "client":      {"version": CLIENT_VERSION},
            "language":    self.language,
            "windowsInfo": self.windows_info,
            "dparams":     dparams,
        }

    def _request_headers(self, *, author: bool = True) -> dict[str, str]:
        """Return per-request headers.

        Parameters
        ----------
        author:
            When ``True`` (default) include the ``guid`` and ``Authorization``
            headers, matching ``addAuthorizationHeader=true`` in the source.
            Set to ``False`` for calls that use ``author: false`` (e.g.
            ``lenovoIdLogin.jhtml`` per ``ApiBaseService.RequestBase`` line 1204).
        """
        if not author:
            return {}
        hdrs: dict[str, str] = {"guid": self.guid}
        if self._jwt_token:
            hdrs["Authorization"] = f"Bearer {self._jwt_token}"
        return hdrs

    def _post(
        self,
        endpoint: str,
        params: dict[str, Any],
        *,
        author: bool = True,
    ) -> Optional[dict[str, Any]]:
        """POST a RequestModel to *endpoint* and return the parsed JSON body.

        Parameters
        ----------
        author:
            Passed to :meth:`_request_headers`.  Use ``False`` for endpoints
            that explicitly set ``author: false`` in the C# source (e.g.
            ``lenovoIdLogin.jhtml``).
        """
        body = self._build_request_model(params)
        try:
            resp = self._session.post(
                self._url(endpoint),
                json=body,
                headers=self._request_headers(author=author),
                timeout=30,
            )
        except requests.RequestException as exc:
            _log(f"[LMSA] POST {endpoint} failed: {exc}")
            return None

        # Extract JWT from response headers when the server echoes our GUID back.
        # From RequestBase in WebApiHttpRequest.cs:
        #   if (response.GetResponseHeader("Guid") == WebApiContext.GUID
        #       && !string.IsNullOrEmpty(response.GetResponseHeader("Authorization")))
        #       WebApiContext.JWT_TOKEN = response.GetResponseHeader("Authorization");
        guid_hdr = resp.headers.get("Guid", "")
        auth_hdr = resp.headers.get("Authorization", "")
        if guid_hdr == self.guid and auth_hdr and auth_hdr != self._jwt_token:
            self._jwt_token = auth_hdr
            _log_debug(f"[LMSA] JWT token updated from {endpoint} response")

        if resp.status_code != 200:
            _log(f"[LMSA] POST {endpoint} → HTTP {resp.status_code}: {resp.text[:200]}")
            return None

        try:
            return resp.json()
        except ValueError:
            _log(f"[LMSA] POST {endpoint} → non-JSON response: {resp.text[:200]}")
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_rsa_public_key(self) -> Optional[str]:
        """Fetch the server's RSA public key.

        Confirmed by decompiling ``lenovo.mbg.service.common.webservices.dll``:
        - Endpoint requires HTTP POST (not GET).
        - Response JSON: ``{"code": "0000", "desc": "<PKCS8-base64>"}``
          The key is in ``desc``, **not** ``data``.
        - Key format: PKCS#8 SubjectPublicKeyInfo, Base64-encoded.

        Returns the raw Base64 string on success, ``None`` on failure.
        Caches the parsed key internally for :meth:`authenticate`.
        """
        # The endpoint requires POST with an empty RequestModel body.
        data = self._post(_EP_RSA_KEY, {})
        if data is None:
            return None

        if data.get("code") != _CODE_OK:
            _log(f"[LMSA] RSA key error code: {data.get('code')} "
                 f"desc: {data.get('desc', '')}")
            return None

        # Key is in the ``desc`` field as PKCS#8 Base64 (Java format).
        key_b64: str = data.get("desc", "")
        if not key_b64:
            _log("[LMSA] RSA key response missing 'desc' field")
            return None

        if _CRYPTO_AVAILABLE:
            self._rsa_key = _parse_rsa_key(key_b64)
            if self._rsa_key is None:
                _log("[LMSA] Warning: RSA public key could not be parsed")

        return key_b64

    def authenticate(self) -> bool:
        """Full anonymous auth flow: fetch RSA key → encrypt GUID → init token.

        Returns ``True`` when a JWT token is successfully obtained.
        Requires *pycryptodome* (``pip install pycryptodome``).

        Note: For Lenovo ID (user) authentication, use
        :class:`~web_crawler.auth.lenovo_id.LenovoIDAuth` instead.
        """
        if not _CRYPTO_AVAILABLE:
            _log(
                "[LMSA] pycryptodome not installed – cannot perform RSA "
                "encryption for token init.  Install with: pip install pycryptodome"
            )
            return False

        _log("[LMSA] Fetching RSA public key …")
        key_b64 = self.get_rsa_public_key()
        if key_b64 is None:
            return False
        if self._rsa_key is None:
            _log("[LMSA] RSA key parse failed – cannot encrypt GUID")
            return False

        _log(f"[LMSA] Encrypting GUID {self.guid} …")
        try:
            encrypted_guid = rsa_encrypt_guid(self.guid, self._rsa_key)
        except Exception as exc:
            _log(f"[LMSA] RSA encryption failed: {exc}")
            return False

        _log("[LMSA] Initialising session token …")
        data = self._post(_EP_INIT_TOKEN, {"guid": encrypted_guid})
        if data is None:
            return False

        if data.get("code") != _CODE_OK:
            _log(f"[LMSA] initToken error: {data.get('code')} – {data.get('desc', '')}")
            return False

        # JWT arrives in the response Authorization header when the server
        # echoes back the client GUID in the Guid response header.
        # (From RequestBase in WebApiHttpRequest.cs decompiled source.)
        token = self._jwt_token   # populated by _post() from Authorization header
        if token:
            self._session.headers["Authorization"] = f"Bearer {token}"
            _log("[LMSA] ✓ Token initialised successfully")
            return True

        _log("[LMSA] Warning: initToken succeeded but no JWT in response headers")
        return True

    def get_firmware(
        self,
        model_name: str,
        region: str = "",
        market: str = "",
        carrier: str = "",
        flash_tool_type: str = "QComFlashTool",
        android_version: str = "",
        build_type: str = "user",
    ) -> Optional[dict[str, Any]]:
        """Query available firmware for a device.

        Parameters
        ----------
        model_name:
            Motorola model number, e.g. ``"xt2553-2"``.
        region:
            Geographic region, e.g. ``"US"``, ``"RETUS"``, ``"RETBR"``.
        carrier:
            Carrier variant, e.g. ``"Unlocked"``, ``"Verizon"``.
        flash_tool_type:
            Flash tool identifier.  MediaTek: ``MTekFlashTool``,
            ``MTekSpFlashTool``.  Qualcomm: ``QComFlashTool``,
            ``QFileTool``.  Generic: ``PnPTool``.

        Returns the raw API response dict on success, ``None`` on failure.
        """
        params: dict[str, Any] = {
            "modelName":     model_name,
            "flashToolType": flash_tool_type,
            "buildType":     build_type,
        }
        if region:
            params["region"] = region
        if market:
            params["market"] = market
        if carrier:
            params["carrier"] = carrier
        if android_version:
            params["androidVersion"] = android_version

        _log(f"[LMSA] Querying firmware for {model_name} …")
        data = self._post(_EP_GET_RESOURCE, params)
        if data is None:
            return None

        code = data.get("code", "")
        if code == "403":
            _log("[LMSA] Firmware query blocked – token required.  Call authenticate() first.")
            return None
        if code != _CODE_OK:
            _log(f"[LMSA] Firmware query error: {code} – {data.get('msg', '')}")
            return None

        return data

    def get_rom_list(
        self,
        model_name: str,
        region: str = "",
        carrier: str = "",
    ) -> Optional[dict[str, Any]]:
        """Fetch the full ROM list for a device (``/priv/getRomList.jhtml``)."""
        params: dict[str, Any] = {"modelName": model_name}
        if region:
            params["region"] = region
        if carrier:
            params["carrier"] = carrier

        _log(f"[LMSA] Fetching ROM list for {model_name} …")
        data = self._post(_EP_ROM_LIST, params)
        if data is None:
            return None
        if data.get("code") != _CODE_OK:
            _log(f"[LMSA] ROM list error: {data.get('code')} – {data.get('msg', '')}")
            return None
        return data

    def get_download_urls(
        self, firmware_response: dict[str, Any]
    ) -> list[str]:
        """Extract download URLs from a ``get_firmware`` response.

        The server returns AES-encrypted URLs when the ``data`` field is a
        string (ciphertext).  Decryption uses the extracted AES key/IV.

        Returns a list of plain-text download URLs.
        """
        urls: list[str] = []
        data = firmware_response.get("data")
        if not data:
            return urls

        # Data may be a ciphertext string → decrypt first
        if isinstance(data, str):
            try:
                data = json.loads(aes_decrypt(data))
            except Exception as exc:
                _log(f"[LMSA] AES decrypt failed: {exc}")
                return urls

        # data is now a dict or list of download items
        items = data if isinstance(data, list) else [data]
        url_re = re.compile(r"https?://\S+")
        for item in items:
            if isinstance(item, dict):
                for key in ("downloadUrl", "url", "fileUrl", "link"):
                    val = item.get(key, "")
                    if val:
                        urls.append(val)
            elif isinstance(item, str) and url_re.match(item):
                urls.append(item)

        return urls

    def renew_download_link(self, file_id: str) -> Optional[str]:
        """Renew an expired download link (``/client/renewFileLink.jhtml``)."""
        data = self._post(_EP_RENEW_LINK, {"fileId": file_id})
        if data is None or data.get("code") != _CODE_OK:
            return None
        result = data.get("data")
        return result if isinstance(result, str) else None

    def get_model_names(
        self, country: str = "Mexico", category: str = "Phone"
    ) -> list[dict[str, Any]]:
        """Return the list of supported device models for *country*.

        Corresponds to ``rescueDevice/getModelNames.jhtml`` — confirmed from
        HAR: ``dparams: {country, category}`` → ``content.models``.

        The API response also contains a ``moreModels`` key with additional
        legacy/regional models not shown in the main list.  Both lists are
        combined and deduplicated by ``modelName``.
        """
        data = self._post(
            _EP_GET_MODEL_NAMES,
            {"country": country, "category": category},
        )
        if data is None or data.get("code") != _CODE_OK:
            return []
        content = data.get("content") or {}
        if not isinstance(content, dict):
            return []
        models: list[dict[str, Any]] = list(content.get("models") or [])
        more:   list[dict[str, Any]] = list(content.get("moreModels") or [])
        # Combine and deduplicate by modelName, preserving main-list priority.
        seen: set[str] = {m.get("modelName", "") for m in models}
        for m in more:
            name = m.get("modelName", "")
            if name and name not in seen:
                seen.add(name)
                models.append(m)
        return models

    def get_resource(
        self, model_name: str, market_name: str, **extra_params: str
    ) -> list[dict[str, Any]]:
        """Return firmware resources for a specific device model.

        Calls ``rescueDevice/getResource.jhtml``.  The API may respond with
        a list of items that have ``paramProperty`` (requiring additional
        params) or fully-resolved items with ``romResource`` / ``toolResource``
        pre-signed S3 URLs.  Extra key=value pairs (e.g. ``simCount``,
        ``country``) can be passed as keyword arguments.
        """
        params: dict[str, Any] = {
            "modelName":  model_name,
            "marketName": market_name,
        }
        params.update(extra_params)
        data = self._post(_EP_GET_RESOURCE_V2, params)
        if data is None or data.get("code") != _CODE_OK:
            return []
        content = data.get("content")
        if isinstance(content, list):
            return content
        return []

    def _resolve_resource(
        self,
        model_name: str,
        market_name: str,
        depth: int = 0,
        **params: str,
    ) -> list[dict[str, Any]]:
        """Recursively resolve paramProperty selections until we get S3 URLs."""
        if depth > _MAX_RESOLVE_DEPTH:  # guard against infinite loops
            return []
        items = self.get_resource(model_name, market_name, **params)
        resolved = []
        for item in items:
            if item.get("romResource") or item.get("toolResource") or item.get("flashFlow"):
                # Fully resolved — has download URLs
                resolved.append(item)
            elif item.get("paramProperty") and item.get("paramValues"):
                # Need to pick one param value — use first available
                prop = item["paramProperty"].get("property", "")
                values = item["paramValues"]
                if prop and values:
                    for val in values:
                        sub = self._resolve_resource(
                            model_name, market_name,
                            depth=depth + 1,
                            **params,
                            **{prop: val},
                        )
                        resolved.extend(sub)
        return resolved

    def get_all_roms(self) -> list[dict[str, Any]]:
        """Return the complete LMSA ROM catalogue via ``/priv/getRomList.jhtml``.

        This endpoint returns **all** firmware files known to the LMSA service
        in a single API call (2 299 items as of 2026-03-04), including entries
        on multiple storage hosts:

        - ``download.lenovo.com`` — **publicly accessible** (no auth needed).
          Confirmed: HTTP 200 without any signed headers.
        - ``rsddownload-secure.lenovo.com`` — Lenovo S3, requires AWS
          pre-signed URL obtained via :meth:`get_resource`.  Base URLs from
          this list return HTTP 403 without signing.
        - ``moto-rsd-prod-secure.s3.us-east-1.amazonaws.com`` — Motorola S3,
          requires separate Motorola API presigning (not available via LMSA).
        - ``rsdsecure-cloud.motorola.com`` — hostname does not resolve on the
          public internet (internal Motorola network only).

        Each returned dict has at minimum:
            ``name``  — original filename (without path)
            ``uri``   — download URL (may lack ``https://`` scheme for some legacy entries)
            ``type``  — 0 = ROM, 1 = Tool
            ``md5``   — MD5 hex digest (empty string when not available)

        Returns a list of normalised resource dicts with the ``uri`` field
        always carrying a full ``https://`` URL.
        """
        data = self._post(_EP_ROM_LIST, {})
        if data is None or data.get("code") != _CODE_OK:
            _log(f"[LMSA] getRomList failed: {data}")
            return []
        roms = data.get("content") or []
        if not isinstance(roms, list):
            return []

        # Normalise scheme-less URIs (a subset of entries omit "https://")
        normalised: list[dict[str, Any]] = []
        for item in roms:
            uri = item.get("uri", "") or ""
            if uri and not uri.startswith(("http://", "https://")):
                item = dict(item)
                item["uri"] = "https://" + uri.lstrip("/")
            normalised.append(item)

        _log(f"[LMSA] getRomList: {len(normalised)} ROM entries")
        return normalised

    def scan_all_firmware(
        self,
        countries: tuple[str, ...] = _FIRMWARE_COUNTRIES,
        categories: tuple[str, ...] = _FIRMWARE_CATEGORIES,
    ) -> list[dict[str, Any]]:
        """Scan the LMSA API for all available firmware download URLs.

        Two complementary strategies are combined:

        **1. Full ROM catalogue** (``/priv/getRomList.jhtml``):
           Returns all ~2 299 ROM file entries in a single API call.
           Entries on ``download.lenovo.com`` are publicly accessible and
           included directly.  S3 entries (``rsddownload-secure.lenovo.com``,
           Motorola S3) are included as *base* (unsigned) URLs — the crawler
           will attempt HEAD requests and skip 403s automatically.

        **2. Per-model pre-signed scan** (``/rescueDevice/getResource.jhtml``):
           Iterates over every supported model in every requested country and
           resolves any multi-step ``paramProperty`` selections until AWS
           pre-signed S3 URLs are returned.  Each pre-signed URL is valid for
           7 days (``X-Amz-Expires=604800``).

        Returns a flat list of resource dicts, each containing at minimum one
        of ``romResource``, ``toolResource``, ``flashFlow``, or a ``_rom_uri``
        key (for raw entries from the full catalogue).  Each dict is augmented
        with ``_country`` and ``_category`` keys for traceability.

        This method makes many authenticated API calls — expect it to take
        several minutes for a full scan (281+ models × 20+ countries).
        Use ``countries=("Mexico",)`` for a fast single-region scan.
        """
        all_resources: list[dict[str, Any]] = []

        # --- Strategy 1: full ROM catalogue ---
        roms = self.get_all_roms()
        for rom in roms:
            all_resources.append({
                "_rom_uri":    rom.get("uri", ""),
                "_rom_name":   rom.get("name", ""),
                "_rom_md5":    rom.get("md5", ""),
                "_rom_type":   rom.get("type", 0),
                "_country":    "",
                "_category":   "",
            })

        # --- Strategy 2: per-model presigned scan ---
        seen_models: set[str] = set()
        presigned: list[dict[str, Any]] = []

        for country in countries:
            for category in categories:
                models = self.get_model_names(country=country, category=category)
                _log(
                    f"[LMSA] {country}/{category}: {len(models)} models"
                )
                for m in models:
                    model_name  = m.get("modelName", "")
                    market_name = m.get("marketName", "")
                    key = f"{model_name}|{country}"
                    if key in seen_models or not model_name:
                        continue
                    seen_models.add(key)

                    items = self._resolve_resource(
                        model_name, market_name, country=country
                    )
                    for item in items:
                        item["_country"]  = country
                        item["_category"] = category
                    presigned.extend(items)
                    if items:
                        _log(
                            f"[LMSA]   {model_name} ({market_name}): "
                            f"{len(items)} resource(s)"
                        )

        all_resources.extend(presigned)
        _log(
            f"[LMSA] scan_all_firmware complete: "
            f"{len(roms)} catalogue entries + "
            f"{len(presigned)} presigned resources "
            f"({len(seen_models)} unique model/country pairs)"
        )
        return all_resources

    def collect_download_urls(
        self,
        resources: list[dict[str, Any]],
    ) -> list[tuple[str, str]]:
        """Extract all pre-signed S3 download URLs from *resources*.

        Returns a list of ``(url, filename)`` tuples for every
        ``romResource``, ``toolResource``, ``flashFlow``, ``otaResource``, and
        ``countryCodeResource`` found in the list returned by
        :meth:`scan_all_firmware`.

        Engineering / debug builds are included — callers can identify them by
        filename patterns such as ``_userdebug_``, ``_eng_``, ``_test-keys``.
        """
        urls: list[tuple[str, str]] = []
        seen: set[str] = set()

        def _add(url_val: Any, default_name: str) -> None:
            if not url_val or not isinstance(url_val, str):
                return
            # Normalise protocol-relative or scheme-less URLs.
            if url_val.startswith("//"):
                url_val = "https:" + url_val
            elif not url_val.startswith(("http://", "https://")):
                url_val = "https://" + url_val
            # Strip query string for dedup (different signed tokens, same file)
            base = url_val.split("?")[0]
            if base in seen:
                return
            seen.add(base)
            name = base.rstrip("/").rsplit("/", 1)[-1] or default_name
            urls.append((url_val, name))

        for item in resources:
            # Raw getRomList catalogue entries use _rom_uri/_rom_name.
            if item.get("_rom_uri"):
                _add(item["_rom_uri"], item.get("_rom_name") or "unknown.zip")
                continue
            # Resolved getResource entries have structured resource sub-dicts.
            model = item.get("modelName") or item.get("_model", "unknown")
            for res_key in ("romResource", "toolResource", "otaResource",
                            "countryCodeResource"):
                res = item.get(res_key)
                if isinstance(res, dict):
                    _add(res.get("uri"), res.get("name") or f"{model}_{res_key}")
            _add(item.get("flashFlow"), f"{model}_flashFlow.json")

        return urls

    def get_plugin_urls(self) -> list[tuple[str, str]]:
        """Return download URLs for LMSA-related tool downloads.

        Gathers downloadable URLs from two sources:

        1. ``/client/getPluginCategoryList.jhtml`` — plugin category metadata.
           Only ``iconUrl`` fields with a recognisable ``download.lenovo.com``
           prefix are used; ``assemblyPath`` values are local DLL/EXE names,
           not network URLs, and are skipped.

        2. Known static tool URLs confirmed to return HTTP 200 without auth:
           - ``https://download.lenovo.com/lsa/ma.apk`` — Moto Assistant APK
           - Tool ZIPs referenced by model firmware resources are already
             included via :meth:`collect_download_urls`; duplicates are
             deduped automatically by the caller.

        Returns ``(url, name)`` pairs with valid ``https://`` URLs only.
        """
        urls: list[tuple[str, str]] = []
        seen: set[str] = set()

        def _add(raw: str, default_name: str = "") -> None:
            """Normalise and add *raw* URL if it is a real HTTPS URL."""
            if not raw:
                return
            if raw.startswith("//"):
                raw = "https:" + raw
            elif not raw.startswith(("http://", "https://")):
                # Local paths like "lenovo.mbg.service.lmsa.toolbox.exe" — skip
                if "." in raw and "/" not in raw:
                    return
                raw = "https://" + raw
            # Skip obvious junk/non-download hosts
            host = raw.split("/")[2] if raw.startswith("http") else ""
            if host in {"www.baidu.com", ""}:
                return
            base = raw.split("?")[0]
            if base in seen:
                return
            seen.add(base)
            name = base.rstrip("/").rsplit("/", 1)[-1] or default_name
            if name:
                urls.append((raw, name))

        # 1. Plugin category list — icon images only (real download.lenovo.com)
        data = self._post("/client/getPluginCategoryList.jhtml", {"country": "US"})
        if data and data.get("code") == _CODE_OK:
            for p in (data.get("content") or []):
                _add(p.get("iconUrl", ""), p.get("categoryName", "plugin"))

        # 2. Static known-public tool URLs (confirmed HTTP 200, no auth)
        _add("https://download.lenovo.com/lsa/ma.apk", "ma.apk")

        return urls

    def logout(self) -> bool:
        """Invalidate the current session token on the server."""
        if not self._jwt_token:
            return True
        data = self._post(_EP_DELETE_TOKEN, {})
        self._jwt_token = None
        self._session.headers.pop("Authorization", None)
        return data is not None and data.get("code") == _CODE_OK

    def inject_into_requests_session(
        self, sess: requests.Session, host: str
    ) -> None:
        """Copy auth headers into *sess* so the crawler uses them for *host*.

        Call this after :meth:`authenticate` to make the crawler's
        :class:`requests.Session` send the JWT token on every request to the
        LMSA download CDN (``rsddownload-secure.lenovo.com``).
        """
        if self._jwt_token:
            sess.headers["Authorization"] = f"Bearer {self._jwt_token}"
        sess.headers["guid"] = self.guid
        sess.headers["Request-Tag"] = "lmsa"

    @property
    def is_authenticated(self) -> bool:
        """``True`` after a successful :meth:`authenticate` call."""
        return bool(self._jwt_token)

    def session_info(self) -> dict[str, Any]:
        """Return a human-readable summary of the current session state."""
        return {
            "base_url":         self.base_url,
            "guid":             self.guid,
            "language":         self.language,
            "client_version":   CLIENT_VERSION,
            "authenticated":    self.is_authenticated,
            "rsa_key_loaded":   self._rsa_key is not None,
            "crypto_available": _CRYPTO_AVAILABLE,
        }


# ---------------------------------------------------------------------------
# Auth-data loader helpers (used by the CLI)
# ---------------------------------------------------------------------------

def load_auth_json(json_string: str) -> dict[str, Any]:
    """Parse *json_string* into an auth-data dict (CLI helper)."""
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as exc:
        _log(f"[LMSA] JSON parse error: {exc}")
        return {}


def load_auth_file(path: str) -> dict[str, Any]:
    """Load auth data from a JSON file at *path* (CLI helper)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        _log(f"[LMSA] Error loading auth file '{path}': {exc}")
        return {}


def lmsa_session_from_auth_data(
    auth_data: dict[str, Any],
    base_url: str = LMSA_BASE_URL,
) -> LMSASession:
    """Build an :class:`LMSASession` from a ``dparams``-style auth dict.

    The dict format matches the ``RequestModel`` used by the LMSA desktop app::

        {
            "client":      {"version": "7.4.3.4"},
            "dparams":     {"guid": "...", "wust": "..."},
            "language":    "es-ES",
            "windowsInfo": "Microsoft Windows 11 Pro, x64-based PC"
        }
    """
    dparams = auth_data.get("dparams", {})
    return LMSASession(
        base_url=base_url,
        guid=dparams.get("guid") or auth_data.get("guid"),
        language=auth_data.get("language", "en-US"),
        windows_info=auth_data.get(
            "windowsInfo", "Windows 10, 64bit"
        ),
    )


# ---------------------------------------------------------------------------
# Tiny logger (avoids importing the web_crawler logger at module level)
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    try:
        from web_crawler.utils.log import log
        log.info(msg)
    except Exception:
        print(msg)


def _log_debug(msg: str) -> None:
    # Debug messages are best-effort; silent failure is acceptable.
    try:
        from web_crawler.utils.log import log
        log.debug(msg)
    except Exception:
        pass
