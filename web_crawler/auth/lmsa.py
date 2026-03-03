"""
LMSA (Lenovo Moto Smart Assistant) authentication and firmware-download client.

Reverse-engineered from LMSA 7.4.3.4 .NET assemblies:
  - Software Fix.exe
  - lenovo.mbg.service.common.webservices.dll
  - lenovo.mbg.service.framework.download.dll
  - lenovo.mbg.service.lmsa.flash.dll

Authentication flow
-------------------
1. GET  /common/rsa.jhtml          → RSA public key (XML, 216-char modulus)
2. POST /client/initToken.jhtml    → JWT token (Authorization header)
   Body: RequestModel with RSA-encrypted GUID in dparams.guid
3. POST /rescueDevice/getNewResource.jhtml  → firmware metadata + download URL
4. GET  <download_url>             → signed CloudFront URL on
                                     rsddownload-secure.lenovo.com

Configuration extracted from ``Software Fix.exe.config``:

    BASE_URL        = "https://lsa.lenovo.com"
    CLIENT_VERSION  = "7.4.3.4"
    AES_KEY         = "jdkei3ffkjijut46#$%6y7U8km4p<mdT"
    AES_IV          = "52,*u^yhNjk<./O0"
    DEFAULT_PASSWORD= "OSD"

HTTP headers from ``WebApiHttpRequest.cs``:

    User-Agent    : Mozilla/5.0 (Windows NT 6.3; WOW64) ...
    Content-Type  : application/json
    Cache-Control : no-cache
    Request-Tag   : lmsa
    Connection    : close      (KeepAlive = false per source)
    guid          : <UUID>     (authenticated requests)
    Authorization : Bearer <JWT>
"""

from __future__ import annotations

import base64
import json
import re
import uuid
import xml.etree.ElementTree as ET
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

#: Production API server (``WebApiUrl.cs`` → ``BASE_URL``).
LMSA_BASE_URL = "https://lsa.lenovo.com"

#: LMSA desktop application version (``ClientInfo.cs``).
CLIENT_VERSION = "7.4.3.4"

# AES-128-CBC parameters from ``Software Fix.exe.config``.
AES_KEY: bytes = b"jdkei3ffkjijut46#$%6y7U8km4p<mdT"[:16]   # first 16 bytes → AES-128
AES_IV: bytes  = b"52,*u^yhNjk<./O0"

#: Password used to decrypt ROM archives (``OSD`` constant in flash DLL).
ROM_PASSWORD = "OSD"

# ---------------------------------------------------------------------------
# Endpoint paths (from ``WebApiUrl.cs``)
# ---------------------------------------------------------------------------
_EP_RSA_KEY          = "/common/rsa.jhtml"
_EP_INIT_TOKEN       = "/client/initToken.jhtml"
_EP_DELETE_TOKEN     = "/client/deleteToken.jhtml"
_EP_RENEW_LINK       = "/client/renewFileLink.jhtml"
_EP_GET_RESOURCE     = "/rescueDevice/getNewResource.jhtml"
_EP_ROM_LIST         = "/priv/getRomList.jhtml"
_EP_ROM_MATCH_PARAMS = "/rescueDevice/getRomMatchParams.jhtml"

# ---------------------------------------------------------------------------
# HTTP headers from ``WebApiHttpRequest.cs``
# ---------------------------------------------------------------------------
_BASE_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/43.0.2357.81 Safari/537.36"
    ),
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Cache-Control": "no-cache",
    "Request-Tag": "lmsa",
    "Connection": "close",      # KeepAlive = false in source
}

# Standard API response code for success.
_CODE_OK = "0000"


# ---------------------------------------------------------------------------
# RSA helpers
# ---------------------------------------------------------------------------

def _parse_rsa_xml(xml_text: str) -> Optional[RSA.RsaKey]:
    """Parse an XML RSA public key into an :class:`RSA.RsaKey`.

    The LMSA server returns the public key as an XML fragment::

        <RSAKeyValue>
          <Modulus>BASE64…</Modulus>
          <Exponent>AQAB</Exponent>
        </RSAKeyValue>

    Returns ``None`` when *pycryptodome* is not installed or parsing fails.
    """
    if not _CRYPTO_AVAILABLE:
        return None
    try:
        root = ET.fromstring(xml_text.strip())
        mod_b64  = root.findtext("Modulus", "").strip()
        exp_b64  = root.findtext("Exponent", "AQAB").strip()
        n = int.from_bytes(base64.b64decode(mod_b64), "big")
        e = int.from_bytes(base64.b64decode(exp_b64), "big")
        return RSA.construct((n, e))
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
        windows_info: str = "Windows 10, 64bit",
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.guid = guid or str(uuid.uuid4()).upper()
        self.language = language
        self.windows_info = windows_info
        self._verify_ssl = verify_ssl

        self._jwt_token: Optional[str] = None
        self._rsa_key: Optional[Any] = None   # RSA.RsaKey when crypto available

        self._session = requests.Session()
        self._session.headers.update(_BASE_HEADERS)
        self._session.verify = verify_ssl

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

    def _request_headers(self) -> dict[str, str]:
        """Return per-request headers including auth tokens when available."""
        hdrs: dict[str, str] = {"guid": self.guid}
        if self._jwt_token:
            hdrs["Authorization"] = f"Bearer {self._jwt_token}"
        return hdrs

    def _post(self, endpoint: str, params: dict[str, Any]) -> Optional[dict[str, Any]]:
        """POST a RequestModel to *endpoint* and return the parsed JSON body."""
        body = self._build_request_model(params)
        try:
            resp = self._session.post(
                self._url(endpoint),
                json=body,
                headers=self._request_headers(),
                timeout=30,
            )
        except requests.RequestException as exc:
            _log(f"[LMSA] POST {endpoint} failed: {exc}")
            return None

        # Extract JWT from response headers when present
        auth_hdr = resp.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            self._jwt_token = auth_hdr[len("Bearer "):]

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

        Returns the raw XML string on success, ``None`` on failure.
        Caches the parsed key internally for :meth:`authenticate`.
        """
        try:
            resp = self._session.get(
                self._url(_EP_RSA_KEY),
                headers=self._request_headers(),
                timeout=10,
            )
        except requests.RequestException as exc:
            _log(f"[LMSA] GET {_EP_RSA_KEY} failed: {exc}")
            return None

        if resp.status_code != 200:
            _log(f"[LMSA] RSA key endpoint → HTTP {resp.status_code}")
            return None

        # Response is a JSON envelope: {"code": "0000", "data": "<XML>"}
        try:
            payload = resp.json()
            if payload.get("code") != _CODE_OK:
                _log(f"[LMSA] RSA key error code: {payload.get('code')} "
                     f"msg: {payload.get('msg', '')}")
                return None
            xml_key: str = payload["data"]
        except (ValueError, KeyError):
            # Fallback: treat entire body as raw XML
            xml_key = resp.text

        if _CRYPTO_AVAILABLE:
            self._rsa_key = _parse_rsa_xml(xml_key)
            if self._rsa_key is None:
                _log("[LMSA] Warning: RSA key XML could not be parsed")

        return xml_key

    def authenticate(self) -> bool:
        """Full authentication flow: fetch RSA key → encrypt GUID → init token.

        Returns ``True`` when a JWT token is successfully obtained.
        Requires *pycryptodome* (``pip install pycryptodome``).
        """
        if not _CRYPTO_AVAILABLE:
            _log(
                "[LMSA] pycryptodome not installed – cannot perform RSA "
                "encryption for token init.  Install with: pip install pycryptodome"
            )
            return False

        _log("[LMSA] Fetching RSA public key …")
        xml_key = self.get_rsa_public_key()
        if xml_key is None:
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
            _log(f"[LMSA] initToken error: {data.get('code')} – {data.get('msg', '')}")
            return False

        # JWT may be in the response body instead of the Authorization header
        token = (
            data.get("data", {}).get("token")
            or data.get("token")
            or self._jwt_token
        )
        if token:
            self._jwt_token = token
            self._session.headers["Authorization"] = f"Bearer {token}"
            _log("[LMSA] ✓ Token initialised successfully")
            return True

        _log("[LMSA] Warning: initToken succeeded but no token in response")
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
