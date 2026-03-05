"""LMSA API client for Motorola Firmware Downloader.

Implements ALL 16 LMSA endpoints discovered in web_crawler/auth/lmsa.py
and web_crawler/auth/lenovo_id.py, plus the scan/collect helper methods.

This module mirrors the LMSASession class from web_crawler/auth/lmsa.py
with the same endpoint paths, request body structures, response parsing,
and JWT rotation behavior confirmed from live HAR traffic (LMSA 7.5.4.2).

Endpoints implemented (all under https://lsa.lenovo.com/Interface):
  Auth:
    1. POST /common/rsa.jhtml              → RSA public key (desc field)
    2. POST /client/initToken.jhtml         → JWT via Guid echo + Authorization
    3. POST /client/deleteToken.jhtml       → Logout / invalidate token
    4. POST /user/lenovoIdLogin.jhtml       → WUST→JWT exchange (author: false)
    5. POST /dictionary/getApiInfo.jhtml     → Login URL (key="TIP_URL")

  Search:
    6.  POST /rescueDevice/getNewResource.jhtml      → Firmware by model (auto-match)
    7.  POST /rescueDevice/getNewResourceByImei.jhtml → Firmware by IMEI
    8.  POST /rescueDevice/getNewResourceBySN.jhtml   → Firmware by serial number
    9.  POST /rescueDevice/getModelNames.jhtml        → All supported models
    10. POST /rescueDevice/getRescueModelNames.jhtml  → Rescue-only models
    11. POST /rescueDevice/getResource.jhtml          → Manual match → pre-signed S3
    12. POST /rescueDevice/getRescueModelRecipe.jhtml  → Rescue recipe
    13. POST /rescueDevice/getRomMatchParams.jhtml     → ROM match parameters
    14. POST /priv/getRomList.jhtml                    → Full ROM catalogue (~2299)

  Download:
    15. POST /client/renewFileLink.jhtml               → Renew expired S3 link
    16. POST /client/getPluginCategoryList.jhtml        → Plugin/tool downloads
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from motorola_downloader.utils.encryption import lmsa_try_decrypt_data
from motorola_downloader.utils.headers import HeaderManager
from motorola_downloader.utils.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.request_builder import RequestBuilder
from motorola_downloader.utils.url_utils import normalize_url

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# API base URLs.  Production and test servers may hold different firmware
# catalogues, so the search engine queries BOTH and merges results.
# ---------------------------------------------------------------------------
LMSA_BASE_URL = "https://lsa.lenovo.com/Interface"
LMSA_BASE_URLS = (
    "https://lsa.lenovo.com/Interface",
    "https://lsatest.lenovo.com/Interface",
)

# ---------------------------------------------------------------------------
# Endpoint paths (from WebApiUrl.cs + WebServicesContext.cs, confirmed via
# live HAR and decompiled LMSA 7.5.4.2 assemblies — lmsa.py lines 105-117)
# ---------------------------------------------------------------------------

# Auth endpoints
_EP_RSA_KEY               = "/common/rsa.jhtml"
_EP_INIT_TOKEN            = "/client/initToken.jhtml"
_EP_DELETE_TOKEN          = "/client/deleteToken.jhtml"
_EP_LOGIN                 = "/user/lenovoIdLogin.jhtml"
_EP_GET_API_INFO          = "/dictionary/getApiInfo.jhtml"

# Search endpoints
_EP_GET_RESOURCE          = "/rescueDevice/getNewResource.jhtml"
_EP_GET_RESOURCE_BY_IMEI  = "/rescueDevice/getNewResourceByImei.jhtml"
_EP_GET_RESOURCE_BY_SN    = "/rescueDevice/getNewResourceBySN.jhtml"
_EP_GET_MODEL_NAMES       = "/rescueDevice/getModelNames.jhtml"
_EP_GET_MARKET_NAMES      = "/rescueDevice/getRescueModelNames.jhtml"
_EP_GET_RESOURCE_V2       = "/rescueDevice/getResource.jhtml"
_EP_GET_RECIPE            = "/rescueDevice/getRescueModelRecipe.jhtml"
_EP_ROM_MATCH_PARAMS      = "/rescueDevice/getRomMatchParams.jhtml"
_EP_ROM_LIST              = "/priv/getRomList.jhtml"

# Download endpoints
_EP_RENEW_LINK            = "/client/renewFileLink.jhtml"
_EP_PLUGIN_LIST           = "/client/getPluginCategoryList.jhtml"

# Standard success code
_CODE_OK = "0000"

# Known device categories (from lmsa.py line 122)
FIRMWARE_CATEGORIES = ("Phone", "Tablet")

# All known countries / carrier-regions observed in the LMSA API
# (union of lmsa.py lines 123-128, HAR captures, and carrier scanner output).
FIRMWARE_COUNTRIES = (
    "Mexico", "US", "Brazil", "Argentina", "Colombia", "Chile",
    "Peru", "Ecuador", "Guatemala", "Paraguay", "Dominican Republic",
    "India", "Germany", "UK", "France", "Italy", "Spain", "Australia",
    "Canada", "Japan", "China",
    # Latin America carriers (from carrier scanner)
    "Mexico-Telcel", "Mexico-AT&T", "Mexico-Altan", "Mexico-Retail",
    "Brazil-TIM", "Brazil_Claro", "Brazil_Retail",
    "Argentina", "Chile-Claro", "Chile-Movistar", "Chile-WOM",
    "Chile-Entel", "Chile-Retail",
    "Peru-Claro", "Peru-Movistar", "Peru-Entel", "Peru_Retail",
    "Colombia-Claro", "Ecuador-Claro",
    "Guatemala-Claro", "Guatemala-Tigo",
    "Dominican Republic Claro", "Paraguay-Claro",
    "Puerto Rico", "El Salvador", "Uruguay",
    # EMEA / APAC
    "Sweden", "Poland", "Taiwan Region,China", "Kazakhstan",
)

# Max recursion depth for _resolve_resource() paramProperty chains.
# Deepest observed chain: 3 steps (simCount → country → resolved).
_MAX_RESOLVE_DEPTH = 4

# How often to emit progress heartbeat during scan_all_firmware.
_SCAN_HEARTBEAT_INTERVAL = 10

# Hosts whose firmware URLs are publicly accessible (no presigning).
_PUBLIC_FIRMWARE_HOSTS = frozenset({"download.lenovo.com"})

# Static tool URL known to return HTTP 200 without auth.
_STATIC_TOOL_URL = "https://download.lenovo.com/lsa/ma.apk"


class LMSAClient:
    """LMSA API client implementing all 16 endpoints.

    Mirrors LMSASession from web_crawler/auth/lmsa.py with identical
    endpoint paths, request body structures (RequestModel envelope),
    response parsing, and JWT rotation behavior.

    Args:
        header_manager: HeaderManager for constructing request headers.
        request_builder: RequestBuilder for LMSA RequestModel envelopes.
        http_client: HTTP client for making API requests.
    """

    def __init__(
        self,
        header_manager: HeaderManager,
        request_builder: RequestBuilder,
        http_client: HTTPClient,
    ) -> None:
        """Initialize the LMSAClient.

        Args:
            header_manager: Manages header profiles (API, auth, download).
            request_builder: Builds RequestModel JSON envelopes.
            http_client: HTTP client with retry logic.
        """
        self._headers = header_manager
        self._builder = request_builder
        self._http = http_client
        self._base_url = LMSA_BASE_URL
        self.logger = get_logger(__name__)
        self._reauth_attempted: bool = False

    @property
    def base_url(self) -> str:
        """Current API base URL."""
        return self._base_url

    @base_url.setter
    def base_url(self, url: str) -> None:
        """Switch the API base URL (e.g. to lsatest.lenovo.com)."""
        self._base_url = url.rstrip("/")
        self.logger.debug("API base URL changed to %s", self._base_url)

    # ------------------------------------------------------------------
    # Internal POST helper (matches lmsa.py _post() exactly)
    # ------------------------------------------------------------------

    def _post(
        self,
        endpoint: str,
        params: Dict[str, Any],
        *,
        author: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """POST a RequestModel to *endpoint* and return parsed JSON body.

        Matches lmsa.py _post() lines 373-420:
          1. Wrap params in RequestModel envelope via _build_request_model
          2. Send with _request_headers(author=...) overlay on _BASE_HEADERS
          3. Extract JWT from response when Guid echo matches
          4. Parse and return JSON body

        On code 402 (token timeout), automatically attempts re-authentication
        via RSA flow with a fresh GUID and retries the request once.

        Args:
            endpoint: API endpoint path (e.g. '/common/rsa.jhtml').
            params: Parameters for the dparams section.
            author: Whether to include auth headers (default True).
                Set to False for lenovoIdLogin.jhtml (author: false).

        Returns:
            Parsed JSON response dict, or None on failure.
        """
        url = f"{self._base_url}{endpoint}"
        body = self._builder.build(params)
        headers = self._headers.get_full_api_headers(author=author)

        try:
            response = self._http.post(url, json_data=body, headers=headers)
        except Exception as exc:
            self.logger.error("POST %s failed: %s", endpoint, exc)
            return None

        # JWT rotation (lmsa.py _post() lines 401-410)
        self._headers.update_jwt_from_response(dict(response.headers))

        if response.status_code != 200:
            self.logger.error(
                "POST %s → HTTP %d: %s",
                endpoint, response.status_code, response.text[:200],
            )
            return None

        try:
            data = response.json()
        except ValueError:
            self.logger.error(
                "POST %s → non-JSON response: %s",
                endpoint, response.text[:200],
            )
            return None

        # Auto re-auth on 402 "token timeout" — try RSA auth once
        if data.get("code") == "402" and not self._reauth_attempted:
            self.logger.warning(
                "Token expired (402). Attempting auto re-authentication..."
            )
            if self._auto_reauth():
                self._reauth_attempted = True
                result = self._post(endpoint, params, author=author)
                self._reauth_attempted = False
                return result
            else:
                self.logger.error(
                    "Auto re-authentication failed. Provide a fresh JWT "
                    "via Configuration → Set JWT Token."
                )

        return data

    def _auto_reauth(self) -> bool:
        """Attempt automatic re-authentication via RSA flow.

        Generates a fresh GUID, fetches RSA key, encrypts GUID,
        and calls initToken. On success, updates headers with new JWT.

        Returns:
            True if re-authentication succeeded.
        """
        import uuid
        import base64

        try:
            from Crypto.Cipher import PKCS1_v1_5
            from Crypto.PublicKey import RSA
        except ImportError:
            self.logger.error(
                "pycryptodome not installed — cannot auto re-authenticate"
            )
            return False

        # Use a fresh random GUID for anonymous auth
        fresh_guid = str(uuid.uuid4()).lower()
        self.logger.info("Trying RSA auth with fresh GUID...")

        # Step 1: RSA key
        key_b64 = self.get_rsa_public_key()
        if not key_b64:
            return False

        # Step 2: Encrypt fresh GUID
        try:
            key_der = base64.b64decode(key_b64.strip())
            rsa_key = RSA.import_key(key_der)
            cipher = PKCS1_v1_5.new(rsa_key)
            encrypted = cipher.encrypt(fresh_guid.encode("utf-8"))
            enc_guid = base64.b64encode(encrypted).decode("ascii")
        except Exception as exc:
            self.logger.error("RSA encryption failed: %s", exc)
            return False

        # Step 3: Update GUID in headers and builder before initToken
        old_guid = self._headers._guid
        self._headers.set_guid(fresh_guid)
        self._builder._guid = fresh_guid

        # Step 4: initToken
        data = self.init_token(enc_guid)
        if data and data.get("code") == _CODE_OK:
            jwt = self._headers.get_jwt_token()
            if jwt:
                self.logger.info("Auto re-authentication successful!")
                return True

        # Restore old GUID on failure
        self._headers.set_guid(old_guid)
        self._builder._guid = old_guid
        self.logger.warning("RSA re-auth failed, reverting GUID")
        return False

    # ==================================================================
    # AUTH ENDPOINTS (5)
    # ==================================================================

    # 1. /common/rsa.jhtml
    def get_rsa_public_key(self) -> Optional[str]:
        """Fetch the server's RSA public key.

        Matches lmsa.py get_rsa_public_key():
          - POST with empty dparams: {}
          - Response: code "0000", desc: "<PKCS8 Base64 key>"
          - Key is in `desc` field (NOT `data`)
          - Format: PKCS#8 SubjectPublicKeyInfo, Base64-encoded

        Returns:
            Base64-encoded RSA public key string, or None on failure.
        """
        data = self._post(_EP_RSA_KEY, {})
        if data is None or data.get("code") != _CODE_OK:
            return None
        key_b64: str = data.get("desc", "")
        if not key_b64:
            self.logger.error("RSA key response missing 'desc' field")
            return None
        self.logger.info("RSA public key fetched successfully")
        return key_b64

    # 2. /client/initToken.jhtml
    def init_token(self, encrypted_guid: str) -> Optional[Dict[str, Any]]:
        """Initialize session token with RSA-encrypted GUID.

        Matches lmsa.py authenticate() step 3:
          - dparams: {guid: ENCRYPTED_GUID}
          - JWT arrives in response Authorization header (Guid echo)
          - Response body: code "0000" on success

        Args:
            encrypted_guid: RSA-encrypted GUID (Base64 string).

        Returns:
            Response dict on success, None on failure.
        """
        data = self._post(_EP_INIT_TOKEN, {"guid": encrypted_guid})
        if data is None or data.get("code") != _CODE_OK:
            if data:
                self.logger.error(
                    "initToken error: %s — %s",
                    data.get("code"), data.get("desc", ""),
                )
            return None
        self.logger.info("Token initialised successfully")
        return data

    # 3. /client/deleteToken.jhtml
    def logout(self) -> bool:
        """Invalidate the current session token on the server.

        Matches lmsa.py logout():
          - POST with empty dparams: {}
          - Clears JWT token on success

        Returns:
            True if logout was successful.
        """
        data = self._post(_EP_DELETE_TOKEN, {})
        success = data is not None and data.get("code") == _CODE_OK
        if success:
            self._headers.set_jwt_token("")
            self.logger.info("Session token invalidated (logout)")
        return success

    # 4. /user/lenovoIdLogin.jhtml
    def lenovo_id_login(self, wust: str, guid: str) -> Optional[Dict[str, Any]]:
        """Exchange WUST token for JWT via Lenovo ID login.

        Matches lenovo_id.py _exchange_wust_for_jwt():
          - author: false → NO guid/Authorization in request headers
          - dparams: {wust: WUST, guid: PLAIN_GUID}
          - JWT in Authorization response header (Guid echo)

        Args:
            wust: WUST token from Lenovo ID OAuth callback.
            guid: Plain device GUID (NOT encrypted).

        Returns:
            Response dict on success, None on failure.
        """
        data = self._post(
            _EP_LOGIN,
            {"wust": wust, "guid": guid},
            author=False,
        )
        if data is None:
            return None

        code = data.get("code", "")
        if code == "402":
            self.logger.error("WUST rejected (expired or invalid)")
            return None
        if code == "403":
            self.logger.error("Invalid token (server-side)")
            return None
        if code != _CODE_OK:
            self.logger.error(
                "lenovoIdLogin error %s: %s", code, data.get("desc", "")
            )
            return None

        self.logger.info("Lenovo ID login successful")
        return data

    # 5. /dictionary/getApiInfo.jhtml
    def get_api_info(self, key: str = "TIP_URL") -> Optional[str]:
        """Fetch API configuration info (e.g. OAuth login URL).

        Matches lenovo_id.py _get_login_url():
          - dparams: {key: "TIP_URL"}
          - Response: code "0000", content: JSON string with login_url

        Args:
            key: Configuration key to fetch (default: "TIP_URL").

        Returns:
            The value string for the requested key, or None on failure.
        """
        data = self._post(_EP_GET_API_INFO, {"key": key})
        if data is None or data.get("code") != _CODE_OK:
            return None

        content = data.get("content", "")
        if not content:
            return None

        # Content is a JSON string that needs parsing
        try:
            import json
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                return parsed.get("login_url", "") or str(parsed)
            return str(parsed)
        except (ValueError, TypeError):
            return content if isinstance(content, str) else None

    # ==================================================================
    # SEARCH ENDPOINTS (9)
    # ==================================================================

    # 6. /rescueDevice/getNewResource.jhtml
    def get_firmware(
        self,
        model_name: str,
        region: str = "",
        market: str = "",
        carrier: str = "",
        flash_tool_type: str = "QComFlashTool",
        android_version: str = "",
        build_type: str = "user",
    ) -> Optional[Dict[str, Any]]:
        """Query available firmware for a device.

        Matches lmsa.py get_firmware() exactly:
          - dparams: {modelName, flashToolType, buildType, region?, market?, carrier?}
          - Response: code "0000", data may be AES-encrypted or plain

        Args:
            model_name: Motorola model number (e.g. 'xt2553-2').
            region: Geographic region (e.g. 'US', 'RETUS', 'RETBR').
            market: Market name variant.
            carrier: Carrier variant (e.g. 'Unlocked', 'Verizon').
            flash_tool_type: Flash tool identifier. MediaTek: MTekFlashTool,
                MTekSpFlashTool. Qualcomm: QComFlashTool, QFileTool. Generic: PnPTool.
            android_version: Android version filter.
            build_type: Build type (user, userdebug, eng).

        Returns:
            Raw API response dict on success, None on failure.
        """
        params: Dict[str, Any] = {
            "modelName": model_name,
            "flashToolType": flash_tool_type,
            "buildType": build_type,
        }
        if region:
            params["region"] = region
        if market:
            params["market"] = market
        if carrier:
            params["carrier"] = carrier
        if android_version:
            params["androidVersion"] = android_version

        self.logger.debug("Querying firmware for %s...", model_name)
        data = self._post(_EP_GET_RESOURCE, params)
        if data is None:
            return None

        code = data.get("code", "")
        if code == "402":
            self.logger.warning("Token expired (402) — re-authentication needed")
            return None
        if code == "403":
            self.logger.debug("Firmware query blocked (403) — token required")
            return None
        if code != _CODE_OK:
            # Code 1000 = "model not found" — expected during multi-variant
            # search; do not pollute the console with expected misses.
            self.logger.debug(
                "Firmware query for '%s': code %s", model_name, code,
            )
            return None

        # The `data` field may be AES-128-CBC encrypted (Base64 string).
        # Try to decrypt it; if it's already plain JSON, leave it as-is.
        raw_data = data.get("data")
        if isinstance(raw_data, str) and raw_data:
            import json as _json
            decrypted = lmsa_try_decrypt_data(raw_data)
            if decrypted != raw_data:
                self.logger.info("Firmware data was AES-encrypted, decrypted OK")
            try:
                data["data"] = _json.loads(decrypted)
            except (ValueError, TypeError):
                data["data"] = decrypted

        return data

    # 7. /rescueDevice/getNewResourceByImei.jhtml
    def get_firmware_by_imei(self, imei: str) -> Optional[Dict[str, Any]]:
        """Query firmware for a device by IMEI number.

        Matches lmsa.py _EP_GET_RESOURCE_BY_IMEI endpoint.

        Args:
            imei: Device IMEI number (15 digits).

        Returns:
            Raw API response dict on success, None on failure.
        """
        self.logger.info("Querying firmware by IMEI...")
        data = self._post(_EP_GET_RESOURCE_BY_IMEI, {"imei": imei})
        if data is None or data.get("code") != _CODE_OK:
            return None
        return data

    # 8. /rescueDevice/getNewResourceBySN.jhtml
    def get_firmware_by_serial(self, serial_number: str) -> Optional[Dict[str, Any]]:
        """Query firmware for a device by serial number.

        Matches lmsa.py _EP_GET_RESOURCE_BY_SN endpoint.

        Args:
            serial_number: Device serial number.

        Returns:
            Raw API response dict on success, None on failure.
        """
        self.logger.info("Querying firmware by serial number...")
        data = self._post(_EP_GET_RESOURCE_BY_SN, {"sn": serial_number})
        if data is None or data.get("code") != _CODE_OK:
            return None
        return data

    # 9. /rescueDevice/getModelNames.jhtml
    def get_model_names(
        self,
        country: str = "Mexico",
        category: str = "Phone",
    ) -> List[Dict[str, Any]]:
        """Return the list of supported device models for a country.

        Matches lmsa.py get_model_names() exactly:
          - dparams: {country, category}
          - Response: content.models + content.moreModels
          - Deduplicates by modelName, preserving main-list priority

        Args:
            country: Country for model list.
            category: Device category ('Phone' or 'Tablet').

        Returns:
            Combined and deduplicated list of model info dicts.
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

        # Combine models + moreModels, dedup by modelName (lmsa.py lines 657-666)
        models: List[Dict[str, Any]] = list(content.get("models") or [])
        more: List[Dict[str, Any]] = list(content.get("moreModels") or [])
        seen: set[str] = {m.get("modelName", "") for m in models}
        for m in more:
            name = m.get("modelName", "")
            if name and name not in seen:
                seen.add(name)
                models.append(m)

        return models

    # 10. /rescueDevice/getRescueModelNames.jhtml
    def get_rescue_model_names(
        self,
        country: str = "Mexico",
    ) -> List[Dict[str, Any]]:
        """Return rescue-only device models.

        Matches lmsa.py _EP_GET_MARKET_NAMES endpoint.

        Args:
            country: Country for model list.

        Returns:
            List of rescue model info dicts.
        """
        data = self._post(_EP_GET_MARKET_NAMES, {"country": country})
        if data is None or data.get("code") != _CODE_OK:
            return []
        content = data.get("content")
        if isinstance(content, list):
            return content
        if isinstance(content, dict):
            return list(content.get("models") or [])
        return []

    # 11. /rescueDevice/getResource.jhtml
    def get_resource(
        self,
        model_name: str,
        market_name: str,
        **extra_params: str,
    ) -> List[Dict[str, Any]]:
        """Return firmware resources for a specific device model.

        Matches lmsa.py get_resource() exactly:
          - dparams: {modelName, marketName, ...extra}
          - Response: content (list) with paramProperty or resolved items

        Items may have:
          - romResource, toolResource, flashFlow, otaResource,
            countryCodeResource → fully resolved (has S3 URLs)
          - paramProperty + paramValues → needs recursive resolution

        Args:
            model_name: Device model name.
            market_name: Market name from model list.
            **extra_params: Additional params (e.g. simCount, country).

        Returns:
            List of resource item dicts.
        """
        params: Dict[str, Any] = {
            "modelName": model_name,
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

    # 12. /rescueDevice/getRescueModelRecipe.jhtml
    def get_rescue_recipe(
        self,
        model_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Get rescue recipe for a device model.

        Matches lmsa.py _EP_GET_RECIPE endpoint.

        Args:
            model_name: Device model name.

        Returns:
            Response dict on success, None on failure.
        """
        data = self._post(_EP_GET_RECIPE, {"modelName": model_name})
        if data is None or data.get("code") != _CODE_OK:
            return None
        return data

    # 13. /rescueDevice/getRomMatchParams.jhtml
    def get_rom_match_params(
        self,
        model_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Get ROM match parameters for a device model.

        Matches lmsa.py _EP_ROM_MATCH_PARAMS endpoint.

        Args:
            model_name: Device model name.

        Returns:
            Response dict on success, None on failure.
        """
        data = self._post(_EP_ROM_MATCH_PARAMS, {"modelName": model_name})
        if data is None or data.get("code") != _CODE_OK:
            return None
        return data

    # 14. /priv/getRomList.jhtml
    def get_rom_list(
        self,
        model_name: str = "",
        region: str = "",
        carrier: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Fetch the ROM list for a specific device.

        Matches lmsa.py get_rom_list():
          - dparams: {modelName?, region?, carrier?}
          - Response: code "0000", content field

        Args:
            model_name: Optional model name filter.
            region: Optional region filter.
            carrier: Optional carrier filter.

        Returns:
            Response dict on success, None on failure.
        """
        params: Dict[str, Any] = {}
        if model_name:
            params["modelName"] = model_name
        if region:
            params["region"] = region
        if carrier:
            params["carrier"] = carrier

        data = self._post(_EP_ROM_LIST, params)
        if data is None or data.get("code") != _CODE_OK:
            return None
        return data

    def get_all_roms(self) -> List[Dict[str, Any]]:
        """Return the complete LMSA ROM catalogue.

        Matches lmsa.py get_all_roms() exactly:
          - POST /priv/getRomList.jhtml with empty dparams: {}
          - Response: content (list of ~2299 ROM entries)
          - Each entry: name, uri, type (0=ROM, 1=Tool), md5
          - Normalises scheme-less URIs (some legacy entries omit https://)

        Returns:
            List of normalised resource dicts.
        """
        data = self._post(_EP_ROM_LIST, {})
        if data is None or data.get("code") != _CODE_OK:
            self.logger.debug("getRomList: %s", data.get("code") if data else "no response")
            return []

        roms = data.get("content") or []
        if not isinstance(roms, list):
            return []

        # Normalise scheme-less URIs (lmsa.py lines 759-766)
        normalised: List[Dict[str, Any]] = []
        for item in roms:
            uri = item.get("uri", "") or ""
            if uri and not uri.startswith(("http://", "https://")):
                item = dict(item)
                item["uri"] = "https://" + uri.lstrip("/")
            normalised.append(item)

        self.logger.info("getRomList: %d ROM entries", len(normalised))
        return normalised

    # ==================================================================
    # DOWNLOAD ENDPOINTS (2)
    # ==================================================================

    # 15. /client/renewFileLink.jhtml
    def renew_download_link(self, file_id: str) -> Optional[str]:
        """Renew an expired S3 pre-signed download URL.

        Matches lmsa.py renew_download_link():
          - dparams: {fileId: FILE_ID}
          - Response: data field contains new URL string

        S3 pre-signed URLs expire after 7 days (X-Amz-Expires=604800).

        Args:
            file_id: File identifier for the expired link.

        Returns:
            New download URL string, or None on failure.
        """
        data = self._post(_EP_RENEW_LINK, {"fileId": file_id})
        if data is None or data.get("code") != _CODE_OK:
            return None
        result = data.get("data")
        return result if isinstance(result, str) else None

    # 16. /client/getPluginCategoryList.jhtml
    def get_plugin_urls(self, country: str = "US") -> List[Tuple[str, str]]:
        """Return download URLs for LMSA-related tool downloads.

        Matches lmsa.py get_plugin_urls() exactly:
          1. /client/getPluginCategoryList.jhtml → iconUrl fields
          2. Static known-public tool URLs (ma.apk)

        Args:
            country: Country code for plugin list.

        Returns:
            List of (url, filename) tuples.
        """
        urls: List[Tuple[str, str]] = []
        seen: set[str] = set()

        def _add(raw: str, default_name: str = "") -> None:
            """Normalise and add URL if it is a real HTTPS URL."""
            if not raw:
                return
            if raw.startswith("//"):
                raw = "https:" + raw
            elif not raw.startswith(("http://", "https://")):
                # Local paths like "lenovo.mbg.service.lmsa.toolbox.exe" — skip
                if "." in raw and "/" not in raw:
                    return
                raw = "https://" + raw
            # Skip junk hosts
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

        # 1. Plugin category list
        data = self._post(_EP_PLUGIN_LIST, {"country": country})
        if data and data.get("code") == _CODE_OK:
            for plugin in (data.get("content") or []):
                _add(plugin.get("iconUrl", ""), plugin.get("categoryName", "plugin"))

        # 2. Static known-public tool URL (confirmed HTTP 200, no auth)
        _add(_STATIC_TOOL_URL, "ma.apk")

        return urls

    # ==================================================================
    # RESOLUTION AND SCANNING METHODS
    # ==================================================================

    @staticmethod
    def _has_download_url(item: Dict[str, Any]) -> bool:
        """Check whether a resource item has at least one real download URI.

        Some intermediate resolution steps include keys like
        ``romResource`` with a *null* or empty value.  Only treat an
        item as fully resolved when the ``uri`` field inside a resource
        dict is a non-empty string.

        Args:
            item: A resource dict from ``getResource.jhtml``.

        Returns:
            True if the item contains at least one downloadable URI.
        """
        for key in ("romResource", "toolResource", "otaResource",
                     "countryCodeResource"):
            res = item.get(key)
            if isinstance(res, dict) and res.get("uri"):
                return True
        # flashFlow can be a JSON string or dict with a download URL
        ff = item.get("flashFlow")
        if ff and isinstance(ff, (str, dict)):
            return True
        return False

    def resolve_resource(
        self,
        model_name: str,
        market_name: str,
        depth: int = 0,
        **params: str,
    ) -> List[Dict[str, Any]]:
        """Recursively resolve paramProperty selections until S3 URLs.

        Matches the real LMSA resolution chain observed in HAR traffic:

            getResource(modelName, marketName)
              → paramProperty: simCount, paramValues: [Single, Dual]
            getResource(…, simCount=Single)
              → paramProperty: country, paramValues: [Mexico, …]
            getResource(…, simCount=Single, country=Mexico)
              → romResource.uri + toolResource.uri  ← fully resolved

        Args:
            model_name: Device model name (e.g. ``XT2523-2``).
            market_name: Market name from model list (e.g. ``Moto g05``).
            depth: Current recursion depth (guard against infinite loops).
            **params: Additional resolution parameters accumulated so far
                (e.g. ``simCount="Single", country="Mexico"``).

        Returns:
            List of fully-resolved resource dicts with S3 download URLs.
        """
        if depth > _MAX_RESOLVE_DEPTH:
            return []

        items = self.get_resource(model_name, market_name, **params)
        resolved: List[Dict[str, Any]] = []

        for item in items:
            # Check if fully resolved (has a real download URI)
            if self._has_download_url(item):
                resolved.append(item)
            elif item.get("paramProperty") and item.get("paramValues"):
                # Need to pick param values and recurse
                prop = item["paramProperty"].get("property", "")
                values = item["paramValues"]
                if prop and values:
                    for val in values:
                        sub = self.resolve_resource(
                            model_name, market_name,
                            depth=depth + 1,
                            **params,
                            **{prop: val},
                        )
                        resolved.extend(sub)

        return resolved

    def scan_all_firmware(
        self,
        countries: Tuple[str, ...] = FIRMWARE_COUNTRIES,
        categories: Tuple[str, ...] = FIRMWARE_CATEGORIES,
    ) -> List[Dict[str, Any]]:
        """Scan the LMSA API for all available firmware download URLs.

        Matches lmsa.py scan_all_firmware() exactly — two strategies:

        1. Full ROM catalogue (/priv/getRomList.jhtml):
           ~2299 entries in a single API call. download.lenovo.com entries
           are public; S3 entries are included as base (unsigned) URLs.

        2. Per-model pre-signed scan (/rescueDevice/getResource.jhtml):
           Iterates every model × country, resolves paramProperty chains
           until AWS pre-signed S3 URLs are returned (valid 7 days).

        Args:
            countries: Countries to scan.
            categories: Device categories to scan.

        Returns:
            Flat list of resource dicts (augmented with _country, _category).
        """
        all_resources: List[Dict[str, Any]] = []

        # --- Strategy 1: full ROM catalogue ---
        self.logger.info("Strategy 1: Fetching full ROM catalogue...")
        roms = self.get_all_roms()
        for rom in roms:
            all_resources.append({
                "_rom_uri": rom.get("uri", ""),
                "_rom_name": rom.get("name", ""),
                "_rom_md5": rom.get("md5", ""),
                "_rom_type": rom.get("type", 0),
                "_country": "",
                "_category": "",
            })

        # --- Strategy 2: per-model presigned scan ---
        self.logger.info("Strategy 2: Per-model pre-signed scan...")
        seen_models: set[str] = set()
        presigned: List[Dict[str, Any]] = []
        scanned_count = 0

        for country in countries:
            for category in categories:
                models = self.get_model_names(country=country, category=category)
                self.logger.info(
                    "%s/%s: %d models", country, category, len(models)
                )

                for model_info in models:
                    model_name = model_info.get("modelName", "")
                    market_name = model_info.get("marketName", "")
                    key = f"{model_name}|{country}"
                    if key in seen_models or not model_name:
                        continue
                    seen_models.add(key)
                    scanned_count += 1

                    # Periodic heartbeat
                    if scanned_count % _SCAN_HEARTBEAT_INTERVAL == 0:
                        self.logger.info(
                            "  … %d models scanned (%d resource(s) found)",
                            scanned_count, len(presigned),
                        )

                    items = self.resolve_resource(
                        model_name, market_name, country=country
                    )
                    for item in items:
                        item["_country"] = country
                        item["_category"] = category
                    presigned.extend(items)

                    if items:
                        self.logger.info(
                            "  %s (%s): %d resource(s)",
                            model_name, market_name, len(items),
                        )

        all_resources.extend(presigned)
        self.logger.info(
            "scan_all_firmware complete: %d catalogue + %d presigned "
            "(%d unique model/country pairs)",
            len(roms), len(presigned), len(seen_models),
        )
        return all_resources

    def collect_download_urls(
        self,
        resources: List[Dict[str, Any]],
    ) -> List[Tuple[str, str]]:
        """Extract all download URLs from resources.

        Matches lmsa.py collect_download_urls() exactly:
          - Extracts romResource, toolResource, flashFlow, otaResource,
            countryCodeResource from resolved getResource entries
          - Extracts _rom_uri from getRomList catalogue entries
          - Deduplicates by base URL (without query string)
          - Normalises protocol-relative and scheme-less URLs

        Args:
            resources: List from scan_all_firmware().

        Returns:
            List of (url, filename) tuples.
        """
        urls: List[Tuple[str, str]] = []
        seen: set[str] = set()

        def _add(url_val: Any, default_name: str) -> None:
            if not url_val or not isinstance(url_val, str):
                return
            if url_val.startswith("//"):
                url_val = "https:" + url_val
            elif not url_val.startswith(("http://", "https://")):
                url_val = "https://" + url_val
            base = url_val.split("?")[0]
            if base in seen:
                return
            seen.add(base)
            name = base.rstrip("/").rsplit("/", 1)[-1] or default_name
            urls.append((url_val, name))

        for item in resources:
            # Raw getRomList catalogue entries
            if item.get("_rom_uri"):
                _add(item["_rom_uri"], item.get("_rom_name") or "unknown.zip")
                continue
            # Resolved getResource entries
            model = item.get("modelName") or item.get("_model", "unknown")
            for res_key in ("romResource", "toolResource", "otaResource",
                            "countryCodeResource"):
                res = item.get(res_key)
                if isinstance(res, dict):
                    _add(res.get("uri"), res.get("name") or f"{model}_{res_key}")
            _add(item.get("flashFlow"), f"{model}_flashFlow.json")

        return urls

    def collect_download_urls_by_type(
        self,
        resources: List[Dict[str, Any]],
    ) -> Dict[str, List[Tuple[str, str]]]:
        """Categorise download URLs by resource type.

        Matches lmsa.py collect_download_urls_by_type() exactly:
          - rom: romResource, otaResource, countryCodeResource, type=0
          - tool: toolResource, type=1
          - other: flashFlow JSON URLs

        Args:
            resources: List from scan_all_firmware().

        Returns:
            Dict with keys 'rom', 'tool', 'other' → list of (url, name).
        """
        categories: Dict[str, List[Tuple[str, str]]] = {
            "rom": [], "tool": [], "other": [],
        }
        seen: set[str] = set()

        def _add(url_val: Any, default_name: str, category: str) -> None:
            if not url_val or not isinstance(url_val, str):
                return
            if url_val.startswith("//"):
                url_val = "https:" + url_val
            elif not url_val.startswith(("http://", "https://")):
                url_val = "https://" + url_val
            base = url_val.split("?")[0]
            if base in seen:
                return
            seen.add(base)
            name = base.rstrip("/").rsplit("/", 1)[-1] or default_name
            categories[category].append((url_val, name))

        for item in resources:
            # Raw getRomList entries — type=1 means tool, else ROM
            if item.get("_rom_uri"):
                cat = "tool" if item.get("_rom_type") == 1 else "rom"
                _add(item["_rom_uri"], item.get("_rom_name") or "unknown.zip", cat)
                continue
            # Resolved getResource entries
            model = item.get("modelName") or item.get("_model", "unknown")
            for res_key in ("romResource", "otaResource", "countryCodeResource"):
                res = item.get(res_key)
                if isinstance(res, dict):
                    _add(res.get("uri"), res.get("name") or f"{model}_{res_key}", "rom")
            res = item.get("toolResource")
            if isinstance(res, dict):
                _add(res.get("uri"), res.get("name") or f"{model}_toolResource", "tool")
            _add(item.get("flashFlow"), f"{model}_flashFlow.json", "other")

        return categories

    def get_download_urls(
        self,
        firmware_response: Dict[str, Any],
    ) -> List[str]:
        """Extract download URLs from a get_firmware() response.

        Matches lmsa.py get_download_urls():
          - data field may be AES-encrypted string or plain dict/list
          - Extracts: downloadUrl, url, fileUrl, link keys

        Args:
            firmware_response: Response from get_firmware().

        Returns:
            List of plain-text download URL strings.
        """
        urls: List[str] = []
        data = firmware_response.get("data")
        if not data:
            return urls

        # data is dict or list of download items
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
