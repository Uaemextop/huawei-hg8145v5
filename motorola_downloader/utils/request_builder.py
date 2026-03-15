"""LMSA RequestModel builder for Motorola Firmware Downloader.

Constructs the JSON request envelope used by all LMSA API endpoints.
Pattern extracted from web_crawler/auth/lmsa.py _build_request_model():

Every LMSA API call wraps its parameters in a standard ``RequestModel``
envelope with four top-level keys:
  - ``client``:      {"version": "7.5.4.2"}
  - ``language``:    BCP-47 tag (default "en-US")
  - ``windowsInfo``: OS description string
  - ``dparams``:     caller-supplied parameters + auto-injected guid

The server expects this exact structure for all POST requests to
``lsa.lenovo.com/Interface/*`` endpoints.
"""

from typing import Any, Dict

from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants from LMSA analysis
# ---------------------------------------------------------------------------

DEFAULT_CLIENT_VERSION = "7.5.4.2"
DEFAULT_LANGUAGE = "en-US"
DEFAULT_WINDOWS_INFO = "Microsoft Windows 11 Pro, x64-based PC"


class RequestBuilder:
    """Builds LMSA RequestModel JSON envelopes.

    Encapsulates the standard request structure used by all LMSA API
    endpoints, matching the pattern from _build_request_model() in
    web_crawler/auth/lmsa.py.

    Args:
        guid: Device GUID to inject into all requests.
        client_version: LMSA client version string.
        language: BCP-47 language tag.
        windows_info: OS description string.
    """

    def __init__(
        self,
        guid: str = "",
        client_version: str = DEFAULT_CLIENT_VERSION,
        language: str = DEFAULT_LANGUAGE,
        windows_info: str = DEFAULT_WINDOWS_INFO,
    ) -> None:
        """Initialize the RequestBuilder.

        Args:
            guid: Device GUID to auto-inject into dparams.
            client_version: LMSA client version string.
            language: BCP-47 language tag.
            windows_info: OS description string.
        """
        self._guid = guid
        self._client_version = client_version
        self._language = language
        self._windows_info = windows_info
        self.logger = get_logger(__name__)

    def build(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Build a complete LMSA RequestModel envelope.

        Wraps the caller's parameters in the standard envelope with
        auto-injected guid (matching lmsa.py _build_request_model).

        The resulting structure matches exactly what the LMSA server expects::

            {
                "client":      {"version": "7.5.4.2"},
                "language":    "en-US",
                "windowsInfo": "Microsoft Windows 11 Pro, x64-based PC",
                "dparams": {
                    "guid": "<device-guid>",
                    ... caller params ...
                }
            }

        Args:
            params: Dictionary of API-specific parameters to include
                    in the ``dparams`` section.

        Returns:
            Complete RequestModel dictionary ready for JSON serialization.
        """
        dparams: Dict[str, Any] = dict(params)
        if self._guid:
            dparams.setdefault("guid", self._guid)

        return {
            "client": {"version": self._client_version},
            "language": self._language,
            "windowsInfo": self._windows_info,
            "dparams": dparams,
        }

    def build_login(self, guid: str, wust: str = "") -> Dict[str, Any]:
        """Build a login request body for lenovoIdLogin.jhtml.

        Login uses ``author: false`` (no guid/Authorization headers) and
        sends wust + guid in dparams. Matches the pattern from
        web_crawler/auth/lenovo_id.py.

        Args:
            guid: Device GUID for login.
            wust: WUST token from OAuth callback (empty for anonymous).

        Returns:
            RequestModel dict for login endpoint.
        """
        return self.build({
            "wust": wust,
            "guid": guid,
        })

    def build_firmware_query(
        self,
        model_name: str,
        region: str = "",
        market: str = "",
        carrier: str = "",
        flash_tool_type: str = "QComFlashTool",
        android_version: str = "",
        build_type: str = "user",
    ) -> Dict[str, Any]:
        """Build a firmware query request for getNewResource.jhtml.

        Matches the get_firmware() parameter pattern in lmsa.py.

        Args:
            model_name: Motorola model number (e.g. 'xt2553-2').
            region: Geographic region (e.g. 'US', 'RETUS', 'RETBR').
            market: Market name variant.
            carrier: Carrier variant (e.g. 'Unlocked', 'Verizon').
            flash_tool_type: Flash tool identifier (QComFlashTool, MTekFlashTool).
            android_version: Android version filter.
            build_type: Build type (user, userdebug, eng).

        Returns:
            RequestModel dict for firmware query.
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

        return self.build(params)

    def build_model_query(
        self,
        country: str = "Mexico",
        category: str = "Phone",
    ) -> Dict[str, Any]:
        """Build a model names query for getModelNames.jhtml.

        Matches get_model_names() in lmsa.py.

        Args:
            country: Country for model list.
            category: Device category ('Phone' or 'Tablet').

        Returns:
            RequestModel dict for model names query.
        """
        return self.build({
            "country": country,
            "category": category,
        })

    def build_rom_list_query(
        self,
        model_name: str = "",
        region: str = "",
        carrier: str = "",
    ) -> Dict[str, Any]:
        """Build a ROM list query for getRomList.jhtml.

        Matches get_rom_list() / get_all_roms() in lmsa.py.

        Args:
            model_name: Optional model name filter.
            region: Optional region filter.
            carrier: Optional carrier filter.

        Returns:
            RequestModel dict for ROM list query.
        """
        params: Dict[str, Any] = {}
        if model_name:
            params["modelName"] = model_name
        if region:
            params["region"] = region
        if carrier:
            params["carrier"] = carrier

        return self.build(params)

    def build_resource_query(
        self,
        model_name: str,
        market_name: str,
        **extra_params: str,
    ) -> Dict[str, Any]:
        """Build a resource query for getResource.jhtml.

        Matches get_resource() in lmsa.py with support for
        additional paramProperty resolution parameters.

        Args:
            model_name: Device model name.
            market_name: Market name from model list.
            **extra_params: Additional parameters (e.g. simCount, country).

        Returns:
            RequestModel dict for resource query.
        """
        params: Dict[str, Any] = {
            "modelName": model_name,
            "marketName": market_name,
        }
        params.update(extra_params)
        return self.build(params)

    def build_token_init(self, encrypted_guid: str) -> Dict[str, Any]:
        """Build a token initialization request for initToken.jhtml.

        The GUID is RSA-encrypted before being sent (matching
        authenticate() in lmsa.py).

        Args:
            encrypted_guid: RSA-encrypted GUID (Base64 string).

        Returns:
            RequestModel dict for token initialization.
        """
        return self.build({"guid": encrypted_guid})

    def build_link_renewal(self, file_id: str) -> Dict[str, Any]:
        """Build a download link renewal request for renewFileLink.jhtml.

        S3 pre-signed URLs expire after 7 days; this renews them.
        Matches renew_download_link() in lmsa.py.

        Args:
            file_id: File identifier for the expired link.

        Returns:
            RequestModel dict for link renewal.
        """
        return self.build({"fileId": file_id})

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_guid(self, guid: str) -> None:
        """Update the device GUID.

        Args:
            guid: New device GUID.
        """
        self._guid = guid

    @property
    def guid(self) -> str:
        """Get the current device GUID.

        Returns:
            The GUID string.
        """
        return self._guid
