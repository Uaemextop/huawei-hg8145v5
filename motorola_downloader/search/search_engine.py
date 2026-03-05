"""Firmware search engine for Motorola Firmware Downloader.

Orchestrates searches across Motorola/LMSA APIs, combining results
from multiple endpoints with deduplication, filtering, and caching.
Search patterns are based on the LMSA API endpoints documented in
web_crawler/auth/lmsa.py.

Key patterns from web_crawler analysis:
  - get_firmware(): POST to /rescueDevice/getNewResource.jhtml with
    RequestModel{dparams: {modelName, flashToolType, buildType, region, ...}}
  - get_rom_list() / get_all_roms(): POST to /priv/getRomList.jhtml
    Returns all ~2299 ROM entries with uri, name, md5, type fields.
  - get_model_names(): POST to /rescueDevice/getModelNames.jhtml
    {dparams: {country, category}} → content.models + content.moreModels
  - _resolve_resource(): recursive paramProperty resolution until S3 URLs.
  - collect_download_urls(): extracts romResource, toolResource, flashFlow,
    otaResource, countryCodeResource from resolved resources.
"""

import time
from typing import Any, Dict, List, Optional

from motorola_downloader.auth.session_manager import SessionManager
from motorola_downloader.exceptions import SearchError
from motorola_downloader.settings import Settings
from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.request_builder import RequestBuilder
from motorola_downloader.utils.url_utils import normalize_url, extract_filename, deduplicate_urls
from motorola_downloader.utils.validators import validate_content_type, validate_search_query

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# LMSA API endpoints — confirmed from web_crawler/auth/lmsa.py lines 105-117
# (WebApiUrl.cs + WebServicesContext.cs, verified via live HAR LMSA 7.5.4.2)
# ---------------------------------------------------------------------------

_EP_RSA_KEY              = "/common/rsa.jhtml"
_EP_GET_RESOURCE         = "/rescueDevice/getNewResource.jhtml"   # auto-match by hw params
_EP_GET_RESOURCE_BY_IMEI = "/rescueDevice/getNewResourceByImei.jhtml"
_EP_GET_RESOURCE_BY_SN   = "/rescueDevice/getNewResourceBySN.jhtml"
_EP_GET_MODEL_NAMES      = "/rescueDevice/getModelNames.jhtml"    # all models
_EP_GET_MARKET_NAMES     = "/rescueDevice/getRescueModelNames.jhtml"  # rescue-only
_EP_GET_RESOURCE_V2      = "/rescueDevice/getResource.jhtml"      # manual match → presigned S3
_EP_GET_RECIPE           = "/rescueDevice/getRescueModelRecipe.jhtml"
_EP_ROM_LIST             = "/priv/getRomList.jhtml"               # full ROM catalogue (~2299 items)
_EP_ROM_MATCH_PARAMS     = "/rescueDevice/getRomMatchParams.jhtml"
_EP_RENEW_LINK           = "/client/renewFileLink.jhtml"

#: Production API base URL (hardcoded, NOT configurable).
#: Confirmed: https://lsa.lenovo.com/Interface via curl + HAR.
LMSA_BASE_URL = "https://lsa.lenovo.com/Interface"

# Content type mappings
CONTENT_TYPES = {
    "firmware": "Firmware",
    "rom": "ROM",
    "tools": "Tools",
    "all": "All",
}

# Categories used by getModelNames (from lmsa.py line 122)
FIRMWARE_CATEGORIES = ("Phone", "Tablet")

# Countries confirmed from LMSA HAR (lmsa.py lines 123-128)
FIRMWARE_COUNTRIES = (
    "Mexico", "US", "Brazil", "Argentina", "Colombia", "Chile",
    "Peru", "Ecuador", "Guatemala", "Paraguay", "Dominican Republic",
    "India", "Germany", "UK", "France", "Italy", "Spain", "Australia",
    "Canada", "Japan", "China",
)

# Max recursion depth for paramProperty resolution (lmsa.py line 132)
_MAX_RESOLVE_DEPTH = 4

# Standard API success code
_CODE_OK = "0000"


class SearchResult:
    """Represents a single firmware search result.

    Attributes:
        name: Firmware or file name.
        model: Device model name.
        version: Firmware version string.
        region: Target region/country.
        download_url: URL to download the firmware.
        file_size: File size in bytes.
        release_date: Release date string.
        content_type: Type of content (Firmware, ROM, Tools).
        checksum: File checksum if available.
    """

    def __init__(
        self,
        name: str = "",
        model: str = "",
        version: str = "",
        region: str = "",
        download_url: str = "",
        file_size: int = 0,
        release_date: str = "",
        content_type: str = "Firmware",
        checksum: str = "",
    ) -> None:
        """Initialize a SearchResult.

        Args:
            name: Firmware or file name.
            model: Device model name.
            version: Firmware version string.
            region: Target region/country.
            download_url: URL to download the firmware.
            file_size: File size in bytes.
            release_date: Release date string.
            content_type: Type of content.
            checksum: File checksum if available.
        """
        self.name = name
        self.model = model
        self.version = version
        self.region = region
        self.download_url = download_url
        self.file_size = file_size
        self.release_date = release_date
        self.content_type = content_type
        self.checksum = checksum

    def to_dict(self) -> Dict[str, Any]:
        """Convert the search result to a dictionary.

        Returns:
            Dictionary representation of the search result.
        """
        return {
            "name": self.name,
            "model": self.model,
            "version": self.version,
            "region": self.region,
            "download_url": self.download_url,
            "file_size": self.file_size,
            "release_date": self.release_date,
            "content_type": self.content_type,
            "checksum": self.checksum,
        }

    def __repr__(self) -> str:
        """Return string representation of the search result.

        Returns:
            Human-readable string representation.
        """
        size_mb = self.file_size / (1024 * 1024) if self.file_size else 0
        return (
            f"[{self.content_type}] {self.name} | {self.model} | "
            f"v{self.version} | {self.region} | {size_mb:.1f} MB"
        )


class SearchEngine:
    """Firmware search engine with multi-endpoint support and caching.

    Queries Motorola/LMSA APIs to find firmware, ROMs, and tools
    matching user criteria. Supports caching, deduplication, and
    relevance-based ranking.

    Args:
        session: Authenticated session manager.
        settings: Application settings instance.
    """

    def __init__(
        self,
        session: SessionManager,
        settings: Settings,
    ) -> None:
        """Initialize the SearchEngine.

        Args:
            session: An active SessionManager for authenticated requests.
            settings: Application settings for search configuration.
        """
        self._session = session
        self._settings = settings
        self.logger = get_logger(__name__)

        # Base URL is a hardcoded constant, NOT from config
        self._base_url: str = LMSA_BASE_URL
        self._default_region: str = settings.get(
            "search", "default_region", fallback="US"
        )
        self._default_limit: int = settings.get_int(
            "search", "default_limit", fallback=50
        )
        self._include_beta: bool = settings.get_bool(
            "search", "include_beta", fallback=False
        )
        self._cache_enabled: bool = settings.get_bool(
            "search", "cache_enabled", fallback=True
        )
        self._cache_ttl: int = settings.get_int(
            "search", "cache_ttl_seconds", fallback=300
        )

        # RequestBuilder for constructing LMSA API request envelopes
        self._request_builder = RequestBuilder(
            guid=settings.get("motorola_server", "guid", fallback=""),
            client_version=settings.get("motorola_server", "client_version", fallback="7.5.4.2"),
            language=settings.get("motorola_server", "language", fallback="en-US"),
            windows_info=settings.get(
                "motorola_server", "windows_info",
                fallback="Microsoft Windows 11 Pro, x64-based PC",
            ),
        )

        # Search cache: key -> (timestamp, results)
        self._cache: Dict[str, tuple[float, List[SearchResult]]] = {}

    def search(
        self,
        query: str,
        content_type: str = "all",
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """Search for firmware, ROMs, or tools.

        Main search entry point that dispatches queries to appropriate
        API endpoints based on content type and aggregates results.

        Args:
            query: Search query (model name, version, or keyword).
            content_type: Type of content to search (firmware, rom, tools, all).
            filters: Optional search filters (region, max_size, date_from, etc.).

        Returns:
            List of SearchResult objects matching the query.

        Raises:
            SearchError: If the search operation fails.
        """
        if not validate_search_query(query):
            raise SearchError(f"Invalid search query: '{query}'")

        if not validate_content_type(content_type):
            content_type = "all"

        filters = filters or {}
        cache_key = self._build_cache_key(query, content_type, filters)

        # Check cache
        cached = self._get_cached(cache_key)
        if cached is not None:
            self.logger.info(
                "Returning %d cached results for '%s'", len(cached), query
            )
            return cached

        self.logger.info(
            "Searching for '%s' (type=%s, filters=%s)", query, content_type, filters
        )

        try:
            results: List[SearchResult] = []
            normalized_type = content_type.lower()

            if normalized_type in ("firmware", "all"):
                results.extend(self._search_firmware(query, filters))

            if normalized_type in ("rom", "all"):
                results.extend(self._search_roms(query, filters))

            if normalized_type in ("tools", "all"):
                results.extend(self._search_tools(query, filters))

            # Deduplicate
            results = self._deduplicate(results)

            # Apply filters
            results = self._apply_filters(results, filters)

            # Rank by relevance
            results = self._rank_results(results, query)

            # Limit results
            limit = filters.get("limit", self._default_limit)
            results = results[:limit]

            # Cache results
            self._set_cached(cache_key, results)

            self.logger.info(
                "Search complete: %d results for '%s'", len(results), query
            )
            return results

        except Exception as exc:
            self.logger.error("Search failed for '%s': %s", query, exc)
            raise SearchError(f"Search failed: {exc}") from exc

    def advanced_search(self, criteria: Dict[str, Any]) -> List[SearchResult]:
        """Perform an advanced search with multiple criteria.

        Args:
            criteria: Dictionary of search criteria including:
                - query: Search keyword (required)
                - model: Specific model name
                - region: Target region
                - version: Firmware version
                - content_type: Content type filter
                - date_from: Minimum release date
                - date_to: Maximum release date
                - max_size: Maximum file size in bytes

        Returns:
            List of SearchResult objects matching criteria.

        Raises:
            SearchError: If the search operation fails.
        """
        query = criteria.get("query", "")
        content_type = criteria.get("content_type", "all")
        filters = {k: v for k, v in criteria.items()
                   if k not in ("query", "content_type")}

        return self.search(query, content_type, filters)

    def get_suggestions(self, partial_query: str) -> List[str]:
        """Get search suggestions for a partial query.

        Queries the model names endpoint to provide autocompletion
        suggestions based on partial input.

        Args:
            partial_query: Partial search string for suggestions.

        Returns:
            List of suggested search terms.
        """
        if not partial_query or len(partial_query) < 2:
            return []

        self.logger.info("Getting suggestions for '%s'", partial_query)
        suggestions: List[str] = []

        try:
            models = self._get_model_names()
            partial_lower = partial_query.lower()
            suggestions = [
                model for model in models
                if partial_lower in model.lower()
            ][:10]

            self.logger.info(
                "Found %d suggestions for '%s'", len(suggestions), partial_query
            )
        except Exception as exc:
            self.logger.warning("Failed to get suggestions: %s", exc)

        return suggestions

    def get_available_regions(self) -> List[str]:
        """Get the list of available search regions.

        Returns:
            List of region name strings (from LMSA HAR traffic).
        """
        return list(FIRMWARE_COUNTRIES)

    def clear_cache(self) -> None:
        """Clear the search results cache."""
        self._cache.clear()
        self.logger.info("Search cache cleared")

    # -----------------------------------------------------------------------
    # Private search methods
    # -----------------------------------------------------------------------

    def _search_firmware(
        self, query: str, filters: Dict[str, Any]
    ) -> List[SearchResult]:
        """Search for firmware files via getNewResource.jhtml.

        Matches lmsa.py get_firmware():
          - POST /rescueDevice/getNewResource.jhtml
          - dparams: {modelName, flashToolType, buildType, region, ...}
          - Response: code "0000", then `data` field contains firmware info
            (may be AES-encrypted string or plain dict/list).

        Args:
            query: Device model name (e.g. 'xt2553-2').
            filters: Search filters (region, carrier, etc.).

        Returns:
            List of firmware SearchResult objects.
        """
        results: List[SearchResult] = []
        region = filters.get("region", self._default_region)

        try:
            headers = self._session.get_auth_headers()

            # Build RequestModel matching lmsa.py get_firmware()
            request_body = self._request_builder.build_firmware_query(
                model_name=query,
                region=region,
                carrier=filters.get("carrier", ""),
            )

            url = f"{self._base_url}{_EP_GET_RESOURCE}"
            response = self._session.http_client.post(
                url, json_data=request_body, headers=headers
            )

            # Update JWT from response (rotates on every call)
            if hasattr(self._session, 'authenticator'):
                self._session.authenticator.header_manager.update_jwt_from_response(
                    dict(response.headers)
                )

            data = response.json()
            code = data.get("code", "")

            if code == "403":
                self.logger.warning("Firmware query blocked — token required")
                return results

            if code != _CODE_OK:
                self.logger.warning("Firmware query error: %s — %s", code, data.get("msg", ""))
                return results

            # Response uses `data` field (may be AES-encrypted or plain)
            # Matching lmsa.py get_download_urls() pattern
            firmware_data = data.get("data")
            if firmware_data and isinstance(firmware_data, dict):
                results.extend(self._parse_resource_data(firmware_data, query))
            elif firmware_data and isinstance(firmware_data, list):
                for item in firmware_data:
                    if isinstance(item, dict):
                        results.extend(self._parse_resource_data(item, query))

        except Exception as exc:
            self.logger.warning("Firmware search error: %s", exc)

        return results

    def _search_roms(
        self, query: str, filters: Dict[str, Any]
    ) -> List[SearchResult]:
        """Search for ROMs via getRomList.jhtml.

        Matches lmsa.py get_all_roms():
          - POST /priv/getRomList.jhtml
          - Response: code "0000", `content` field is a list of ROM dicts.
          - Each ROM has: name, uri, type (0=ROM, 1=Tool), md5.
          - URIs may lack 'https://' scheme (normalised here).

        Args:
            query: Search query string (model name or keyword).
            filters: Search filters.

        Returns:
            List of ROM SearchResult objects.
        """
        results: List[SearchResult] = []

        try:
            headers = self._session.get_auth_headers()

            # Build RequestModel (matches lmsa.py get_rom_list / get_all_roms)
            request_body = self._request_builder.build_rom_list_query(
                model_name=query,
                region=filters.get("region", ""),
            )

            url = f"{self._base_url}{_EP_ROM_LIST}"
            response = self._session.http_client.post(
                url, json_data=request_body, headers=headers
            )

            data = response.json()
            if data.get("code") != _CODE_OK:
                self.logger.warning("ROM list error: %s — %s", data.get("code"), data.get("msg", ""))
                return results

            # Response uses `content` field (list) — from lmsa.py get_all_roms()
            rom_list = data.get("content") or []
            if not isinstance(rom_list, list):
                return results

            query_lower = query.lower()
            for rom in rom_list:
                name = rom.get("name", "")
                uri = rom.get("uri", "") or ""
                rom_type = rom.get("type", 0)  # 0=ROM, 1=Tool

                # Filter ROMs only (type=0), skip tools here
                if rom_type != 0:
                    continue

                # Filter by query if provided
                if query and query_lower not in name.lower():
                    continue

                # Normalise scheme-less URIs (lmsa.py get_all_roms pattern)
                download_url = normalize_url(uri)

                result = SearchResult(
                    name=name,
                    model=query,
                    version="",
                    region="",
                    download_url=download_url,
                    file_size=0,
                    release_date="",
                    content_type="ROM",
                    checksum=rom.get("md5", ""),
                )
                results.append(result)

        except Exception as exc:
            self.logger.warning("ROM search error: %s", exc)

        return results

    def _search_tools(
        self, query: str, filters: Dict[str, Any]
    ) -> List[SearchResult]:
        """Search for tools via getRomList.jhtml (type=1) and getResource.jhtml.

        Two sources for tools (from lmsa.py analysis):
        1. getRomList entries with type=1 are flash tools.
        2. getResource.jhtml responses contain toolResource sub-dicts.

        Args:
            query: Search query string (model name or keyword).
            filters: Search filters.

        Returns:
            List of Tools SearchResult objects.
        """
        results: List[SearchResult] = []

        try:
            headers = self._session.get_auth_headers()

            # Source 1: Tools from ROM catalogue (type=1)
            request_body = self._request_builder.build_rom_list_query(
                model_name=query,
            )

            url = f"{self._base_url}{_EP_ROM_LIST}"
            response = self._session.http_client.post(
                url, json_data=request_body, headers=headers
            )

            data = response.json()
            if data.get("code") == _CODE_OK:
                rom_list = data.get("content") or []
                if isinstance(rom_list, list):
                    query_lower = query.lower() if query else ""
                    for item in rom_list:
                        # type=1 means tool (from lmsa.py collect_download_urls_by_type)
                        if item.get("type") != 1:
                            continue
                        name = item.get("name", "")
                        if query_lower and query_lower not in name.lower():
                            continue
                        download_url = normalize_url(item.get("uri", ""))
                        result = SearchResult(
                            name=name,
                            model=query,
                            version="",
                            download_url=download_url,
                            file_size=0,
                            content_type="Tools",
                            checksum=item.get("md5", ""),
                        )
                        results.append(result)

        except Exception as exc:
            self.logger.warning("Tools search error: %s", exc)

        return results

    def _get_model_names(self) -> List[str]:
        """Fetch available model names from the API.

        Uses RequestBuilder.build_model_query() matching
        get_model_names() in lmsa.py. Combines 'models' and 'moreModels'
        lists and deduplicates by modelName (matching lmsa.py pattern).

        Returns:
            List of model name strings.
        """
        models: List[str] = []
        seen: set[str] = set()

        try:
            headers = self._session.get_auth_headers()

            for category in FIRMWARE_CATEGORIES:
                request_body = self._request_builder.build_model_query(
                    country=self._default_region,
                    category=category,
                )

                url = f"{self._base_url}{_EP_GET_MODEL_NAMES}"
                response = self._session.http_client.post(
                    url, json_data=request_body, headers=headers
                )

                data = response.json()
                if data.get("code") == _CODE_OK:
                    # Match lmsa.py: content.models + content.moreModels dedup
                    content = data.get("content") or {}
                    if isinstance(content, dict):
                        main_models = content.get("models") or []
                        more_models = content.get("moreModels") or []
                        for model_info in main_models + more_models:
                            name = model_info.get("modelName", "") or model_info.get("name", "")
                            if name and name not in seen:
                                seen.add(name)
                                models.append(name)

        except Exception as exc:
            self.logger.warning("Failed to fetch model names: %s", exc)

        return models

    def _parse_resource_data(
        self, resource: Dict[str, Any], query: str
    ) -> List[SearchResult]:
        """Parse a firmware resource dict into SearchResult objects.

        Extracts download URLs from the same resource structure that lmsa.py
        uses in collect_download_urls():
          - romResource.uri / romResource.name
          - toolResource.uri / toolResource.name
          - otaResource.uri / otaResource.name
          - countryCodeResource.uri / countryCodeResource.name
          - flashFlow (JSON download URL)

        Args:
            resource: API response resource dictionary (single item from
                `data` or resolved `content`).
            query: Original search query for context.

        Returns:
            List of SearchResult objects extracted from the resource.
        """
        results: List[SearchResult] = []
        model = resource.get("modelName") or query

        # ROM resources (firmware files)
        for res_key in ("romResource", "otaResource", "countryCodeResource"):
            res = resource.get(res_key)
            if isinstance(res, dict) and res.get("uri"):
                download_url = normalize_url(res["uri"])
                name = res.get("name") or extract_filename(download_url, f"{model}_{res_key}")
                result = SearchResult(
                    name=name,
                    model=model,
                    version=resource.get("version", ""),
                    region=resource.get("country", ""),
                    download_url=download_url,
                    file_size=int(res.get("size", 0) or 0),
                    release_date=resource.get("releaseDate", ""),
                    content_type="Firmware",
                    checksum=res.get("md5", ""),
                )
                results.append(result)

        # Tool resources (flash tools)
        tool_res = resource.get("toolResource")
        if isinstance(tool_res, dict) and tool_res.get("uri"):
            download_url = normalize_url(tool_res["uri"])
            name = tool_res.get("name") or extract_filename(download_url, f"{model}_toolResource")
            result = SearchResult(
                name=name,
                model=model,
                version=resource.get("version", ""),
                download_url=download_url,
                file_size=int(tool_res.get("size", 0) or 0),
                content_type="Tools",
                checksum=tool_res.get("md5", ""),
            )
            results.append(result)

        # Flash flow JSON
        flash_flow = resource.get("flashFlow")
        if flash_flow:
            download_url = normalize_url(flash_flow)
            if download_url:
                result = SearchResult(
                    name=f"{model}_flashFlow.json",
                    model=model,
                    version=resource.get("version", ""),
                    download_url=download_url,
                    content_type="Firmware",
                )
                results.append(result)

        # Also handle raw download URL keys (from AES-decrypted data)
        for url_key in ("downloadUrl", "url", "fileUrl", "link"):
            url_val = resource.get(url_key, "")
            if url_val:
                download_url = normalize_url(url_val)
                if download_url:
                    result = SearchResult(
                        name=extract_filename(download_url, f"{model}_firmware"),
                        model=model,
                        version=resource.get("version", ""),
                        download_url=download_url,
                        content_type="Firmware",
                    )
                    results.append(result)

        return results

    # -----------------------------------------------------------------------
    # Cache management
    # -----------------------------------------------------------------------

    def _build_cache_key(
        self, query: str, content_type: str, filters: Dict[str, Any]
    ) -> str:
        """Build a unique cache key from search parameters.

        Args:
            query: Search query.
            content_type: Content type filter.
            filters: Additional filters.

        Returns:
            Cache key string.
        """
        filter_str = "&".join(f"{k}={v}" for k, v in sorted(filters.items()))
        return f"{query}|{content_type}|{filter_str}"

    def _get_cached(self, cache_key: str) -> Optional[List[SearchResult]]:
        """Get cached search results if still valid.

        Args:
            cache_key: The cache key to look up.

        Returns:
            Cached results list, or None if not found or expired.
        """
        if not self._cache_enabled:
            return None

        if cache_key in self._cache:
            timestamp, results = self._cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return results
            del self._cache[cache_key]

        return None

    def _set_cached(self, cache_key: str, results: List[SearchResult]) -> None:
        """Store search results in the cache.

        Args:
            cache_key: The cache key.
            results: The search results to cache.
        """
        if self._cache_enabled:
            self._cache[cache_key] = (time.time(), results)

    # -----------------------------------------------------------------------
    # Result processing
    # -----------------------------------------------------------------------

    def _deduplicate(self, results: List[SearchResult]) -> List[SearchResult]:
        """Remove duplicate results based on download URL.

        Args:
            results: List of search results.

        Returns:
            Deduplicated list of search results.
        """
        seen_urls: set[str] = set()
        unique_results: List[SearchResult] = []

        for result in results:
            if result.download_url and result.download_url not in seen_urls:
                seen_urls.add(result.download_url)
                unique_results.append(result)
            elif not result.download_url:
                unique_results.append(result)

        removed = len(results) - len(unique_results)
        if removed > 0:
            self.logger.info("Removed %d duplicate results", removed)

        return unique_results

    def _apply_filters(
        self, results: List[SearchResult], filters: Dict[str, Any]
    ) -> List[SearchResult]:
        """Apply user-specified filters to search results.

        Args:
            results: List of search results to filter.
            filters: Filter criteria dictionary.

        Returns:
            Filtered list of search results.
        """
        filtered = results

        region = filters.get("region")
        if region:
            filtered = [r for r in filtered if
                        not r.region or r.region.lower() == region.lower()]

        max_size = filters.get("max_size")
        if max_size:
            filtered = [r for r in filtered if
                        r.file_size == 0 or r.file_size <= int(max_size)]

        if not self._include_beta:
            filtered = [r for r in filtered if
                        "beta" not in r.version.lower()
                        and "beta" not in r.name.lower()]

        return filtered

    def _rank_results(
        self, results: List[SearchResult], query: str
    ) -> List[SearchResult]:
        """Rank search results by relevance to the query.

        Args:
            results: List of search results.
            query: Original search query.

        Returns:
            Sorted list of search results (most relevant first).
        """
        query_lower = query.lower()

        def relevance_score(result: SearchResult) -> int:
            score = 0
            if query_lower in result.name.lower():
                score += 10
            if query_lower in result.model.lower():
                score += 8
            if query_lower in result.version.lower():
                score += 5
            if result.download_url:
                score += 3
            if result.file_size > 0:
                score += 1
            return score

        return sorted(results, key=relevance_score, reverse=True)
