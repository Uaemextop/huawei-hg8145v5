"""Firmware search engine for Motorola Firmware Downloader.

Orchestrates searches across Motorola/LMSA APIs, combining results
from multiple endpoints with deduplication, filtering, and caching.
Delegates all API calls to LMSAClient (api_client.py) which implements
all 16 LMSA endpoints with correct request body and header handling.

Multi-variant search:
  When the user searches for a Motorola codename like "lamu", the engine
  automatically expands it into known variants (lamu, lamuc, lamug,
  lamumite, …) and queries each against the firmware API with multiple
  flash-tool types (QComFlashTool, MTekFlashTool, …).  The ROM
  catalogue and tools searches also match all variants.
"""

import time
from typing import Any, Dict, List, Optional, Set

from motorola_downloader.utils.api_client import (
    LMSAClient,
    LMSA_BASE_URLS,
    FIRMWARE_COUNTRIES,
    FIRMWARE_CATEGORIES,
)
from motorola_downloader.auth.session_manager import SessionManager
from motorola_downloader.exceptions import SearchError
from motorola_downloader.settings import Settings
from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.url_utils import normalize_url, extract_filename, deduplicate_urls
from motorola_downloader.utils.validators import validate_content_type, validate_search_query

_logger = get_logger(__name__)

# Content type mappings
CONTENT_TYPES = {
    "firmware": "Firmware",
    "rom": "ROM",
    "tools": "Tools",
    "all": "All",
}

# Flash tool types observed in LMSA traffic.  The firmware API returns
# different (or no) results depending on which tool is requested.
FLASH_TOOL_TYPES = (
    "QComFlashTool",
    "MTekFlashTool",
    "MTekSpFlashTool",
    "QFileTool",
    "PnPTool",
)


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

        # LMSAClient — delegates all API calls to the centralised client
        # which implements all 16 endpoints with correct headers/body
        self._api = LMSAClient(
            header_manager=session.authenticator.header_manager,
            request_builder=session.authenticator._request_builder,
            http_client=session.http_client,
        )

        # All base URLs to query (production + test server)
        self._base_urls = LMSA_BASE_URLS

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

    def search_by_imei(self, imei: str) -> List[SearchResult]:
        """Search firmware by IMEI number.

        Uses /rescueDevice/getNewResourceByImei.jhtml endpoint.

        Args:
            imei: Device IMEI number (15 digits).

        Returns:
            List of SearchResult objects.
        """
        results: List[SearchResult] = []
        try:
            data = self._api.get_firmware_by_imei(imei)
            if data:
                fw = data.get("data")
                if isinstance(fw, dict):
                    results.extend(self._parse_resource_data(fw, imei))
        except Exception as exc:
            self.logger.warning("IMEI search error: %s", exc)
        return results

    def search_by_serial(self, serial_number: str) -> List[SearchResult]:
        """Search firmware by serial number.

        Uses /rescueDevice/getNewResourceBySN.jhtml endpoint.

        Args:
            serial_number: Device serial number.

        Returns:
            List of SearchResult objects.
        """
        results: List[SearchResult] = []
        try:
            data = self._api.get_firmware_by_serial(serial_number)
            if data:
                fw = data.get("data")
                if isinstance(fw, dict):
                    results.extend(self._parse_resource_data(fw, serial_number))
        except Exception as exc:
            self.logger.warning("Serial number search error: %s", exc)
        return results

    def get_rescue_models(self, country: str = "") -> List[Dict[str, Any]]:
        """Get rescue-only device models.

        Uses /rescueDevice/getRescueModelNames.jhtml endpoint.

        Args:
            country: Country for model list.

        Returns:
            List of rescue model info dicts.
        """
        country = country or self._default_region
        return self._api.get_rescue_model_names(country=country)

    def get_rescue_recipe(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get rescue recipe for a device model.

        Uses /rescueDevice/getRescueModelRecipe.jhtml endpoint.

        Args:
            model_name: Device model name.

        Returns:
            Response dict on success, None on failure.
        """
        return self._api.get_rescue_recipe(model_name)

    def get_rom_match_params(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get ROM match parameters for a device.

        Uses /rescueDevice/getRomMatchParams.jhtml endpoint.

        Args:
            model_name: Device model name.

        Returns:
            Response dict on success, None on failure.
        """
        return self._api.get_rom_match_params(model_name)

    def get_presigned_resource(
        self,
        model_name: str,
        market_name: str,
        **extra_params: str,
    ) -> List[SearchResult]:
        """Get fully resolved firmware with pre-signed S3 URLs.

        Uses /rescueDevice/getResource.jhtml with recursive
        paramProperty resolution (matching lmsa.py _resolve_resource).

        Args:
            model_name: Device model name.
            market_name: Market name from model list.
            **extra_params: Additional params (e.g. simCount, country).

        Returns:
            List of SearchResult objects with pre-signed S3 download URLs.
        """
        results: List[SearchResult] = []
        try:
            items = self._api.resolve_resource(
                model_name, market_name, **extra_params
            )
            for item in items:
                results.extend(self._parse_resource_data(item, model_name))
        except Exception as exc:
            self.logger.warning("Presigned resource error: %s", exc)
        return results

    def renew_download_link(self, file_id: str) -> Optional[str]:
        """Renew an expired S3 pre-signed download URL.

        Uses /client/renewFileLink.jhtml endpoint.

        Args:
            file_id: File identifier for the expired link.

        Returns:
            New download URL string, or None on failure.
        """
        return self._api.renew_download_link(file_id)

    @property
    def api_client(self) -> LMSAClient:
        """Get the underlying LMSAClient for direct API access.

        Returns:
            The LMSAClient instance.
        """
        return self._api

    def clear_cache(self) -> None:
        """Clear the search results cache."""
        self._cache.clear()
        self.logger.info("Search cache cleared")

    # -----------------------------------------------------------------------
    # Model variant expansion
    # -----------------------------------------------------------------------

    @staticmethod
    def _expand_model_variants(query: str) -> List[str]:
        """Expand a model codename or XT number into known variants.

        Motorola uses codename families where the base name is shared
        across regional/carrier/chipset variants.  For example the
        "lamu" family includes: lamu, lamuc, lamug, lamumite.

        For XT model numbers (e.g. ``xt2523``), the engine generates
        dash-number suffixes: xt2523-1, xt2523-2, …, xt2523-10.
        If the user already provides a full XT number like ``xt2523-2``,
        the base is extracted and all siblings are included.

        The expansion algorithm:
          1. Always include the original query.
          2. If the query looks like an XT model number (``xt`` + digits,
             optionally followed by ``-N``), generate ``xt…-1`` to
             ``xt…-10``.
          3. Otherwise append common Motorola codename suffixes (c, g,
             mite, ds, f, p, s, plus, lite, ultra).
          4. Return a deduplicated, ordered list.

        Args:
            query: User-provided model name or codename.

        Returns:
            List of model name variants to search (always ≥ 1 item).
        """
        import re

        base = query.strip().lower()
        if not base:
            return [query]

        # XT model number pattern: "xt" + digits, optionally "-N"
        xt_match = re.match(r'^(xt\d+)(?:-\d+)?$', base)
        if xt_match:
            xt_base = xt_match.group(1)
            variants: list[str] = [base]
            for n in range(1, 11):
                candidate = f"{xt_base}-{n}"
                if candidate not in variants:
                    variants.append(candidate)
            return variants

        # Codename expansion: common Motorola suffixes
        _SUFFIXES = ("c", "g", "mite", "ds", "f", "p", "s",
                     "plus", "lite", "ultra")

        variants = [base]
        for suffix in _SUFFIXES:
            candidate = base + suffix
            if candidate != base:
                variants.append(candidate)

        return variants

    # -----------------------------------------------------------------------
    # Private search methods — delegate to LMSAClient
    # -----------------------------------------------------------------------

    def _search_firmware(
        self, query: str, filters: Dict[str, Any]
    ) -> List[SearchResult]:
        """Search for firmware across both LMSA hosts and all regions.

        Implements the full resolution chain observed in HAR traffic,
        querying **both** ``lsa.lenovo.com`` and ``lsatest.lenovo.com``
        with **all** known countries/categories:

          1. ``getModelNames`` for every country × category (Phone,
             Tablet) — find matching models.
          2. Reverse-map codenames → XT numbers via ROM catalogue.
          3. ``resolve_resource`` per model (simCount → country → S3).
          4. Fallback: ``getNewResource`` per variant × flash-tool.
          5. IMEI / serial number search.

        All steps run against each host, results are merged and
        deduplicated by download URL.

        Args:
            query: Device model name, codename, or market name.
            filters: Search filters (region, carrier, imei, serial, …).

        Returns:
            List of firmware SearchResult objects.
        """
        results: List[SearchResult] = []
        carrier = filters.get("carrier", "")
        seen_urls: Set[str] = set()

        variants = self._expand_model_variants(query)
        query_lower = query.strip().lower()

        original_base = self._api.base_url
        try:
            for host_url in self._base_urls:
                self._api.base_url = host_url
                host_tag = "prod" if "lsatest" not in host_url else "test"

                # ── Step 1: discover models across ALL regions ────────
                matched_models: List[Dict[str, str]] = []
                try:
                    # Use all known countries for maximum coverage
                    for country in FIRMWARE_COUNTRIES:
                        for category in FIRMWARE_CATEGORIES:
                            try:
                                model_list = self._api.get_model_names(
                                    country=country, category=category,
                                )
                            except Exception:
                                continue
                            for m in model_list:
                                mn = (m.get("modelName") or "").lower()
                                mk = (m.get("marketName") or "").lower()
                                if (any(v in mn for v in variants)
                                        or query_lower in mk
                                        or query_lower in mn):
                                    pair = {
                                        "modelName": m.get("modelName", ""),
                                        "marketName": m.get("marketName", ""),
                                    }
                                    if pair not in matched_models:
                                        matched_models.append(pair)
                except Exception as exc:
                    self.logger.debug(
                        "Model name lookup failed on %s: %s", host_tag, exc,
                    )

                # ── Step 1b: reverse-map codename → XT model ─────────
                if not matched_models:
                    try:
                        import re
                        xt_numbers: Set[str] = set()
                        roms = self._api.get_all_roms()
                        variant_set = {v.lower() for v in variants}
                        for rom in roms:
                            name = (rom.get("name") or "").lower()
                            if any(v in name for v in variant_set):
                                for m in re.finditer(
                                    r'xt\d+-\d+', name, re.IGNORECASE
                                ):
                                    xt_numbers.add(m.group(0).upper())

                        if xt_numbers:
                            self.logger.info(
                                "Reverse-mapped '%s' → %s",
                                query, ", ".join(sorted(xt_numbers)),
                            )
                            for country in FIRMWARE_COUNTRIES:
                                for category in FIRMWARE_CATEGORIES:
                                    try:
                                        model_list = self._api.get_model_names(
                                            country=country,
                                            category=category,
                                        )
                                    except Exception:
                                        continue
                                    for m_info in model_list:
                                        mn = m_info.get("modelName") or ""
                                        if mn.upper() in xt_numbers:
                                            pair = {
                                                "modelName": mn,
                                                "marketName": m_info.get(
                                                    "marketName", ""
                                                ),
                                            }
                                            if pair not in matched_models:
                                                matched_models.append(pair)
                    except Exception as exc:
                        self.logger.debug(
                            "Codename reverse-map failed: %s", exc,
                        )

                if matched_models:
                    self.logger.info(
                        "[%s] '%s': %d matching models",
                        host_tag, query, len(matched_models),
                    )

                # ── Step 2: resolve each model ────────────────────────
                for pair in matched_models:
                    try:
                        resolved = self._api.resolve_resource(
                            pair["modelName"], pair["marketName"],
                        )
                        for item in resolved:
                            for r in self._parse_resource_data(item, query):
                                if r.download_url and r.download_url not in seen_urls:
                                    seen_urls.add(r.download_url)
                                    results.append(r)
                    except Exception:
                        pass

                # ── Step 3: fallback — getNewResource ─────────────────
                try:
                    for variant in variants:
                        for flash_tool in FLASH_TOOL_TYPES:
                            data = self._api.get_firmware(
                                model_name=variant,
                                carrier=carrier,
                                flash_tool_type=flash_tool,
                            )
                            if not data:
                                continue
                            firmware_data = data.get("data")
                            if firmware_data and isinstance(firmware_data, dict):
                                for r in self._parse_resource_data(
                                    firmware_data, variant
                                ):
                                    if r.download_url not in seen_urls:
                                        seen_urls.add(r.download_url)
                                        results.append(r)
                            elif firmware_data and isinstance(firmware_data, list):
                                for item in firmware_data:
                                    if isinstance(item, dict):
                                        for r in self._parse_resource_data(
                                            item, variant
                                        ):
                                            if r.download_url not in seen_urls:
                                                seen_urls.add(r.download_url)
                                                results.append(r)
                except Exception:
                    pass

        finally:
            self._api.base_url = original_base

        # ── Step 4: IMEI / serial number search ───────────────────────
        try:
            imei = filters.get("imei", "")
            if imei:
                imei_data = self._api.get_firmware_by_imei(imei)
                if imei_data:
                    fw = imei_data.get("data")
                    if isinstance(fw, dict):
                        results.extend(self._parse_resource_data(fw, query))

            serial = filters.get("serial", "")
            if serial:
                sn_data = self._api.get_firmware_by_serial(serial)
                if sn_data:
                    fw = sn_data.get("data")
                    if isinstance(fw, dict):
                        results.extend(self._parse_resource_data(fw, query))
        except Exception:
            pass

        return results

    def _search_roms(
        self, query: str, filters: Dict[str, Any]
    ) -> List[SearchResult]:
        """Search for ROMs across both LMSA hosts.

        Queries the ROM catalogue (``getRomList.jhtml``) on each host
        and matches codename variants so that ``'lamu'`` also finds
        ``fastboot_lamuc_*``, ``fastboot_lamug_*``, etc.

        Args:
            query: Search query string (model name or keyword).
            filters: Search filters.

        Returns:
            List of ROM SearchResult objects (deduplicated by name).
        """
        results: List[SearchResult] = []
        seen_names: Set[str] = set()
        variants = self._expand_model_variants(query)
        variant_set = {v.lower() for v in variants}

        original_base = self._api.base_url
        try:
            for host_url in self._base_urls:
                self._api.base_url = host_url
                try:
                    roms = self._api.get_all_roms()
                except Exception:
                    continue

                for rom in roms:
                    name = rom.get("name", "")
                    uri = rom.get("uri", "") or ""
                    rom_type = rom.get("type", 0)

                    if rom_type != 0:
                        continue

                    name_lower = name.lower()
                    if query and not any(v in name_lower for v in variant_set):
                        continue

                    if name in seen_names:
                        continue
                    seen_names.add(name)

                    download_url = normalize_url(uri)
                    result = SearchResult(
                        name=name,
                        model=query,
                        download_url=download_url,
                        content_type="ROM",
                        checksum=rom.get("md5", ""),
                    )
                    results.append(result)
        except Exception as exc:
            self.logger.warning("ROM search error: %s", exc)
        finally:
            self._api.base_url = original_base

        return results

    def _search_tools(
        self, query: str, filters: Dict[str, Any]
    ) -> List[SearchResult]:
        """Search for tools across both LMSA hosts.

        Queries ROM catalogue tools (``type=1``) and plugin URLs on
        each host.  Matches codename variants.

        Args:
            query: Search query string.
            filters: Search filters.

        Returns:
            List of Tools SearchResult objects (deduplicated by name).
        """
        results: List[SearchResult] = []
        seen_names: Set[str] = set()
        variants = self._expand_model_variants(query)
        variant_set = {v.lower() for v in variants}

        original_base = self._api.base_url
        try:
            for host_url in self._base_urls:
                self._api.base_url = host_url
                try:
                    roms = self._api.get_all_roms()
                except Exception:
                    roms = []

                for item in roms:
                    if item.get("type") != 1:
                        continue
                    name = item.get("name", "")
                    name_lower = name.lower()
                    if query and not any(v in name_lower for v in variant_set):
                        continue
                    if name in seen_names:
                        continue
                    seen_names.add(name)
                    download_url = normalize_url(item.get("uri", ""))
                    result = SearchResult(
                        name=name,
                        model=query,
                        download_url=download_url,
                        content_type="Tools",
                        checksum=item.get("md5", ""),
                    )
                    results.append(result)

                try:
                    plugin_urls = self._api.get_plugin_urls()
                    query_lower = query.lower() if query else ""
                    for url, name in plugin_urls:
                        if query_lower and query_lower not in name.lower():
                            continue
                        if name in seen_names:
                            continue
                        seen_names.add(name)
                        result = SearchResult(
                            name=name,
                            download_url=url,
                            content_type="Tools",
                        )
                        results.append(result)
                except Exception:
                    pass
        except Exception as exc:
            self.logger.warning("Tools search error: %s", exc)
        finally:
            self._api.base_url = original_base

        return results

    def _get_model_names(self) -> List[str]:
        """Fetch available model names via LMSAClient.get_model_names().

        Delegates to api_client.py which handles combining
        models + moreModels and deduplicating by modelName.

        Returns:
            List of model name strings.
        """
        models: List[str] = []

        try:
            from motorola_downloader.utils.api_client import FIRMWARE_CATEGORIES
            for category in FIRMWARE_CATEGORIES:
                model_list = self._api.get_model_names(
                    country=self._default_region,
                    category=category,
                )
                for model_info in model_list:
                    name = model_info.get("modelName", "")
                    if name and name not in models:
                        models.append(name)

        except Exception as exc:
            self.logger.warning("Failed to fetch model names: %s", exc)

        return models

    def _parse_resource_data(
        self, resource: Dict[str, Any], query: str
    ) -> List[SearchResult]:
        """Parse a firmware resource dict into SearchResult objects.

        Extracts download URLs from the resolved resource structure
        (confirmed via HAR capture of ``getResource.jhtml``):

          - ``romResource``: firmware ZIP (``fastboot_lamu_g_…``)
          - ``toolResource``: flash tool (``Lamu_Flash_Tool_Console_…``)
          - ``otaResource`` / ``countryCodeResource``: OTA / regional
          - ``flashFlow``: flash-flow JSON URL

        Metadata fields used:
          - ``modelName``, ``marketName``, ``fingerPrint`` (version),
            ``comments`` (region/carrier notes), ``platform`` (MTK/QCom),
            ``romResource.publishDate``.

        Args:
            resource: API response resource dictionary (single item from
                ``data`` or resolved ``content``).
            query: Original search query for context.

        Returns:
            List of SearchResult objects extracted from the resource.
        """
        results: List[SearchResult] = []
        model = resource.get("modelName") or query
        market = resource.get("marketName") or ""

        # Extract version from fingerPrint if available
        # e.g. "motorola/lamul_g/lamul:15/VVTAS35.51-137-2-1/c99c2a:user/release-keys"
        fp = resource.get("fingerPrint") or ""
        version = resource.get("version", "")
        if not version and fp:
            parts = fp.split("/")
            if len(parts) >= 4:
                version = parts[3]  # e.g. "VVTAS35.51-137-2-1"

        # Region from comments or resolved chain
        region = resource.get("country", "") or resource.get("comments", "")
        platform = resource.get("platform", "")
        release_date = ""

        # ROM resources (firmware files)
        for res_key in ("romResource", "otaResource", "countryCodeResource"):
            res = resource.get(res_key)
            if isinstance(res, dict) and res.get("uri"):
                download_url = normalize_url(res["uri"])
                name = res.get("name") or extract_filename(
                    download_url, f"{model}_{res_key}"
                )
                pub_date = res.get("publishDate") or release_date
                result = SearchResult(
                    name=name,
                    model=f"{model} ({market})" if market else model,
                    version=version,
                    region=region,
                    download_url=download_url,
                    file_size=int(res.get("size", 0) or 0),
                    release_date=pub_date,
                    content_type="Firmware",
                    checksum=res.get("md5", ""),
                )
                results.append(result)

        # Tool resources (flash tools — QComFlashTool, MTekFlashTool, etc.)
        tool_res = resource.get("toolResource")
        if isinstance(tool_res, dict) and tool_res.get("uri"):
            download_url = normalize_url(tool_res["uri"])
            name = tool_res.get("name") or extract_filename(
                download_url, f"{model}_toolResource"
            )
            tool_type = f"FlashTool ({platform})" if platform else "FlashTool"
            result = SearchResult(
                name=name,
                model=f"{model} ({market})" if market else model,
                version=version,
                download_url=download_url,
                file_size=int(tool_res.get("size", 0) or 0),
                content_type=tool_type,
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
                    model=f"{model} ({market})" if market else model,
                    version=version,
                    download_url=download_url,
                    content_type="FlashFlow",
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
                        version=version,
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
