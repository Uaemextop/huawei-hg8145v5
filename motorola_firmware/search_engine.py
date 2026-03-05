"""
Firmware search engine for the Motorola Firmware Downloader.

Orchestrates searches across the Motorola firmware API with result
caching, deduplication, and relevance ranking.

Connects to :class:`SessionManager` for authenticated headers and
:class:`HttpClient` for API requests.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, List, Optional

from motorola_firmware.config import (
    DEFAULT_SEARCH_LIMIT,
    EP_FIRMWARE_SEARCH,
    EP_FIRMWARE_SUGGEST,
    MAX_CACHE_SIZE,
)
from motorola_firmware.exceptions import SearchError
from motorola_firmware.http_client import HttpClient
from motorola_firmware.session_manager import SessionManager
from motorola_firmware.settings import Settings
from motorola_firmware.utils.logger import log
from motorola_firmware.utils.validators import validate_content_type, validate_search_query


class SearchResult:
    """Represents a single firmware search result.

    Attributes:
        name: File or firmware name.
        version: Firmware version string.
        device_model: Target device model.
        content_type: Type of content (firmware, rom, tools).
        size_bytes: File size in bytes.
        download_url: Direct download URL.
        release_date: Release date string.
        region: Target region.
        is_beta: Whether this is a beta release.
        checksum: File checksum if available.
    """

    def __init__(
        self,
        name: str,
        version: str = "",
        device_model: str = "",
        content_type: str = "firmware",
        size_bytes: int = 0,
        download_url: str = "",
        release_date: str = "",
        region: str = "global",
        is_beta: bool = False,
        checksum: str = "",
    ) -> None:
        """Initialize a search result.

        Args:
            name: File or firmware name.
            version: Firmware version.
            device_model: Target device model.
            content_type: Content type classification.
            size_bytes: File size.
            download_url: Download URL.
            release_date: Release date.
            region: Target region.
            is_beta: Beta release flag.
            checksum: File checksum.
        """
        self.name = name
        self.version = version
        self.device_model = device_model
        self.content_type = content_type
        self.size_bytes = size_bytes
        self.download_url = download_url
        self.release_date = release_date
        self.region = region
        self.is_beta = is_beta
        self.checksum = checksum

    def to_dict(self) -> Dict[str, Any]:
        """Convert the search result to a dictionary.

        Returns:
            Dictionary representation of the search result.
        """
        return {
            "name": self.name,
            "version": self.version,
            "device_model": self.device_model,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "download_url": self.download_url,
            "release_date": self.release_date,
            "region": self.region,
            "is_beta": self.is_beta,
            "checksum": self.checksum,
        }

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> SearchResult:
        """Create a SearchResult from an API response dictionary.

        Handles multiple field name variants to accommodate different
        API response formats.

        Args:
            data: Dictionary with search result fields.

        Returns:
            A new SearchResult instance.
        """
        return cls(
            name=data.get("name", ""),
            version=data.get("version", ""),
            device_model=data.get("device_model", data.get("model", "")),
            content_type=data.get("content_type", data.get("type", "firmware")),
            size_bytes=int(data.get("size_bytes", data.get("size", 0))),
            download_url=data.get("download_url", data.get("url", "")),
            release_date=data.get("release_date", data.get("date", "")),
            region=data.get("region", "global"),
            is_beta=bool(data.get("is_beta", data.get("beta", False))),
            checksum=data.get("checksum", ""),
        )

    def __repr__(self) -> str:
        """Return string representation of the search result."""
        return (
            f"SearchResult(name='{self.name}', version='{self.version}', "
            f"model='{self.device_model}', type='{self.content_type}')"
        )


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable units.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Formatted size string (e.g., '1.5 MB').
    """
    if size_bytes == 0:
        return "Unknown"
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


class SearchEngine:
    """Orchestrates firmware searches across the Motorola API.

    Provides search, advanced search, and suggestion functionality with
    result caching and deduplication.

    All network calls go through :class:`SessionManager` (for auth headers)
    and :class:`HttpClient` (for the actual HTTP transport).

    Args:
        settings: Application settings instance.
        session_manager: Session manager for authenticated requests.
        http_client: HTTP client for API requests.
    """

    def __init__(
        self,
        settings: Settings,
        session_manager: SessionManager,
        http_client: HttpClient,
    ) -> None:
        """Initialize the search engine.

        Args:
            settings: Application settings.
            session_manager: Authenticated session manager.
            http_client: HTTP client for requests.
        """
        self._settings = settings
        self._session_manager = session_manager
        self._http_client = http_client
        self._cache: OrderedDict[str, List[SearchResult]] = OrderedDict()

    def search(
        self,
        query: str,
        content_type: str = "all",
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """Search for firmware, ROMs, or tools.

        Args:
            query: Search query (device model, version, etc.).
            content_type: Filter by type: firmware, rom, tools, or all.
            filters: Optional additional filters (region, max_size,
                include_beta, release_date).

        Returns:
            List of SearchResult objects matching the query.

        Raises:
            SearchError: If the search request fails.
        """
        if not validate_search_query(query):
            raise SearchError("Invalid search query")
        if not validate_content_type(content_type):
            raise SearchError(f"Invalid content type: {content_type}")

        # Check cache
        cache_key = self._build_cache_key(query, content_type, filters)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            log.info("[SEARCH] Returning %d cached results for '%s'",
                     len(cached), query)
            return cached

        log.info("[SEARCH] Searching for '%s' (type: %s)", query, content_type)

        try:
            headers = self._session_manager.get_authenticated_headers()
            self._http_client.set_headers(headers)

            base_url = self._settings.get("motorola_server", "base_url")
            search_url = f"{base_url}{EP_FIRMWARE_SEARCH}"

            params: Dict[str, Any] = {
                "q": query,
                "type": content_type,
                "limit": self._settings.get_int("search", "default_limit",
                                                DEFAULT_SEARCH_LIMIT),
            }
            if filters:
                params.update(self._filters_to_params(filters))
            if "region" not in params:
                params["region"] = self._settings.get("search", "default_region", "global")

            response = self._http_client.get(search_url, params=params)
            data = response.json()

            results = self._parse_results(data)
            results = self._deduplicate(results)
            results = self._apply_local_filters(results, filters)
            results = self._rank_results(results, query)

            self._add_to_cache(cache_key, results)
            log.info("[SEARCH] Found %d results for '%s'", len(results), query)
            return results

        except SearchError:
            raise
        except Exception as error:
            log.error("[SEARCH] Search failed for '%s': %s", query, error)
            raise SearchError(f"Search failed: {error}") from error

    def advanced_search(self, criteria: Dict[str, Any]) -> List[SearchResult]:
        """Perform an advanced search with multiple criteria.

        Args:
            criteria: Dictionary of search criteria. Must include ``query``.
                Optional keys: content_type, device_model, version, region,
                max_size, include_beta, release_date_from, release_date_to.

        Returns:
            List of matching SearchResult objects.

        Raises:
            SearchError: If the search fails or criteria is invalid.
        """
        query = criteria.get("query", "")
        if not query:
            raise SearchError("Search criteria must include a query")

        content_type = criteria.get("content_type", "all")
        filters: Dict[str, Any] = {}
        for key in ("device_model", "version", "region", "max_size",
                     "include_beta", "release_date_from", "release_date_to"):
            if key in criteria:
                filters[key] = criteria[key]

        return self.search(query, content_type, filters)

    def get_suggestions(self, partial_query: str) -> List[str]:
        """Get search suggestions based on a partial query.

        Args:
            partial_query: The partial search text.

        Returns:
            List of suggested search terms.
        """
        if not partial_query or len(partial_query.strip()) < 2:
            return []

        try:
            headers = self._session_manager.get_authenticated_headers()
            self._http_client.set_headers(headers)

            base_url = self._settings.get("motorola_server", "base_url")
            suggest_url = f"{base_url}{EP_FIRMWARE_SUGGEST}"

            response = self._http_client.get(
                suggest_url, params={"q": partial_query.strip()}
            )
            data = response.json()
            suggestions = data.get("suggestions", [])
            log.debug("[SEARCH] %d suggestions for '%s'",
                      len(suggestions), partial_query)
            return suggestions
        except Exception as error:
            log.warning("[SEARCH] Suggestions failed: %s", error)
            return []

    # ── Internal helpers ───────────────────────────────────────────

    def _filters_to_params(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Convert filter dictionary to API query parameters."""
        mapping = {
            "device_model": "model",
            "version": "version",
            "region": "region",
            "include_beta": "beta",
            "release_date_from": "date_from",
            "release_date_to": "date_to",
        }
        params: Dict[str, Any] = {}
        for user_key, api_key in mapping.items():
            if user_key in filters and filters[user_key] is not None:
                params[api_key] = filters[user_key]
        return params

    def _parse_results(self, data: Dict[str, Any]) -> List[SearchResult]:
        """Parse API response data into SearchResult objects."""
        results: List[SearchResult] = []
        items = data.get("results", data.get("items", []))
        for item in items:
            try:
                results.append(SearchResult.from_api_response(item))
            except (KeyError, ValueError) as error:
                log.warning("[SEARCH] Failed to parse result: %s", error)
        return results

    def _deduplicate(self, results: List[SearchResult]) -> List[SearchResult]:
        """Remove duplicate results based on name+version+model."""
        seen: set = set()
        unique: List[SearchResult] = []
        for result in results:
            key = (result.name.lower(), result.version.lower(),
                   result.device_model.lower())
            if key not in seen:
                seen.add(key)
                unique.append(result)
        removed = len(results) - len(unique)
        if removed > 0:
            log.debug("[SEARCH] Removed %d duplicate results", removed)
        return unique

    def _apply_local_filters(
        self,
        results: List[SearchResult],
        filters: Optional[Dict[str, Any]],
    ) -> List[SearchResult]:
        """Apply post-processing filters to results."""
        if not filters:
            return results

        filtered = results

        max_size = filters.get("max_size")
        if max_size is not None:
            filtered = [r for r in filtered
                        if r.size_bytes == 0 or r.size_bytes <= int(max_size)]

        include_beta = filters.get(
            "include_beta",
            self._settings.get_bool("search", "include_beta", False),
        )
        if not include_beta:
            filtered = [r for r in filtered if not r.is_beta]

        return filtered

    def _rank_results(self, results: List[SearchResult], query: str) -> List[SearchResult]:
        """Rank search results by relevance to the query."""
        query_lower = query.lower()

        def score(result: SearchResult) -> int:
            s = 0
            if query_lower in result.name.lower():
                s += 10
            if query_lower in result.device_model.lower():
                s += 8
            if query_lower == result.name.lower():
                s += 20
            if query_lower == result.device_model.lower():
                s += 15
            if not result.is_beta:
                s += 2
            return s

        return sorted(results, key=score, reverse=True)

    def _build_cache_key(
        self, query: str, content_type: str, filters: Optional[Dict[str, Any]]
    ) -> str:
        """Build a cache key from search parameters."""
        parts = [query.lower().strip(), content_type.lower()]
        if filters:
            parts.append(str(sorted(filters.items())))
        return "|".join(parts)

    def _get_from_cache(self, key: str) -> Optional[List[SearchResult]]:
        """Get cached search results."""
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def _add_to_cache(self, key: str, results: List[SearchResult]) -> None:
        """Add search results to cache (evict oldest if full)."""
        if len(self._cache) >= MAX_CACHE_SIZE:
            self._cache.popitem(last=False)
        self._cache[key] = results
