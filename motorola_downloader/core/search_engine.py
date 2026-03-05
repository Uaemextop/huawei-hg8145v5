"""Search engine for Motorola firmware files.

Orchestrates searches across the Motorola API, with filtering,
deduplication, and ranking capabilities.
"""

from typing import Any, Dict, List, Optional

from motorola_downloader.core.authenticator import Authenticator
from motorola_downloader.core.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger


class SearchResult:
    """Represents a firmware search result."""

    def __init__(
        self,
        model: str,
        version: str,
        region: str,
        download_url: str,
        file_size: int = 0,
        release_date: Optional[str] = None,
        description: Optional[str] = None,
        content_type: str = "firmware",
    ) -> None:
        """Initialize search result.

        Args:
            model: Device model name
            version: Firmware version
            region: Geographic region
            download_url: Download URL
            file_size: File size in bytes
            release_date: Release date string
            description: Result description
            content_type: Type (firmware, rom, tools)
        """
        self.model = model
        self.version = version
        self.region = region
        self.download_url = download_url
        self.file_size = file_size
        self.release_date = release_date
        self.description = description
        self.content_type = content_type

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "model": self.model,
            "version": self.version,
            "region": self.region,
            "download_url": self.download_url,
            "file_size": self.file_size,
            "release_date": self.release_date,
            "description": self.description,
            "content_type": self.content_type,
        }


class SearchEngine:
    """Firmware search engine.

    Searches for firmware, ROMs, and tools across Motorola APIs
    with filtering and ranking.
    """

    def __init__(
        self,
        base_url: str,
        authenticator: Authenticator,
        http_client: HTTPClient,
        cache_enabled: bool = True,
    ) -> None:
        """Initialize search engine.

        Args:
            base_url: Motorola server base URL
            authenticator: Authenticator instance
            http_client: HTTP client instance
            cache_enabled: Whether to cache search results
        """
        self.base_url = base_url.rstrip("/")
        self.authenticator = authenticator
        self.http_client = http_client
        self.cache_enabled = cache_enabled
        self.logger = get_logger(__name__)

        # Search cache
        self._cache: Dict[str, List[SearchResult]] = {}

    def search(
        self,
        query: str,
        content_type: str = "all",
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 50,
    ) -> List[SearchResult]:
        """Search for firmware/ROM/tools.

        Args:
            query: Search query (model name, version, etc.)
            content_type: Type to search (firmware, rom, tools, all)
            filters: Optional filters (region, min_size, max_size, date_from, date_to)
            limit: Maximum results to return

        Returns:
            List of SearchResult objects
        """
        # Check cache
        cache_key = f"{query}:{content_type}:{filters}"
        if self.cache_enabled and cache_key in self._cache:
            self.logger.info(f"Returning cached results for: {query}")
            cached = self._cache[cache_key]
            return cached[:limit]

        self.logger.info(
            f"Searching for '{query}' (type: {content_type}, limit: {limit})"
        )

        results: List[SearchResult] = []

        try:
            # Build search endpoint
            endpoint = f"{self.base_url}/api/search"

            # Build request parameters
            params = {
                "query": query,
                "limit": limit,
            }

            if content_type != "all":
                params["type"] = content_type

            # Add filters
            if filters:
                if "region" in filters:
                    params["region"] = filters["region"]
                if "min_size" in filters:
                    params["min_size"] = filters["min_size"]
                if "max_size" in filters:
                    params["max_size"] = filters["max_size"]
                if "date_from" in filters:
                    params["date_from"] = filters["date_from"]
                if "date_to" in filters:
                    params["date_to"] = filters["date_to"]
                if "beta" in filters:
                    params["include_beta"] = filters["beta"]

            # Get authentication headers
            headers = self.authenticator.get_headers()

            # Perform search request
            response = self.http_client.get(
                endpoint,
                params=params,
                headers=headers,
            )

            if not response:
                self.logger.error("Search request failed")
                return []

            # Parse response
            data = response.json()

            if data.get("code") == "0000" or data.get("success"):
                items = data.get("results") or data.get("items") or []

                for item in items:
                    result = self._parse_search_result(item)
                    if result:
                        results.append(result)

                self.logger.info(f"Found {len(results)} results")

            else:
                error = data.get("message") or data.get("error") or "Unknown error"
                self.logger.error(f"Search failed: {error}")

        except Exception as e:
            self.logger.error(f"Search error: {e}")

        # Apply filters
        results = self._apply_filters(results, filters)

        # Deduplicate
        results = self._deduplicate(results)

        # Rank results
        results = self._rank_results(results, query)

        # Cache results
        if self.cache_enabled:
            self._cache[cache_key] = results

        return results[:limit]

    def advanced_search(
        self,
        criteria: Dict[str, Any],
    ) -> List[SearchResult]:
        """Perform advanced search with multiple criteria.

        Args:
            criteria: Search criteria dictionary with keys:
                - model: Device model
                - version: Firmware version
                - region: Geographic region
                - content_type: Type (firmware, rom, tools, all)
                - min_size: Minimum file size
                - max_size: Maximum file size
                - date_from: Minimum release date
                - date_to: Maximum release date
                - beta: Include beta versions

        Returns:
            List of SearchResult objects
        """
        query = criteria.get("model", "") or criteria.get("version", "")
        content_type = criteria.get("content_type", "all")

        filters = {
            k: v for k, v in criteria.items()
            if k not in ("model", "version", "content_type")
        }

        limit = criteria.get("limit", 50)

        return self.search(query, content_type, filters, limit)

    def get_suggestions(self, partial_query: str) -> List[str]:
        """Get search suggestions for partial query.

        Args:
            partial_query: Partial search query

        Returns:
            List of suggested search terms
        """
        self.logger.debug(f"Getting suggestions for: {partial_query}")

        try:
            endpoint = f"{self.base_url}/api/suggestions"
            params = {"query": partial_query, "limit": 10}
            headers = self.authenticator.get_headers()

            response = self.http_client.get(
                endpoint,
                params=params,
                headers=headers,
            )

            if response:
                data = response.json()
                suggestions = data.get("suggestions", [])
                return suggestions

        except Exception as e:
            self.logger.error(f"Failed to get suggestions: {e}")

        return []

    def clear_cache(self) -> None:
        """Clear search result cache."""
        self._cache.clear()
        self.logger.info("Search cache cleared")

    def _parse_search_result(self, item: Dict[str, Any]) -> Optional[SearchResult]:
        """Parse API response item into SearchResult.

        Args:
            item: API response item

        Returns:
            SearchResult or None if parsing fails
        """
        try:
            return SearchResult(
                model=item.get("model", ""),
                version=item.get("version", ""),
                region=item.get("region", ""),
                download_url=item.get("download_url", ""),
                file_size=item.get("file_size", 0),
                release_date=item.get("release_date"),
                description=item.get("description"),
                content_type=item.get("type", "firmware"),
            )
        except Exception as e:
            self.logger.warning(f"Failed to parse search result: {e}")
            return None

    def _apply_filters(
        self,
        results: List[SearchResult],
        filters: Optional[Dict[str, Any]],
    ) -> List[SearchResult]:
        """Apply filters to search results.

        Args:
            results: List of search results
            filters: Filter criteria

        Returns:
            Filtered list of results
        """
        if not filters:
            return results

        filtered = results

        # Filter by region
        if "region" in filters:
            region = filters["region"].lower()
            filtered = [r for r in filtered if region in r.region.lower()]

        # Filter by file size
        if "min_size" in filters:
            min_size = int(filters["min_size"])
            filtered = [r for r in filtered if r.file_size >= min_size]

        if "max_size" in filters:
            max_size = int(filters["max_size"])
            filtered = [r for r in filtered if r.file_size <= max_size]

        # Filter by release date
        if "date_from" in filters or "date_to" in filters:
            # Date filtering logic would go here
            pass

        return filtered

    def _deduplicate(self, results: List[SearchResult]) -> List[SearchResult]:
        """Remove duplicate results based on download URL.

        Args:
            results: List of search results

        Returns:
            Deduplicated list
        """
        seen_urls = set()
        deduped = []

        for result in results:
            url = result.download_url.split("?")[0]  # Remove query params
            if url not in seen_urls:
                seen_urls.add(url)
                deduped.append(result)

        if len(deduped) < len(results):
            self.logger.debug(
                f"Removed {len(results) - len(deduped)} duplicate results"
            )

        return deduped

    def _rank_results(
        self,
        results: List[SearchResult],
        query: str,
    ) -> List[SearchResult]:
        """Rank results by relevance to query.

        Args:
            results: List of search results
            query: Original search query

        Returns:
            Ranked list of results
        """
        query_lower = query.lower()

        def relevance_score(result: SearchResult) -> int:
            """Calculate relevance score for result."""
            score = 0

            # Exact model match
            if result.model.lower() == query_lower:
                score += 100

            # Model contains query
            if query_lower in result.model.lower():
                score += 50

            # Version contains query
            if query_lower in result.version.lower():
                score += 30

            # Description contains query
            if result.description and query_lower in result.description.lower():
                score += 10

            return score

        # Sort by relevance score (descending)
        ranked = sorted(results, key=relevance_score, reverse=True)

        return ranked
