"""
Search orchestration across Motorola firmware endpoints.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from motorola_firmware.http_client import HttpClient
from motorola_firmware.logger import get_logger
from motorola_firmware.settings import Settings


class SearchEngine:
    """High-level search orchestration with caching and deduplication."""

    def __init__(self, settings: Settings, http_client: HttpClient) -> None:
        self.settings = settings
        self.http_client = http_client
        self.logger = get_logger(__name__)
        self._cache: Dict[str, tuple[float, List[Dict[str, object]]]] = {}

    def search(
        self,
        query: str,
        content_type: str = "all",
        filters: Optional[Dict[str, object]] = None,
    ) -> List[Dict[str, object]]:
        """Run a search across available firmware sources."""
        filters = filters or {}
        cache_key = self._cache_key(query, content_type, filters)
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        params: Dict[str, object] = {
            "q": query,
            "type": content_type,
            "limit": self.settings.get_int("search", "default_limit", 25),
            "region": self.settings.get("search", "region", "us"),
        }
        params.update(filters)

        try:
            url = self._search_url()
            response = self.http_client.get(url, params=params)
            results = self._deduplicate(response.json())
            self._cache[cache_key] = (time.time(), results)
            self.logger.info("Search returned %d results", len(results))
            return results
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Search failed: %s", exc)
            return []

    def advanced_search(self, criteria: Dict[str, object]) -> List[Dict[str, object]]:
        """Perform an advanced search with structured criteria."""
        query = str(criteria.get("query", ""))
        content_type = str(criteria.get("type", "all"))
        filters = {k: v for k, v in criteria.items() if k not in {"query", "type"}}
        return self.search(query=query, content_type=content_type, filters=filters)

    def get_suggestions(self, partial_query: str) -> List[str]:
        """Return suggestions based on cached searches or API hints."""
        cache_hits = [
            key for key in self._cache.keys()
            if partial_query.lower() in key.lower()
        ]
        if cache_hits:
            suggestions = [k.split("|", 1)[0] for k in cache_hits]
            return list(dict.fromkeys(suggestions))

        try:
            url = self._suggest_url()
            response = self.http_client.get(url, params={"q": partial_query})
            data = response.json()
            if isinstance(data, list):
                return [str(item) for item in data]
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("Suggestions fetch failed: %s", exc)
        return []

    def _deduplicate(self, results: object) -> List[Dict[str, object]]:
        deduped: Dict[str, Dict[str, object]] = {}
        if not isinstance(results, list):
            return []
        for item in results:
            if not isinstance(item, dict):
                continue
            key = str(item.get("id") or item.get("download_url") or item.get("name"))
            if not key:
                continue
            deduped[key] = item
        return list(deduped.values())

    def _cache_key(
        self,
        query: str,
        content_type: str,
        filters: Dict[str, object],
    ) -> str:
        return f"{query}|{content_type}|{sorted(filters.items())}"

    def _get_cached(self, key: str) -> Optional[List[Dict[str, object]]]:
        ttl = self.settings.get_int("search", "cache_ttl_seconds", 300)
        cached = self._cache.get(key)
        if not cached:
            return None
        ts, results = cached
        if time.time() - ts <= ttl:
            self.logger.info("Serving search results from cache")
            return results
        self._cache.pop(key, None)
        return None

    def _search_url(self) -> str:
        base = self.settings.get("motorola_server", "base_url")
        return f"{base.rstrip('/')}/search"

    def _suggest_url(self) -> str:
        base = self.settings.get("motorola_server", "base_url")
        return f"{base.rstrip('/')}/suggest"
