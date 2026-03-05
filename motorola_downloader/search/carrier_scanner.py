"""Country and carrier scanner for Motorola Firmware Downloader.

Queries every model returned by ``getModelNames.jhtml`` and walks the
``paramProperty`` resolution chain (simCount → country) to collect
all known country/carrier combinations.  The resulting deduplicated
list can be used to:

  - Populate the search UI with available regions.
  - Pre-seed the search engine with valid ``country`` values.
  - Generate a reference CSV/JSON of all operators.

Usage (standalone)::

    python -m motorola_downloader.search.carrier_scanner

Usage (library)::

    from motorola_downloader.search.carrier_scanner import CarrierScanner
    scanner = CarrierScanner(api_client)
    countries = scanner.scan_all_countries()
"""

from typing import Any, Dict, List, Set, Tuple

from motorola_downloader.utils.api_client import (
    LMSAClient,
    FIRMWARE_CATEGORIES,
    FIRMWARE_COUNTRIES,
)
from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)

# Param properties that contain country/carrier information
_COUNTRY_PROPERTIES = {"country", "region", "carrier"}

# SIM count values to iterate
_SIM_COUNTS = ("Single", "Dual")


class CarrierScanner:
    """Scans all models for available countries and carriers.

    Args:
        api: An authenticated LMSAClient instance.
    """

    def __init__(self, api: LMSAClient) -> None:
        self._api = api
        self.logger = get_logger(__name__)

    def scan_all_countries(
        self,
        search_countries: Tuple[str, ...] = FIRMWARE_COUNTRIES,
        categories: Tuple[str, ...] = FIRMWARE_CATEGORIES,
        max_models: int = 0,
    ) -> List[Dict[str, Any]]:
        """Scan all models to extract country/carrier combinations.

        For each model returned by ``getModelNames``, calls
        ``getResource`` to discover the ``paramProperty`` chain.
        When a ``simCount`` property is found, iterates both
        ``Single`` and ``Dual`` to reach the ``country`` level.

        Args:
            search_countries: Countries to query for model lists.
            categories: Device categories (Phone, Tablet).
            max_models: Limit number of models to scan (0 = all).

        Returns:
            List of dicts with keys: ``country``, ``model``,
            ``marketName``, ``simCount``.
        """
        # Collect all unique models first
        all_models: List[Dict[str, str]] = []
        seen_models: Set[str] = set()

        self.logger.info("Scanning model lists across %d countries, %d categories",
                         len(search_countries), len(categories))

        for country in search_countries:
            for category in categories:
                try:
                    models = self._api.get_model_names(
                        country=country, category=category,
                    )
                    for m in models:
                        mn = m.get("modelName", "")
                        mk = m.get("marketName", "")
                        key = f"{mn}|{mk}"
                        if key not in seen_models:
                            seen_models.add(key)
                            all_models.append({
                                "modelName": mn,
                                "marketName": mk,
                                "platform": m.get("platform", ""),
                                "category": m.get("category", category),
                            })
                except Exception as exc:
                    self.logger.debug(
                        "getModelNames(%s, %s) failed: %s",
                        country, category, exc,
                    )

        self.logger.info("Found %d unique models to scan", len(all_models))

        if max_models > 0:
            all_models = all_models[:max_models]

        # Scan each model for countries/carriers
        all_countries: List[Dict[str, Any]] = []
        seen_entries: Set[str] = set()

        for idx, model in enumerate(all_models, 1):
            mn = model["modelName"]
            mk = model["marketName"]

            if idx % 50 == 0:
                self.logger.info(
                    "Progress: %d/%d models scanned, %d countries found",
                    idx, len(all_models), len(all_countries),
                )

            try:
                entries = self._scan_model_countries(mn, mk)
                for entry in entries:
                    key = f"{entry['country']}|{entry['model']}|{entry.get('simCount','')}"
                    if key not in seen_entries:
                        seen_entries.add(key)
                        all_countries.append(entry)
            except Exception as exc:
                self.logger.debug("Scan failed for %s: %s", mn, exc)

        self.logger.info(
            "Scan complete: %d unique country/carrier entries from %d models",
            len(all_countries), len(all_models),
        )
        return all_countries

    def get_unique_carriers(
        self,
        country_entries: List[Dict[str, Any]],
    ) -> List[str]:
        """Extract a deduplicated sorted list of country/carrier names.

        Args:
            country_entries: Output from ``scan_all_countries()``.

        Returns:
            Sorted list of unique country/carrier strings.
        """
        carriers: Set[str] = set()
        for entry in country_entries:
            carriers.add(entry["country"])
        return sorted(carriers)

    def _scan_model_countries(
        self, model_name: str, market_name: str,
    ) -> List[Dict[str, Any]]:
        """Scan a single model for available countries/carriers.

        Calls ``getResource`` and walks the paramProperty chain.
        If the first level is ``simCount``, iterates both Single
        and Dual.  If a ``country`` property is found at any level,
        collects all values.

        Args:
            model_name: Device model name (e.g. ``XT2523-2``).
            market_name: Market name (e.g. ``Moto g05``).

        Returns:
            List of country entry dicts.
        """
        results: List[Dict[str, Any]] = []

        items = self._api.get_resource(model_name, market_name)

        for item in items:
            pp = item.get("paramProperty") or {}
            pv = item.get("paramValues") or []
            prop = pp.get("property", "")

            if prop == "simCount" and pv:
                # Iterate SIM counts to reach country level
                for sim_val in pv:
                    sub_items = self._api.get_resource(
                        model_name, market_name, simCount=sim_val,
                    )
                    for sub in sub_items:
                        sub_pp = sub.get("paramProperty") or {}
                        sub_pv = sub.get("paramValues") or []
                        sub_prop = sub_pp.get("property", "")

                        if sub_prop in _COUNTRY_PROPERTIES and sub_pv:
                            for country in sub_pv:
                                results.append({
                                    "country": country,
                                    "model": model_name,
                                    "marketName": market_name,
                                    "simCount": sim_val,
                                })
                        elif not sub_pp:
                            # Fully resolved without country level
                            comments = sub.get("comments", "")
                            if comments:
                                results.append({
                                    "country": comments,
                                    "model": model_name,
                                    "marketName": market_name,
                                    "simCount": sim_val,
                                })

            elif prop in _COUNTRY_PROPERTIES and pv:
                # Direct country level (no simCount)
                for country in pv:
                    results.append({
                        "country": country,
                        "model": model_name,
                        "marketName": market_name,
                        "simCount": "",
                    })

        return results


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the carrier scanner as a standalone script."""
    import json
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    ))))

    from motorola_downloader.settings import Settings
    from motorola_downloader.utils.logger import setup_logging
    from motorola_downloader.auth.session_manager import SessionManager
    from motorola_downloader.utils.http_client import HTTPClient

    setup_logging(level="INFO", log_file="logs/carrier_scan.log", debug=False)
    logger = get_logger("carrier_scanner_main")

    guid = os.environ.get("MOTOROLA_GUID", "")
    jwt_token = os.environ.get("MOTOROLA_JWT", "")
    if not guid or not jwt_token:
        logger.error("Set MOTOROLA_GUID and MOTOROLA_JWT environment variables")
        sys.exit(1)

    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config.ini",
    )
    settings = Settings(config_path)
    settings.load_from_file(create_if_missing=True)

    http_client = HTTPClient(timeout=60, max_retries=3)
    session = SessionManager(settings, http_client)
    session.authenticator.from_jwt(jwt=jwt_token, guid=guid)
    session._active = True

    from motorola_downloader.search.search_engine import SearchEngine
    search_engine = SearchEngine(session, settings)
    api = search_engine.api_client

    scanner = CarrierScanner(api)

    # Scan a limited set of countries for speed
    scan_countries = ("Mexico", "US", "Brazil", "Argentina", "India")
    logger.info("Starting carrier scan (%d countries)...", len(scan_countries))

    # Use max_models=0 for full scan, or a small number for testing
    max_models = int(os.environ.get("MAX_MODELS", "30"))
    entries = scanner.scan_all_countries(
        search_countries=scan_countries,
        max_models=max_models,
    )

    carriers = scanner.get_unique_carriers(entries)

    print(f"\n{'='*70}")
    print(f" Carrier Scan Results: {len(carriers)} unique carriers/countries")
    print(f"{'='*70}")
    for c in carriers:
        print(f"  • {c}")

    # Save to JSON
    output_path = "carrier_list.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "carriers": carriers,
            "details": entries,
        }, f, indent=2, ensure_ascii=False)
    logger.info("Saved carrier list to %s", output_path)


if __name__ == "__main__":
    main()
