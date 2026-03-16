"""
crawl4ai.extensions.sites.hp_support – Site module for support.hp.com.

HP's support site is an Angular SPA.  Download links for drivers, firmware,
and software are **not** in the static HTML – they are loaded dynamically
via the ``/wcc-services/`` JSON API.  This module:

1. Detects ``support.hp.com`` URLs.
2. Dynamically resolves product OID from the URL path, or discovers
   products via HP's search API when no OID is present.
3. Dynamically fetches all available OS platforms and versions from the
   ``/wcc-services/swd-v2/osVersionData`` API.
4. If the OS API returns no data, falls back to the
   ``/wcc-services/s/init`` API to detect the user's OS dynamically.
5. POSTs to ``/wcc-services/swd-v2/driverDetails`` for every OS version
   and collects file metadata (name, size, version, release date,
   category, OS, description, download URL) for each software entry.

**No static / hardcoded data** — all product OIDs, OS IDs, platform IDs,
and file metadata are discovered at runtime via HP's own APIs.

Instead of returning download URLs, this module returns a list of
:class:`FileEntry` dicts that the downloader writes to a ``file_index.md``
Markdown table.
"""

from __future__ import annotations

import itertools
import logging
import re
import urllib.parse
from typing import TYPE_CHECKING

from .base import BaseSiteModule, FileEntry

if TYPE_CHECKING:
    import requests

__all__ = ["HPSupportModule"]

log = logging.getLogger(__name__)

# ── Hosts ────────────────────────────────────────────────────────────────

_HP_HOSTS = {"support.hp.com", "h30434.www3.hp.com", "ftp.hp.com"}

# ── URL patterns ─────────────────────────────────────────────────────────

# /model/<oid>
_OID_MODEL_RE = re.compile(r"/model/(\d+)")
# /product/details/<seo-name>/<oid>  (from search API targetUrl)
_OID_PRODUCT_RE = re.compile(r"/product/details/[^/]+/(\d+)")
# Last numeric path segment ≥5 digits (generic fallback)
_OID_LAST_RE = re.compile(r"/(\d{5,})(?:[/?#]|$)")
# SEO name from /drivers/<seo-name> path
_SEO_NAME_RE = re.compile(r"/drivers/([a-z0-9][\w-]+)", re.I)
# Locale: /us-en/
_LOCALE_RE = re.compile(r"/([a-z]{2})-([a-z]{2})/")

# ── API endpoints ────────────────────────────────────────────────────────

_BASE = "https://support.hp.com"
_SWD_DRIVERS_URL = f"{_BASE}/wcc-services/swd-v2/driverDetails"
_SWD_OS_URL = f"{_BASE}/wcc-services/swd-v2/osVersionData"
_INIT_URL = f"{_BASE}/wcc-services/s/init"
_SEARCH_URL = f"{_BASE}/wcc-services/searchresult"

_REQUEST_TIMEOUT = 30
_MAX_DESCRIPTION_LENGTH = 200

# Broad queries used to discover products when no OID is in the URL.
# Each query returns up to ~200 products from HP's search API.
_CATALOG_SEARCH_QUERIES = [
    "HP printer",
    "HP laptop",
    "HP desktop",
    "HP workstation",
    "HP monitor",
    "HP scanner",
    "HP docking station",
    "HP ink",
    "HP toner",
    "HP accessories",
]

# Maximum number of products to process when doing a full catalog crawl.
_MAX_CATALOG_PRODUCTS = 50

_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}


class HPSupportModule(BaseSiteModule):
    """Discovers driver/software file metadata from support.hp.com.

    All product IDs, OS versions, platform IDs, and file metadata are
    fetched **dynamically** from HP's JSON APIs — nothing is hardcoded.

    Returns a list of :class:`FileEntry` dicts with file name, size,
    version, release date, category, OS, description, and download URL
    so the downloader can write a ``file_index.md`` instead of
    downloading the actual files.
    """

    name = "HP Support (drivers & software)"
    hosts = list(_HP_HOSTS)

    # ── BaseSiteModule interface ─────────────────────────────────────

    def matches(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc in _HP_HOSTS

    def generate_index(self, url: str) -> list[FileEntry]:
        """Discover driver/software files and return their metadata.

        The entire flow is dynamic:

        1. Extract locale (``cc``, ``lc``) from the URL.
        2. Extract or discover product OID(s).
        3. For each OID, fetch OS versions from the API.
        4. For each OS, POST to driverDetails and collect file metadata.

        When no product OID is found in the URL (e.g. the root page
        ``https://support.hp.com``), this method discovers products
        dynamically via HP's search API using multiple broad queries
        and processes each product found.
        """
        entries: list[FileEntry] = []
        cc, lc = self._extract_locale(url)

        # 1. Try extracting OID directly from the URL
        oid = self._extract_oid(url)

        # 2. If no numeric OID, try resolving via SEO name → search API
        if not oid:
            seo_name = self._extract_seo_name(url)
            if seo_name:
                log.info("[HP] No OID in URL — searching for '%s'", seo_name)
                oid = self._resolve_oid_by_search(seo_name, cc, lc)

        if oid:
            # Single-product mode: fetch files for this one product
            log.info("[HP] Product OID=%s  locale=%s-%s", oid, cc, lc)
            self._collect_files_for_product(oid, cc, lc, entries)
        else:
            # Catalog mode: discover products via broad search queries
            log.info("[HP] No product OID — discovering catalog …")
            product_oids = self._discover_catalog_products(cc, lc)
            log.info("[HP] Catalog: found %d products to scan", len(product_oids))
            for i, (prod_oid, prod_name) in enumerate(product_oids, 1):
                log.info("[HP] [%d/%d] %s (OID=%s)",
                         i, len(product_oids), prod_name, prod_oid)
                self._collect_files_for_product(
                    prod_oid, cc, lc, entries,
                    product_name=prod_name,
                )

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique: list[FileEntry] = []
        for entry in entries:
            u = entry.get("url", "")
            if u and u not in seen_urls:
                seen_urls.add(u)
                unique.append(entry)

        log.info("[HP] Discovered %d unique files total", len(unique))
        return unique

    # ── Catalog discovery ────────────────────────────────────────────

    def _discover_catalog_products(
        self, cc: str, lc: str,
    ) -> list[tuple[str, str]]:
        """Search HP's product API with multiple queries to build a
        product catalog.

        Returns a list of ``(oid, product_name)`` tuples, limited to
        :data:`_MAX_CATALOG_PRODUCTS` unique products.
        """
        seen_oids: set[str] = set()
        products: list[tuple[str, str]] = []

        for query in _CATALOG_SEARCH_QUERIES:
            if len(products) >= _MAX_CATALOG_PRODUCTS:
                break
            found = self._search_products(query, cc, lc)
            for oid, name in found:
                if oid not in seen_oids:
                    seen_oids.add(oid)
                    products.append((oid, name))
                    if len(products) >= _MAX_CATALOG_PRODUCTS:
                        break
            log.debug("[HP] Query '%s' → %d products (total %d)",
                      query, len(found), len(products))

        return products

    def _search_products(
        self, query: str, cc: str, lc: str,
    ) -> list[tuple[str, str]]:
        """Search HP and return ``(oid, name)`` tuples for all products
        found."""
        sess = self._get_session()
        results: list[tuple[str, str]] = []
        try:
            resp = sess.get(
                f"{_SEARCH_URL}/{cc}-{lc}",
                params={"q": query, "context": "pdp"},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return results
            data = resp.json()
            categories = (
                data.get("data", {})
                .get("kaaSResponse", {})
                .get("data", {})
                .get("searchResults", {})
                .get("categories", [])
            )
            for cat in categories:
                self._extract_products_from_category(cat, results)
                for sub in cat.get("subCategoryList") or []:
                    self._extract_products_from_category(sub, results)
        except Exception as exc:
            log.debug("[HP] Product search '%s' failed: %s", query, exc)
        return results

    @staticmethod
    def _extract_products_from_category(
        cat: dict, results: list[tuple[str, str]],
    ) -> None:
        """Extract ``(oid, name)`` pairs from a search category dict."""
        for prod in cat.get("productList") or []:
            target = prod.get("targetUrl", "")
            name = prod.get("productName", "")
            m = _OID_PRODUCT_RE.search(target) or _OID_LAST_RE.search(target)
            if m:
                results.append((m.group(1), name))

    def _collect_files_for_product(
        self,
        oid: str,
        cc: str,
        lc: str,
        entries: list[FileEntry],
        product_name: str = "",
    ) -> None:
        """Fetch OS versions and driver metadata for a single product
        and append discovered :class:`FileEntry` items to *entries*."""
        os_list = self._fetch_os_versions(oid, cc, lc)
        if not os_list:
            os_list = self._detect_os_from_init(cc, lc)

        for os_info in os_list:
            try:
                os_entries = self._fetch_driver_entries(oid, os_info, cc, lc)
                entries.extend(os_entries)
            except Exception as exc:
                log.debug("[HP] Error fetching drivers for OS %s: %s",
                          os_info.get("name", "?"), exc)

    # ── Session helper ───────────────────────────────────────────────

    def _get_session(self) -> "requests.Session":
        if self.session is not None:
            return self.session
        import requests as _req
        s = _req.Session()
        s.headers.update(_HEADERS)
        return s

    # ── URL parsing (no hardcoded IDs) ───────────────────────────────

    @staticmethod
    def _extract_oid(url: str) -> str | None:
        """Extract a numeric product OID from the URL path."""
        for pattern in (_OID_MODEL_RE, _OID_PRODUCT_RE, _OID_LAST_RE):
            m = pattern.search(url)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _extract_seo_name(url: str) -> str | None:
        """Extract the product SEO name from a ``/drivers/<seo-name>`` URL."""
        m = _SEO_NAME_RE.search(url)
        return m.group(1) if m else None

    @staticmethod
    def _extract_locale(url: str) -> tuple[str, str]:
        m = _LOCALE_RE.search(url)
        if m:
            return m.group(1), m.group(2)
        return "us", "en"

    # ── Dynamic product resolution ───────────────────────────────────

    def _resolve_oid_by_search(
        self, seo_name: str, cc: str, lc: str,
    ) -> str | None:
        """Search HP's product API to find the OID for a SEO name.

        Calls ``/wcc-services/searchresult/{cc}-{lc}?q=<name>&context=pdp``
        and extracts the first ``targetUrl`` that contains a numeric OID.
        """
        sess = self._get_session()
        # Convert seo-name to search query: "hp-officejet-3830" → "hp officejet 3830"
        query = seo_name.replace("-", " ")
        try:
            resp = sess.get(
                f"{_SEARCH_URL}/{cc}-{lc}",
                params={"q": query, "context": "pdp"},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return None
            data = resp.json()
            # Walk the nested category/product tree
            categories = (
                data.get("data", {})
                .get("kaaSResponse", {})
                .get("data", {})
                .get("searchResults", {})
                .get("categories", [])
            )
            for cat in categories:
                for sub in cat.get("subCategoryList") or []:
                    for prod in sub.get("productList") or []:
                        target = prod.get("targetUrl", "")
                        m = _OID_PRODUCT_RE.search(target) or _OID_LAST_RE.search(target)
                        if m:
                            log.info("[HP] Search resolved '%s' → OID %s",
                                     seo_name, m.group(1))
                            return m.group(1)
                # Also check direct productList at category level
                for prod in cat.get("productList") or []:
                    target = prod.get("targetUrl", "")
                    m = _OID_PRODUCT_RE.search(target) or _OID_LAST_RE.search(target)
                    if m:
                        return m.group(1)
        except Exception as exc:
            log.debug("[HP] Product search failed: %s", exc)
        return None

    # ── Dynamic OS version discovery ─────────────────────────────────

    def _fetch_os_versions(
        self, oid: str, cc: str, lc: str,
    ) -> list[dict]:
        """Fetch all available OS platforms + versions for a product.

        Calls ``/wcc-services/swd-v2/osVersionData?cc=…&lc=…&productOid=…``
        and returns a flat list of ``{id, name, platformId, platformName}``
        dicts — one entry per OS version.
        """
        sess = self._get_session()
        try:
            resp = sess.get(
                _SWD_OS_URL,
                params={"cc": cc, "lc": lc, "productOid": oid},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return []
            data = resp.json().get("data", {})
            if data is None:
                return []

            os_versions: list[dict] = []

            # Primary structure: osAvailablePlatformsAnsOS.osPlatforms[]
            platforms_data = data.get("osAvailablePlatformsAnsOS", {})
            platforms = platforms_data.get("osPlatforms", [])
            for platform in platforms:
                platform_id = platform.get("id", "")
                platform_name = platform.get("name", "")
                for version in platform.get("osVersions", []):
                    os_versions.append({
                        "id": version.get("id", ""),
                        "name": version.get("name", ""),
                        "platformId": platform_id,
                        "platformName": platform_name,
                    })

            # Fallback structure: platformList[]
            if not os_versions:
                for platform in data.get("platformList", []):
                    platform_id = platform.get("platformId", "")
                    platform_name = platform.get("platformName", "")
                    for version in platform.get("osVersions", []):
                        os_versions.append({
                            "id": version.get("osTmsId", version.get("id", "")),
                            "name": version.get("osName", version.get("name", "")),
                            "platformId": platform_id,
                            "platformName": platform_name,
                        })

            if os_versions:
                log.info("[HP] Found %d OS versions across %d platforms",
                         len(os_versions), len(platforms))
            return os_versions
        except Exception as exc:
            log.debug("[HP] OS version fetch failed: %s", exc)
        return []

    def _detect_os_from_init(
        self, cc: str, lc: str,
    ) -> list[dict]:
        """Dynamically detect the user's OS via ``/wcc-services/s/init``.

        This endpoint returns the detected OS TMS ID based on the
        requesting client's User-Agent.  Used as a last-resort fallback
        when ``osVersionData`` returns no results.
        """
        sess = self._get_session()
        try:
            resp = sess.get(
                _INIT_URL,
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return []
            data = resp.json().get("data", {})
            if data is None:
                return []
            os_info = data.get("osInfo", {})
            os_tms_id = os_info.get("osTmsId", "")
            if not os_tms_id:
                return []
            log.info("[HP] Detected OS from /s/init: TMS ID=%s", os_tms_id)
            return [{
                "id": os_tms_id,
                "name": "Detected OS",
                "platformId": "",
                "platformName": "",
            }]
        except Exception as exc:
            log.debug("[HP] /s/init OS detection failed: %s", exc)
        return []

    # ── Driver / software metadata collection ────────────────────────

    def _fetch_driver_entries(
        self,
        oid: str,
        os_info: dict,
        cc: str,
        lc: str,
    ) -> list[FileEntry]:
        """POST to ``/wcc-services/swd-v2/driverDetails`` and extract
        file metadata from the response.

        Returns a list of :class:`FileEntry` dicts with name, size,
        version, release date, category, OS, description, and URL.
        """
        sess = self._get_session()
        payload = {
            "cc": cc,
            "lc": lc,
            "productSeriesOid": oid,
            "osTMSId": os_info.get("id", ""),
            "osName": os_info.get("platformName", ""),
            "platformId": os_info.get("platformId", ""),
        }

        entries: list[FileEntry] = []
        os_name = os_info.get("name", "")
        try:
            resp = sess.post(
                _SWD_DRIVERS_URL,
                json=payload,
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return entries
            data = resp.json().get("data", {})
            if data is None:
                return entries

            for sw_type in data.get("softwareTypes", []):
                category = sw_type.get(
                    "accordionName",
                    sw_type.get("categoryName", ""),
                )
                # Primary structure: softwareDriversList[]
                for drv in sw_type.get("softwareDriversList", []):
                    self._collect_entries_from_driver(
                        drv, category, os_name, entries,
                    )
                # Fallback structure: softwareList[]
                for item in sw_type.get("softwareList", []):
                    self._collect_entries_from_item(
                        item, category, os_name, entries,
                    )
                    for sub in item.get("subCategory", {}).get("softwareList", []):
                        self._collect_entries_from_item(
                            sub, category, os_name, entries,
                        )
        except Exception as exc:
            log.debug("[HP] driverDetails call failed: %s", exc)

        return entries

    @staticmethod
    def _collect_entries_from_driver(
        driver: dict,
        category: str,
        os_name: str,
        entries: list[FileEntry],
    ) -> None:
        """Extract file entries from a ``softwareDriversList`` item."""
        latest = driver.get("latestVersionDriver") or {}
        drv_name = latest.get("name", driver.get("name", ""))
        version = latest.get("version", "")
        size = latest.get("fileSize", "")
        release = latest.get("releaseDate", "")
        desc_html = (latest.get("detailInformation") or {}).get("description", "")
        # Strip HTML tags for plain-text description
        description = re.sub(r"<[^>]+>", " ", desc_html).strip()[:_MAX_DESCRIPTION_LENGTH]

        file_url = latest.get("fileUrl", "")
        if file_url and file_url.startswith("http"):
            # Derive file name from productSoftwareFileList or URL
            sub_files = latest.get("productSoftwareFileList", [])
            if sub_files:
                fname = sub_files[0].get("fileName", "")
                fsize = sub_files[0].get("fileSize", size)
            else:
                fname = file_url.rsplit("/", 1)[-1].split("?")[0]
                fsize = size

            entries.append(FileEntry(
                name=fname or drv_name or file_url.rsplit("/", 1)[-1],
                url=file_url,
                size=str(fsize) if fsize else "",
                version=str(version) if version else "",
                release_date=str(release).split("T")[0] if release else "",
                category=category,
                os=os_name,
                description=description,
            ))

            # Additional sub-files with different URLs
            for sf in itertools.islice(sub_files, 1, None):
                sf_url = sf.get("fileUrl", "")
                if sf_url and sf_url.startswith("http") and sf_url != file_url:
                    entries.append(FileEntry(
                        name=sf.get("fileName", sf_url.rsplit("/", 1)[-1]),
                        url=sf_url,
                        size=str(sf.get("fileSize", "")) if sf.get("fileSize") else "",
                        version=str(version) if version else "",
                        release_date=str(release).split("T")[0] if release else "",
                        category=category,
                        os=os_name,
                        description=description,
                    ))

    @staticmethod
    def _collect_entries_from_item(
        item: dict,
        category: str,
        os_name: str,
        entries: list[FileEntry],
    ) -> None:
        """Extract file entries from a generic software item dict."""
        file_url = item.get("fileUrl", "")
        if file_url and file_url.startswith("http"):
            entries.append(FileEntry(
                name=item.get("name", file_url.rsplit("/", 1)[-1]),
                url=file_url,
                size=str(item.get("fileSize", "")) if item.get("fileSize") else "",
                version=str(item.get("version", "")) if item.get("version") else "",
                release_date="",
                category=category,
                os=os_name,
                description="",
            ))
        for f in item.get("productSoftwareFileList", []):
            fu = f.get("fileUrl", "")
            if fu and fu.startswith("http"):
                entries.append(FileEntry(
                    name=f.get("fileName", fu.rsplit("/", 1)[-1]),
                    url=fu,
                    size=str(f.get("fileSize", "")) if f.get("fileSize") else "",
                    version="",
                    release_date="",
                    category=category,
                    os=os_name,
                    description="",
                ))
