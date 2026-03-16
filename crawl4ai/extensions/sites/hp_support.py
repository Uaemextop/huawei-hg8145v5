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
   and collects all ``fileUrl`` values from each software entry.

**No static / hardcoded data** — all product OIDs, OS IDs, platform IDs,
and download URLs are discovered at runtime via HP's own APIs.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import TYPE_CHECKING

from .base import BaseSiteModule

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
_SITEMAP_URL = f"{_BASE}/wcc-services/sitemap/href"

_REQUEST_TIMEOUT = 30

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
    """Discovers driver/software download URLs from support.hp.com.

    All product IDs, OS versions, platform IDs, and download URLs are
    fetched **dynamically** from HP's JSON APIs — nothing is hardcoded.
    """

    name = "HP Support (drivers & software)"
    hosts = list(_HP_HOSTS)

    # ── BaseSiteModule interface ─────────────────────────────────────

    def matches(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc in _HP_HOSTS

    def extra_urls(self, url: str) -> set[str]:
        """Discover driver/software download URLs via HP's SWD APIs.

        The entire flow is dynamic:

        1. Extract locale (``cc``, ``lc``) from the URL.
        2. Extract or discover product OID(s).
        3. For each OID, fetch OS versions from the API.
        4. For each OS, POST to driverDetails and collect ``fileUrl``.
        """
        urls: set[str] = set()
        cc, lc = self._extract_locale(url)

        # 1. Try extracting OID directly from the URL
        oid = self._extract_oid(url)

        # 2. If no numeric OID, try resolving via SEO name → search API
        if not oid:
            seo_name = self._extract_seo_name(url)
            if seo_name:
                log.info("[HP] No OID in URL — searching for '%s'", seo_name)
                oid = self._resolve_oid_by_search(seo_name, cc, lc)

        # 3. If still no OID, scan for product page links as fallback
        if not oid:
            log.info("[HP] No product OID found — scanning sitemap")
            urls |= self._discover_product_pages(url, cc, lc)
            return urls

        log.info("[HP] Product OID=%s  locale=%s-%s", oid, cc, lc)

        # 4. Fetch OS versions dynamically
        os_list = self._fetch_os_versions(oid, cc, lc)
        if not os_list:
            # Fallback: detect user OS from /s/init API
            os_list = self._detect_os_from_init(cc, lc)

        # 5. For each OS, fetch driver/software list
        for os_info in os_list:
            try:
                driver_urls = self._fetch_driver_urls(oid, os_info, cc, lc)
                urls |= driver_urls
            except Exception as exc:
                log.debug("[HP] Error fetching drivers for OS %s: %s",
                          os_info.get("name", "?"), exc)

        log.info("[HP] Discovered %d download URLs for product %s", len(urls), oid)
        return urls

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

    # ── Driver / software list ───────────────────────────────────────

    def _fetch_driver_urls(
        self,
        oid: str,
        os_info: dict,
        cc: str,
        lc: str,
    ) -> set[str]:
        """POST to ``/wcc-services/swd-v2/driverDetails`` and extract
        all download URLs from the response.

        The response contains ``softwareTypes[]`` → ``softwareDriversList[]``
        → ``latestVersionDriver`` / ``productSoftwareFileList[]`` with
        ``fileUrl`` pointing to ``ftp.hp.com`` download links.
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

        urls: set[str] = set()
        try:
            resp = sess.post(
                _SWD_DRIVERS_URL,
                json=payload,
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return urls
            data = resp.json().get("data", {})
            if data is None:
                return urls

            for sw_type in data.get("softwareTypes", []):
                # Primary structure: softwareDriversList[]
                for item in sw_type.get("softwareDriversList", []):
                    self._collect_file_urls_from_driver(item, urls)
                # Fallback structure: softwareList[]
                for item in sw_type.get("softwareList", []):
                    self._collect_file_urls_from_item(item, urls)
                    for sub in item.get("subCategory", {}).get("softwareList", []):
                        self._collect_file_urls_from_item(sub, urls)
        except Exception as exc:
            log.debug("[HP] driverDetails call failed: %s", exc)

        return urls

    @staticmethod
    def _collect_file_urls_from_driver(driver: dict, urls: set[str]) -> None:
        """Extract download URLs from a ``softwareDriversList`` entry.

        Each entry has a ``latestVersionDriver`` object with ``fileUrl``
        and a ``productSoftwareFileList`` array with per-file URLs.
        """
        latest = driver.get("latestVersionDriver") or {}
        file_url = latest.get("fileUrl", "")
        if file_url and file_url.startswith("http"):
            urls.add(file_url)
        for f in latest.get("productSoftwareFileList", []):
            fu = f.get("fileUrl", "")
            if fu and fu.startswith("http"):
                urls.add(fu)

        # Also check previousDriverVersions if available
        for prev in latest.get("detailInformation", {}).get(
            "previousDriverVersions", []
        ) or []:
            fu = prev.get("fileUrl", "")
            if fu and fu.startswith("http"):
                urls.add(fu)

    @staticmethod
    def _collect_file_urls_from_item(item: dict, urls: set[str]) -> None:
        """Extract download URLs from a generic software item dict."""
        file_url = item.get("fileUrl", "")
        if file_url and file_url.startswith("http"):
            urls.add(file_url)
        for f in item.get("productSoftwareFileList", []):
            fn = f.get("fileName", "")
            if fn and fn.startswith("http"):
                urls.add(fn)
            fu = f.get("fileUrl", "")
            if fu and fu.startswith("http"):
                urls.add(fu)

    # ── Product page discovery (no OID fallback) ─────────────────────

    def _discover_product_pages(
        self, url: str, cc: str, lc: str,
    ) -> set[str]:
        """Fallback when no OID could be determined.

        Scans the HP sitemap API for product/driver page links and also
        tries to discover products from the search API with a broad query.
        """
        urls: set[str] = set()
        urls |= self._scan_sitemap_links(url, cc, lc)
        urls |= self._search_product_pages(cc, lc)
        return urls

    def _scan_sitemap_links(
        self, url: str, cc: str, lc: str,
    ) -> set[str]:
        """Scan the HP ``/wcc-services/sitemap/href`` API for driver pages."""
        sess = self._get_session()
        urls: set[str] = set()
        try:
            resp = sess.get(
                _SITEMAP_URL,
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.ok:
                data = resp.json()
                for entry in data.get("data", []) or []:
                    href = entry.get("href", "")
                    if href and "/drivers/" in href:
                        abs_url = urllib.parse.urljoin(url, href)
                        urls.add(abs_url)
        except Exception as exc:
            log.debug("[HP] Sitemap scan failed: %s", exc)
        return urls

    def _search_product_pages(
        self, cc: str, lc: str,
    ) -> set[str]:
        """Use the search API to discover popular product driver pages."""
        sess = self._get_session()
        urls: set[str] = set()
        try:
            resp = sess.get(
                f"{_SEARCH_URL}/{cc}-{lc}",
                params={"q": "HP printer", "context": "pdp"},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return urls
            data = resp.json()
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
                        if target:
                            abs_url = urllib.parse.urljoin(_BASE, target)
                            urls.add(abs_url)
                for prod in cat.get("productList") or []:
                    target = prod.get("targetUrl", "")
                    if target:
                        abs_url = urllib.parse.urljoin(_BASE, target)
                        urls.add(abs_url)
        except Exception as exc:
            log.debug("[HP] Product search fallback failed: %s", exc)
        return urls
