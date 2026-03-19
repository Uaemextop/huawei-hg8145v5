"""
crawl4ai.extensions.sites.hp_support – Site module for support.hp.com.

HP's support site is an Angular SPA.  Download links for drivers, firmware,
and software are **not** in the static HTML – they are loaded dynamically
via the ``/wcc-services/`` JSON API.  This module:

1. Detects ``support.hp.com`` URLs.
2. Dynamically resolves product OID from the URL path, or discovers
   products via HP's navigation and search APIs when no OID is present.
3. Dynamically fetches all available OS platforms and versions **per
   device** from the ``/wcc-services/swd-v2/osVersionData`` API,
   parsing three response structures (``osPlatforms``, ``platformList``,
   ``osversions``).  Only the platforms actually supported by each
   device are queried — no cross-device platform fallback.
4. POSTs to ``/wcc-services/swd-v2/driverDetails`` for every OS version
   returned by ``osVersionData`` and collects file metadata (name, size,
   version, release date, category, OS, description, download URL).
   Detects HTTP 403 rate limits and breaks early to avoid cascading
   failures.
5. Fetches product **manuals** (user guides, setup docs) from the
   ``/wcc-services/pdp/manuals/getManuals`` API.
6. Fetches **security advisories** from the
   ``/wcc-services/pdp/securityalerts/`` API.
7. Discovers **HP diagnostics tools** and **HPSA framework** downloads
   from ``ftp.hp.com`` and ``sudf-resources.hpcloud.hp.com``.
8. Probes **staging / QA / developer** endpoints dynamically from the
   Angular JS bundle (``qa2.houston.hp.com``,
   ``stage.portalshell.int.hp.com``, ``stg.cd.id.hp.com``).

**No static / hardcoded data** — all product OIDs, OS IDs, platform IDs,
category names, and file metadata are discovered at runtime via HP's own
APIs.  No predefined limits on the number of products processed.

Instead of returning download URLs, this module returns a list of
:class:`FileEntry` dicts that the downloader writes to a ``file_index.md``
Markdown table.
"""

from __future__ import annotations

import itertools
import logging
import re
import time
import urllib.parse
from typing import TYPE_CHECKING, Callable

from .base import BaseSiteModule, FileEntry

if TYPE_CHECKING:
    import requests

__all__ = ["HPSupportModule"]

log = logging.getLogger(__name__)

# ── Hosts ────────────────────────────────────────────────────────────────

_HP_HOSTS = {
    "support.hp.com",
    "h30434.www3.hp.com",
    "ftp.hp.com",
    "sudf-resources.hpcloud.hp.com",
    "h30318.www3.hp.com",
    "kaas.hpcloud.hp.com",
}

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
# Links matching HP product/driver URL patterns in HTML
_HTML_PRODUCT_LINK_RE = re.compile(
    r'href=["\']([^"\']*?/(?:product|model|drivers)/[^"\']*?)["\']',
    re.I,
)

# Product type names to search for in the Angular JS bundle.
_PRODUCT_TYPE_RE = re.compile(
    r'(?:Laptop|Printer|Desktop|Monitor|Scanner|Server|'
    r'Tablet|Workstation|Chromebook|All.in.One|'
    r'Notebook|Plotter|Projector|Docking Station|'
    r'Thin Client|Point of Sale)s?',
    re.I,
)
# ── API endpoints ────────────────────────────────────────────────────────

_BASE = "https://support.hp.com"
_SWD_DRIVERS_URL = f"{_BASE}/wcc-services/swd-v2/driverDetails"
_SWD_OS_URL = f"{_BASE}/wcc-services/swd-v2/osVersionData"
_SWD_POPULAR_PRINTERS_URL = f"{_BASE}/wcc-services/swd-v2/popularPrinters"
_INIT_URL = f"{_BASE}/wcc-services/s/init"
_SEARCH_URL = f"{_BASE}/wcc-services/searchresult"
_WARRANTY_SPECS_URL = f"{_BASE}/wcc-services/profile/devices/warranty/specs"

# Product detail page (PDP) endpoints — manuals, security alerts, specs
_PDP_MANUALS_URL = f"{_BASE}/wcc-services/pdp/manuals/getManuals"
_PDP_MANUAL_LANGS_URL = f"{_BASE}/wcc-services/pdp/manuals/getManualDropdownList"
_PDP_SECURITY_ALERTS_URL = f"{_BASE}/wcc-services/pdp/securityalerts"
_PDP_CATEGORY_URL = f"{_BASE}/wcc-services/pdp/category"
_PDP_CATEGORY_DETAILS_URL = f"{_BASE}/wcc-services/pdp/category-details"
_PDP_SPECS_URL = f"{_BASE}/wcc-services/pdp/specifications"

# CMS content, sitemap, product category, and methone virtual-agent endpoints
_CMS_URL = f"{_BASE}/wcc-services/cms-v2"
_SITEMAP_URL = f"{_BASE}/wcc-services/sitemap/href"
_PROD_CATEGORY_URL = f"{_BASE}/wcc-services/prodcategory/getProductCategoriesBySeoName"
_METHONE_URL = f"{_BASE}/wcc-services/methone/va-url"

# HP diagnostics / tool download sources (discovered from Angular JS bundle)
_FTP_HP = "https://ftp.hp.com"
_SUDF_RESOURCES = "https://sudf-resources.hpcloud.hp.com"

# Known staging / QA / developer endpoints (discovered from main.js bundle
# and commUtil.js HAR analysis).  Probed dynamically — only accessible ones used.
_STAGING_HOSTS = (
    # QA environments (internal — usually unreachable from public internet)
    "qa2.houston.hp.com",
    "ppssupport-qa2.houston.hp.com",
    # ITG (integration-test) environments (from commUtil.js — unreachable)
    "wcc-dev1.itg.support.hp.com",
    "wcc-qa1.itg.support.hp.com",
    "mastiff-itg.ext.hp.com",
    # UAT environment (returns 403 Access Denied from Akamai)
    "uat.support.hp.com",
    # Staging portal (CloudFront-backed — sometimes 403)
    "stage.portalshell.int.hp.com",
    "myaccount.stage.portalshell.int.hp.com",
    # CD staging (publicly accessible HP account staging)
    "stg.cd.id.hp.com",
    "account.stg.cd.id.hp.com",
    "myaccount.stg.cd.id.hp.com",
    # Staging navbar (from commUtil.js — publicly accessible)
    "global-navbar-backend.stg.cd.id.hp.com",
    # ITG live www (from commUtil.js — publicly accessible)
    "itg-live.www.hp.com",
)

# Methone virtual-agent API endpoints (discovered from SSF HPWPD/HPDIA scripts)
_METHONE_PROD = "https://api2-methone.hpcloud.hp.com/v4"
_METHONE_ITG = "https://api2-itg-methone.hpcloud.hp.com/v2"

# SUDF diagnostic tool scripts
_SUDF_SCRIPTS = (
    "SSF.Common.js",
    "SSF.HPDIA.js",
    "SSF.HPWPD.js",
)

# Known direct-download tool files on ftp.hp.com (discovered from SUDF scripts)
_FTP_TOOL_PATHS = (
    "pub/softlib/software13/HPSA/HPSupportSolutionsFramework-13.0.1.131.exe",
    "pub/softlib/software13/HPSA/HPSupportSolutionsFramework-12.15.14.3.exe",
)

_REQUEST_TIMEOUT = 30

# Navigation API endpoint for discovering product categories dynamically.
_NAV_URL = f"{_BASE}/wcc-services/navigation"

# Keys used to traverse HP's navigation tree structures recursively.
_NAV_CHILD_KEYS = (
    "children", "subCategories", "subCategoryList",
    "items", "categories", "navigationItems",
    "menuItems", "childNodes",
)

# Pool of User-Agent strings — rotated across request batches to reduce
# the chance of a single fingerprint hitting Akamai rate limits.
_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:128.0) "
    "Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0",
)

_HEADERS: dict[str, str] = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "Referer": "https://support.hp.com/us-en/drivers",
    "Origin": "https://support.hp.com",
    "User-Agent": _USER_AGENTS[0],
}

# Minimum delay (seconds) between API requests to avoid Akamai rate
# limits.  Curl testing shows ~45 burst requests trigger a 5-minute
# IP-level ban; 1 req/s sustains indefinitely.
_REQUEST_DELAY = 0.35


def _strip_bom(text: str | None) -> str:
    """Strip BOM (U+FEFF) and whitespace from a string.

    HP's API often returns driver titles with a BOM prefix character
    (observed in HAR traffic for localized responses).
    """
    return (text or "").strip().lstrip("\ufeff").strip()


# Placeholder values the HP API may return instead of real data.
_PLACEHOLDER_VALUES = frozenset({"n/a", "none", "null", ""})


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
        dynamically via HP's navigation and search APIs.  There is **no**
        limit on the number of products processed — all discovered
        products are scanned for files.
        """
        entries: list[FileEntry] = []
        cc, lc = self._extract_locale(url)
        # Initialize rate-limit tracking state
        self._consecutive_403s = 0
        self._ua_index = 0
        self._hp_session = None  # will be lazily created by _get_session()
        log.info("[HP] ── Starting HP support file discovery ──")
        log.info("[HP] URL: %s", url)
        log.info("[HP] Locale: %s-%s", cc, lc)

        # 1. Try extracting OID directly from the URL
        oid = self._extract_oid(url)

        # 2. If no numeric OID, try resolving via SEO name → search API
        if not oid:
            seo_name = self._extract_seo_name(url)
            if seo_name:
                log.info("[HP] No OID in URL — searching for '%s' …", seo_name)
                oid = self._resolve_oid_by_search(seo_name, cc, lc)
            else:
                log.info("[HP] No OID and no SEO name in URL — will scan full catalog")

        if oid:
            # Single-product mode: fetch files for this one product
            log.info("[HP] ── Single-product mode: OID=%s ──", oid)
            prod_name = self._extract_seo_name(url) or oid
            prod_name = prod_name.replace("-", " ").title()
            before = len(entries)
            self._collect_files_for_product(oid, cc, lc, entries,
                                            product_name=prod_name)
            log.info("[HP] Drivers/software: %d files found", len(entries) - before)
            # Also fetch manuals and security alerts for this product
            manuals = self._fetch_manuals(oid, cc, lc,
                                          product_name=prod_name)
            entries.extend(manuals)
            alerts = self._fetch_security_alerts(oid, cc, lc,
                                                 product_name=prod_name)
            entries.extend(alerts)
            log.info("[HP] Product total: %d files (drivers) + %d manuals + %d alerts",
                     len(entries) - len(manuals) - len(alerts), len(manuals), len(alerts))
        else:
            # Catalog mode: discover products via navigation + search APIs
            log.info("[HP] ── Catalog mode: discovering all products dynamically ──")
            product_oids = self._discover_catalog_products(cc, lc)
            log.info("[HP] Catalog: found %d products to scan", len(product_oids))
            for i, (prod_oid, prod_name) in enumerate(product_oids, 1):
                before = len(entries)
                log.info("[HP] [%d/%d] Scanning: %s (OID=%s) …",
                         i, len(product_oids), prod_name, prod_oid)
                # Adaptive delay when rate-limited
                if self._consecutive_403s >= 5:
                    delay = min(self._consecutive_403s, 30)
                    log.info("[HP]   Rate-limit backoff: waiting %ds …", delay)
                    time.sleep(delay)
                self._collect_files_for_product(
                    prod_oid, cc, lc, entries,
                    product_name=prod_name,
                )
                manuals = self._fetch_manuals(prod_oid, cc, lc,
                                              product_name=prod_name)
                entries.extend(manuals)
                alerts = self._fetch_security_alerts(
                    prod_oid, cc, lc, product_name=prod_name)
                entries.extend(alerts)
                added = len(entries) - before
                if added:
                    log.info("[HP] [%d/%d] → %d files found (total so far: %d)",
                             i, len(product_oids), added, len(entries))

        # Collect HP diagnostics tools and HPSA framework downloads
        log.info("[HP] ── Collecting diagnostics tools & HPSA framework ──")
        diag = self._collect_diagnostics_tools()
        entries.extend(diag)

        # Probe staging/QA endpoints from JS bundle for additional files
        log.info("[HP] ── Probing staging/QA/developer endpoints ──")
        staging = self._probe_staging_endpoints(cc, lc)
        entries.extend(staging)

        # Deduplicate by URL
        seen_urls: set[str] = set()
        unique: list[FileEntry] = []
        for entry in entries:
            u = entry.get("url", "")
            if u and u not in seen_urls:
                seen_urls.add(u)
                unique.append(entry)

        log.info("[HP] ── Discovery complete: %d unique files from %d total ──",
                 len(unique), len(entries))
        return unique

    def page_urls(self, url: str) -> list[str]:
        """Discover HP support page URLs for deeper crawling.

        Parses the support page HTML and HP's navigation API to find
        product pages, category pages, and document pages that the
        regular HTML link extractor cannot see (because support.hp.com
        is an Angular SPA).
        """
        cc, lc = self._extract_locale(url)
        pages: list[str] = []
        seen: set[str] = set()

        def _add(u: str) -> None:
            if u and u not in seen:
                seen.add(u)
                pages.append(u)

        # 1. Discover product pages from the HTML
        for oid, name in self._discover_products_from_html(cc, lc):
            _add(f"{_BASE}/{cc}-{lc}/drivers/{oid}")

        # 2. Add category page links from the navigation API
        try:
            resp = self._api_get(
                _NAV_URL,
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.ok:
                data = resp.json()
                self._collect_nav_page_urls(
                    data.get("data") or data, cc, lc, _add,
                )
        except Exception as exc:
            log.debug("[HP] Navigation page URL discovery failed: %s", exc)

        # 3. Add sitemap URLs from HP's sitemap API
        try:
            resp = self._api_get(
                _SITEMAP_URL,
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.ok:
                sdata = resp.json().get("data") or {}
                if isinstance(sdata, dict):
                    for _key, urls in sdata.items():
                        if isinstance(urls, list):
                            for u in urls:
                                if isinstance(u, str):
                                    _add(u if u.startswith("http") else _BASE + u)
                                elif isinstance(u, dict):
                                    _add(u.get("href", "") or u.get("url", ""))
                elif isinstance(sdata, list):
                    for u in sdata:
                        if isinstance(u, str):
                            _add(u if u.startswith("http") else _BASE + u)
        except Exception as exc:
            log.debug("[HP] Sitemap page URL discovery failed: %s", exc)

        # 4. Add FTP and diagnostics resource pages
        _add(f"{_FTP_HP}/pub/softlib/")
        _add(f"{_SUDF_RESOURCES}/DMDScripts/")

        # 5. Probe known staging/QA hosts
        for host in _STAGING_HOSTS:
            _add(f"https://{host}/")

        log.info("[HP] Discovered %d additional page URLs for crawling",
                 len(pages))
        return pages

    def _collect_nav_page_urls(
        self,
        node: dict | list,
        cc: str,
        lc: str,
        add_fn: Callable[[str], None],
    ) -> None:
        """Recursively walk nav tree and add page URLs."""
        if isinstance(node, list):
            for item in node:
                self._collect_nav_page_urls(item, cc, lc, add_fn)
            return
        if not isinstance(node, dict):
            return

        # Check for URL/href/link keys
        for key in ("url", "href", "link", "targetUrl"):
            val = node.get(key, "")
            if val and isinstance(val, str):
                if not val.startswith("http"):
                    val = _BASE + val
                add_fn(val)

        # Recurse into child structures
        for key in _NAV_CHILD_KEYS:
            child = node.get(key)
            if child:
                self._collect_nav_page_urls(child, cc, lc, add_fn)

    # ── Catalog discovery ────────────────────────────────────────────

    def _discover_catalog_products(
        self, cc: str, lc: str,
    ) -> list[tuple[str, str]]:
        """Dynamically discover products from HP's category and search APIs.

        Returns a list of ``(oid, product_name)`` tuples with **no**
        hard limit — all products found are returned.

        Discovery flow (curl-verified):
        1. Fetch device types from CMS product finder (always works,
           returns Printer/Laptop/Desktop/Other/headset/Others).
        2. Extract product-type search terms from the Angular main.js
           bundle (tablet, server, monitor, projector, etc.).
        3. Fallback: ``/s/init`` and ``/wcc-services/navigation`` APIs.
        4. For each category, query HP's search API to find products.
        5. Collect all unique ``(oid, name)`` pairs across all categories.
        6. If no products found from APIs, parse the support page HTML
           for product links as a last resort.
        """
        seen_oids: set[str] = set()
        products: list[tuple[str, str]] = []

        # 1. CMS product finder — most reliable source (curl-verified)
        categories = self._fetch_device_types_from_cms(cc, lc)

        # 2. Angular JS bundle — extracts product type names dynamically
        js_terms = self._extract_search_terms_from_js(cc, lc)
        for t in js_terms:
            if t.lower() not in {c.lower() for c in categories}:
                categories.append(t)

        # 3. Navigation API fallback (may return 400 on newer backend)
        if not categories:
            log.info("[HP] CMS + JS empty — trying navigation API …")
            nav_cats = self._fetch_navigation_categories(cc, lc)
            categories.extend(nav_cats)

        # 4. /s/init fallback
        if not categories:
            log.info("[HP] Navigation API empty — trying /s/init …")
            init_cats = self._fetch_init_categories(cc, lc)
            categories.extend(init_cats)

        log.info("[HP] Discovered %d categories to scan", len(categories))

        for idx, query in enumerate(categories, 1):
            found = self._search_products(query, cc, lc)
            new_count = 0
            for oid, name in found:
                if oid not in seen_oids:
                    seen_oids.add(oid)
                    products.append((oid, name))
                    new_count += 1
            if new_count:
                log.info("[HP] Category [%d/%d] '%s' → %d new products (total %d)",
                         idx, len(categories), query, new_count, len(products))

        # Additional discovery: fetch popular printers (has OIDs in URLs)
        popular = self._fetch_popular_products(cc, lc)
        for oid, name in popular:
            if oid not in seen_oids:
                seen_oids.add(oid)
                products.append((oid, name))
        if popular:
            log.info("[HP] Popular products: %d new products (total %d)",
                     len(popular), len(products))

        # Last resort: parse the support page HTML for product links
        if not products:
            log.info("[HP] No products found from APIs — "
                     "parsing support page HTML for product links")
            html_products = self._discover_products_from_html(cc, lc)
            for oid, name in html_products:
                if oid not in seen_oids:
                    seen_oids.add(oid)
                    products.append((oid, name))

        return products

    def _fetch_navigation_categories(
        self, cc: str, lc: str,
    ) -> list[str]:
        """Dynamically fetch product categories from HP's navigation API.

        Calls ``/wcc-services/navigation?cc=…&lc=…`` to get the site's
        full category tree and extracts all category/sub-category names
        to use as search queries.
        """
        categories: list[str] = []
        try:
            log.info("[HP] Fetching categories from /wcc-services/navigation …")
            resp = self._api_get(
                _NAV_URL,
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                log.info("[HP] Navigation API returned HTTP %d", resp.status_code)
                return categories
            data = resp.json()
            # Walk the navigation tree to extract category names
            nav_data = data.get("data") or data
            self._walk_nav_tree(nav_data, categories)
            if not categories:
                log.info("[HP] Navigation API returned data but no categories extracted")
            else:
                log.info("[HP] Navigation API: extracted %d categories", len(categories))
        except Exception as exc:
            log.info("[HP] Navigation API failed: %s", exc)
        return categories

    def _walk_nav_tree(self, node: dict | list, out: list[str]) -> None:
        """Recursively walk a navigation tree and collect category names
        suitable for product search queries."""
        if isinstance(node, list):
            for item in node:
                self._walk_nav_tree(item, out)
            return
        if not isinstance(node, dict):
            return

        # Collect names from common navigation keys
        for key in ("name", "categoryName", "label", "title"):
            val = node.get(key, "")
            if val and isinstance(val, str) and len(val) > 2:
                out.append(val)

        # Recurse into child structures
        for key in _NAV_CHILD_KEYS:
            child = node.get(key)
            if child:
                self._walk_nav_tree(child, out)

    def _fetch_init_categories(
        self, cc: str, lc: str,
    ) -> list[str]:
        """Fallback: derive search queries from the ``/s/init`` API.

        The init response contains ``supportCategories`` and
        ``productFinder`` data that can yield category keywords.
        """
        categories: list[str] = []
        try:
            resp = self._api_get(
                _INIT_URL,
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                log.info("[HP] /s/init returned HTTP %d", resp.status_code)
                return categories
            raw = resp.json()
            data = raw.get("data") or raw
            if not isinstance(data, dict):
                data = {}

            # Extract from supportCategories
            for cat in (data.get("supportCategories") or []):
                if not isinstance(cat, dict):
                    continue
                name = cat.get("name", "") or cat.get("label", "")
                if name:
                    categories.append(name)

            # Extract from productFinder categories
            pf = data.get("productFinder") or {}
            if isinstance(pf, dict):
                for cat in (pf.get("categories") or []):
                    if not isinstance(cat, dict):
                        continue
                    name = cat.get("name", "") or cat.get("label", "")
                    if name:
                        categories.append(name)
                    for sub in (cat.get("subCategories") or []):
                        if not isinstance(sub, dict):
                            continue
                        sub_name = sub.get("name", "") or sub.get("label", "")
                        if sub_name:
                            categories.append(sub_name)

            # Extract from header/menu navigation
            header = data.get("header") or {}
            if isinstance(header, dict):
                for nav in (header.get("navigation") or []):
                    if not isinstance(nav, dict):
                        continue
                    name = nav.get("name", "") or nav.get("label", "")
                    if name:
                        categories.append(name)

            if not categories:
                log.info("[HP] /s/init returned data but no categories extracted")
        except Exception as exc:
            log.info("[HP] /s/init category extraction failed: %s", exc)
        return categories

    def _fetch_device_types_from_cms(
        self, cc: str, lc: str,
    ) -> list[str]:
        """Fetch device type names from CMS product-finder and product-icons.

        HAR analysis shows ``/wcc-services/cms-v2/{locale}/wcc_swd_pfinder``
        returns device types (printer, laptop, desktop, etc.) with their
        ``deviceType`` and ``toolTipTitle`` fields.
        """
        types: list[str] = []
        seen: set[str] = set()
        for cms_key in ("wcc_swd_pfinder", "wcc_sitehome_producticons"):
            try:
                resp = self._api_get(
                    f"{_CMS_URL}/{cc}-{lc}/{cms_key}",
                    headers=_HEADERS,
                    timeout=_REQUEST_TIMEOUT,
                )
                if not resp.ok:
                    continue
                data = resp.json().get("data") or []
                if not isinstance(data, list):
                    continue
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    for key in ("toolTipTitle", "deviceType", "title"):
                        val = (item.get(key) or "").strip()
                        if val and val.lower() not in seen:
                            seen.add(val.lower())
                            types.append(val)
            except Exception:
                pass
        if types:
            log.info("[HP] CMS device types: %s", types)
        return types

    def _extract_search_terms_from_js(
        self, cc: str, lc: str,
    ) -> list[str]:
        """Extract product type search terms from the Angular main.js bundle.

        Downloads the support page HTML to find the main.js URL, then
        downloads and scans the JS bundle for product-type names
        (Laptop, Printer, Desktop, etc.) that HP uses in its product
        finder.

        This is a dynamic fallback: the terms come from the live JS
        bundle, not from a static list.
        """
        terms: list[str] = []
        try:
            # 1. Fetch the main page to discover the main.js bundle URL
            resp = self._api_get(
                f"{_BASE}/{cc}-{lc}/",
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if not resp.ok:
                log.info("[HP] Could not fetch support page for JS analysis")
                return terms

            # Find main.*.js script tag
            main_js_match = re.search(
                r'src="(/wcc-assets/main\.[a-f0-9]+\.js)"', resp.text,
            )
            if not main_js_match:
                log.info("[HP] Could not find main.js bundle in page HTML")
                return terms

            main_js_url = f"{_BASE}{main_js_match.group(1)}"
            log.info("[HP] Downloading Angular bundle: %s", main_js_url)

            # 2. Fetch main.js with proper headers
            js_resp = self._api_get(
                main_js_url,
                headers={
                    **_HEADERS,
                    "Accept": "*/*",
                    "Referer": f"{_BASE}/{cc}-{lc}/",
                },
                timeout=60,
            )
            if not js_resp.ok:
                log.info("[HP] main.js download failed: HTTP %d", js_resp.status_code)
                return terms

            js_text = js_resp.text

            # 3. Extract product type names from the JS bundle.
            #    The Angular app references product types like Laptop,
            #    Printer, Desktop, Monitor, etc. in its code.  We search
            #    for these case-insensitively and normalise to singular
            #    lowercase form for use as search queries.
            seen: set[str] = set()
            for m in _PRODUCT_TYPE_RE.finditer(js_text):
                raw = m.group(0)
                # Normalise: lowercase, remove a single trailing 's'
                normalised = raw.lower()
                if normalised.endswith("s"):
                    normalised = normalised[:-1]
                if normalised not in seen:
                    seen.add(normalised)
                    terms.append(normalised)

            log.info("[HP] Extracted %d product-type search terms from JS",
                     len(terms))
        except Exception as exc:
            log.info("[HP] JS bundle analysis failed: %s", exc)
        return terms

    def _search_products(
        self, query: str, cc: str, lc: str,
    ) -> list[tuple[str, str]]:
        """Search HP and return ``(oid, name)`` tuples for all products
        found.

        HAR analysis shows HP's SPA uses two search contexts:
        - ``context=pdp`` — general product pages
        - ``context=swd`` with ``navigation=false`` — driver download pages
        Both are tried for maximum coverage.
        """
        results: list[tuple[str, str]] = []
        seen: set[str] = set()

        # Try both contexts: 'pdp' for general and 'swd' for drivers
        for ctx in ("swd", "pdp"):
            try:
                params: dict = {"q": query, "context": ctx}
                if ctx == "swd":
                    params["navigation"] = "false"
                resp = self._api_get(
                    f"{_SEARCH_URL}/{cc}-{lc}",
                    params=params,
                    headers=_HEADERS,
                    timeout=_REQUEST_TIMEOUT,
                )
                if not resp.ok:
                    log.info("[HP] Search '%s' (ctx=%s) returned HTTP %d",
                             query, ctx, resp.status_code)
                    continue
                data = resp.json()

                # Primary structure: data.kaaSResponse.data.searchResults.categories[]
                # Note: any of these fields can be JSON null → Python None,
                # so we guard each level with ``or {}``.
                _d = data.get("data") or {}
                _kaas = _d.get("kaaSResponse") or {}
                _kaas_data = _kaas.get("data") or {}
                _sr = _kaas_data.get("searchResults") or {}
                categories = _sr.get("categories") or []
                for cat in (categories or []):
                    self._extract_products_from_category(cat, results)
                    for sub in cat.get("subCategoryList") or []:
                        self._extract_products_from_category(sub, results)

                # Fallback: try direct structure data.categories[]
                if not results:
                    for cat in (_d.get("categories") or []):
                        self._extract_products_from_category(cat, results)

                # Fallback: try flat productList at top level
                if not results:
                    for prod in (_d.get("productList") or []):
                        target = prod.get("targetUrl", "")
                        name = prod.get("productName", "")
                        m = _OID_PRODUCT_RE.search(target) or _OID_LAST_RE.search(target)
                        if m:
                            results.append((m.group(1), name))

                # Also check verifyResponse for direct product match
                verify = _d.get("verifyResponse") or {}
                if verify and isinstance(verify, dict):
                    vdata = verify.get("data") or {}
                    if vdata and isinstance(vdata, dict):
                        target_url = vdata.get("targetUrl", "")
                        prod_name = vdata.get("productName", "")
                        if target_url:
                            m = (_OID_PRODUCT_RE.search(target_url) or
                                 _OID_LAST_RE.search(target_url))
                            if m and m.group(1) not in seen:
                                results.append((m.group(1), prod_name or query))
                                seen.add(m.group(1))

            except Exception as exc:
                log.info("[HP] Product search '%s' (ctx=%s) failed: %s",
                         query, ctx, exc)

        # Deduplicate
        unique: list[tuple[str, str]] = []
        for oid, name in results:
            if oid not in seen:
                seen.add(oid)
                unique.append((oid, name))
        return unique

    def _discover_products_from_html(
        self, cc: str, lc: str,
    ) -> list[tuple[str, str]]:
        """Parse the HP support homepage HTML to find product page links.

        This is a last-resort fallback when the JSON APIs return no
        products.  It fetches the HTML of the support page and extracts
        links matching product URL patterns.
        """
        results: list[tuple[str, str]] = []
        try:
            url = f"{_BASE}/{cc}-{lc}/"
            resp = self._api_get(url, headers=_HEADERS, timeout=_REQUEST_TIMEOUT)
            if not resp.ok:
                log.info("[HP] Support page HTML fetch returned HTTP %d",
                         resp.status_code)
                return results
            html = resp.text

            # Find all links matching HP product/driver URL patterns
            for m in _HTML_PRODUCT_LINK_RE.finditer(html):
                link = m.group(1)
                if not link.startswith("http"):
                    link = _BASE + link
                oid = self._extract_oid(link)
                if oid:
                    # Use last path segment as product name, or OID as fallback
                    parts = urllib.parse.urlparse(link).path.strip("/").split("/")
                    raw = parts[-1] if parts else ""
                    name = raw.replace("-", " ").title() if raw else oid
                    results.append((oid, name or oid))
            log.info("[HP] Found %d product links in HTML", len(results))
        except Exception as exc:
            log.info("[HP] HTML product discovery failed: %s", exc)
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

    def _fetch_popular_products(
        self, cc: str, lc: str,
    ) -> list[tuple[str, str]]:
        """Fetch popular products from HP's ``/swd-v2/popularPrinters`` API.

        HAR analysis shows this endpoint returns product titles and URLs
        with ``h_product=<OID>`` parameters.  Returns ``(oid, name)`` pairs.
        """
        results: list[tuple[str, str]] = []
        try:
            resp = self._api_get(
                f"{_SWD_POPULAR_PRINTERS_URL}/{cc}-{lc}",
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return results
            data = resp.json().get("data") or []
            if not isinstance(data, list):
                return results
            for item in data:
                title = item.get("productTitle", "")
                url = item.get("productUrl", "")
                # Extract h_product=<OID> from the navigation URL
                m = re.search(r"h_product=(\d+)", url)
                if m and title:
                    results.append((m.group(1), title))
            if results:
                log.info("[HP] popularPrinters: discovered %d products",
                         len(results))
        except Exception as exc:
            log.info("[HP] popularPrinters fetch failed: %s", exc)
        return results

    def _fetch_product_specs(
        self, oid: str, cc: str, lc: str,
    ) -> dict:
        """Fetch product specifications from ``/wcc-services/profile/devices/warranty/specs``.

        HAR analysis shows this endpoint returns:
        - ``productName``: human-readable name (e.g. "HP Pavilion - 15-ec0004la")
        - ``productSeriesName``: series name
        - ``productLineCode``, ``productNumberOid``, ``productNameOid``
        - ``imageUri``: product image URL

        Returns a dict with extracted fields, or empty dict on failure.
        """
        try:
            resp = self._api_post(
                _WARRANTY_SPECS_URL,
                json={
                    "cc": cc,
                    "lc": lc,
                    "utcOffset": "M0600",
                    "devices": [{
                        "seriesOid": None,
                        "modelOid": int(oid) if oid.isdigit() else None,
                        "serialNumber": None,
                        "displayProductNumber": None,
                        "countryOfPurchase": cc,
                    }],
                    "captchaToken": "",
                },
                params={"cache": "true"},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                log.info("[HP]   Specs API returned HTTP %d for OID=%s",
                         resp.status_code, oid)
                return {}
            data = resp.json().get("data") or {}
            if not data:
                return {}
            devices = (data.get("devices") or [])
            if not devices:
                return {}
            specs_data = (devices[0].get("productSpecs") or {})
            if isinstance(specs_data, dict):
                # The specs data may be nested inside its own data key
                inner = specs_data.get("data") or specs_data
                return {
                    "productName": inner.get("productName", ""),
                    "productSeriesName": inner.get("productSeriesName", ""),
                    "productLineCode": inner.get("productLineCode", ""),
                    "productNumberOid": inner.get("productNumberOid"),
                    "productNameOid": inner.get("productNameOid"),
                    "productSeriesOid": inner.get("productSeriesOid"),
                    "productBigSeriesOid": inner.get("productBigSeriesOid"),
                    "imageUri": inner.get("imageUri", ""),
                }
        except Exception as exc:
            log.info("[HP] Product specs fetch failed for OID=%s: %s", oid, exc)
        return {}

    def _collect_files_for_product(
        self,
        oid: str,
        cc: str,
        lc: str,
        entries: list[FileEntry],
        product_name: str = "",
    ) -> None:
        """Fetch OS versions and driver metadata for a single product
        and append discovered :class:`FileEntry` items to *entries*.

        Uses the warranty/specs API to resolve the real product name and
        additional OID fields (productLineCode, productNumberOid,
        productNameOid) that HP's SPA includes in the driverDetails POST
        body for more accurate results.
        """
        # Resolve real product name from specs API when only a URL-derived
        # name is available (e.g. "hp-pavilion-gaming" → "HP Pavilion - 15-ec0004la")
        specs = self._fetch_product_specs(oid, cc, lc)
        # Replace the product name with the real one from specs if the
        # current name looks URL-derived (contains hyphens) or is missing
        if specs.get("productName") and (
            not product_name or "-" in product_name
        ):
            product_name = specs["productName"]
            log.info("[HP] Resolved product name: %s", product_name)

        os_list = self._fetch_os_versions(oid, cc, lc)
        if not os_list:
            log.info("[HP]   No OS versions from API — trying /s/init fallback")
            os_list = self._detect_os_from_init(cc, lc)
        if not os_list:
            log.info("[HP]   No OS versions available — skipping driver fetch")

        if os_list:
            # Summarise platforms being queried
            plat_counts: dict[str, int] = {}
            for v in os_list:
                pn = v.get("platformName") or "Unknown"
                plat_counts[pn] = plat_counts.get(pn, 0) + 1
            log.info(
                "[HP]   Querying %d OS versions across %d platforms: %s",
                len(os_list), len(plat_counts),
                ", ".join(f"{n} ({c})" for n, c in plat_counts.items()),
            )

        # Enrich OS info dicts with product-specific fields from specs
        for os_info in os_list:
            if specs.get("productLineCode"):
                os_info.setdefault("productLineCode", specs["productLineCode"])
            if specs.get("productNumberOid"):
                os_info.setdefault("productNumberOid", specs["productNumberOid"])
            if specs.get("productNameOid"):
                os_info.setdefault("productNameOid", specs["productNameOid"])

        total_os_entries = 0
        consecutive_driver_403s = 0
        for idx, os_info in enumerate(os_list):
            # Rate-limit detection: if driverDetails returned 403 three
            # times in a row for this product, stop trying more OS versions.
            if consecutive_driver_403s >= 3:
                remaining = len(os_list) - idx
                log.info(
                    "[HP]   Rate-limited — skipping remaining %d OS versions "
                    "for this product",
                    remaining,
                )
                break
            try:
                os_entries, got_403 = self._fetch_driver_entries(
                    oid, os_info, cc, lc,
                    product_name=product_name,
                )
                if got_403:
                    consecutive_driver_403s += 1
                    self._consecutive_403s += 1
                else:
                    consecutive_driver_403s = 0
                    self._consecutive_403s = 0
                entries.extend(os_entries)
                total_os_entries += len(os_entries)
                if os_entries:
                    log.info("[HP]   OS '%s' → %d drivers/software",
                             os_info.get("name", "?"), len(os_entries))
            except Exception as exc:
                log.info("[HP]   Error fetching drivers for OS %s: %s",
                         os_info.get("name", "?"), exc)
        if total_os_entries:
            log.info("[HP]   Product total: %d driver/software entries",
                     total_os_entries)

    # ── Manuals endpoint ─────────────────────────────────────────────

    def _fetch_manuals(
        self, oid: str, cc: str, lc: str,
        product_name: str = "",
    ) -> list[FileEntry]:
        """Fetch product manuals from ``/wcc-services/pdp/manuals/getManuals``.

        Returns :class:`FileEntry` dicts for each manual PDF/document.
        """
        entries: list[FileEntry] = []
        try:
            resp = self._api_get(
                _PDP_MANUALS_URL,
                params={
                    "productID": oid,
                    "countryCode": cc,
                    "languageCode": lc,
                    "browserLangCode": lc,
                },
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return entries
            data = resp.json()
            if data.get("code") not in (200, None):
                return entries
            manuals = (data.get("data") or {}).get("manuals", [])
            for m in manuals:
                url = m.get("url", "")
                if url and url.startswith("http"):
                    entries.append(FileEntry(
                        name=m.get("title", url.rsplit("/", 1)[-1]),
                        url=url,
                        size=str(m.get("fileSize") or ""),
                        version="",
                        release_date="",
                        category="Manual",
                        os="",
                        description=m.get("fileType", ""),
                        source="pdp/manuals/getManuals",
                        product=product_name,
                    ))
            if entries:
                log.info("[HP] Found %d manuals for OID=%s", len(entries), oid)
        except Exception as exc:
            log.debug("[HP] Manuals fetch failed for OID=%s: %s", oid, exc)
        return entries

    # ── Security alerts endpoint ─────────────────────────────────────

    def _fetch_security_alerts(
        self, oid: str, cc: str, lc: str,
        product_name: str = "",
    ) -> list[FileEntry]:
        """Fetch security advisories from
        ``/wcc-services/pdp/securityalerts/{locale}/{oid}``.

        Returns :class:`FileEntry` dicts for alerts that have links.
        """
        entries: list[FileEntry] = []
        try:
            resp = self._api_get(
                f"{_PDP_SECURITY_ALERTS_URL}/{cc}-{lc}/{oid}",
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return entries
            data = resp.json()
            # HP API returns code=200 on success or code=204 when the
            # endpoint has no data.  Both are valid JSON responses.
            if data.get("code") not in (200, 204, None):
                return entries
            alerts = (data.get("data") or {}).get("securityAlerts", [])
            for a in alerts:
                link = a.get("link", "") or a.get("renderLink", "")
                if link:
                    if not link.startswith("http"):
                        link = _BASE + link
                    entries.append(FileEntry(
                        name=a.get("title", link.rsplit("/", 1)[-1]),
                        url=link,
                        size="",
                        version="",
                        release_date=(
                            a.get("contentUpdateDate", "").split("T")[0]
                            if a.get("contentUpdateDate") else ""
                        ),
                        category="Security Advisory",
                        os="",
                        description=f"Severity: {a.get('severity', 'N/A')}",
                        source="pdp/securityalerts",
                        product=product_name,
                    ))
            if entries:
                log.info("[HP] Found %d security alerts for OID=%s",
                         len(entries), oid)
        except Exception as exc:
            log.debug("[HP] Security alerts fetch failed for OID=%s: %s",
                      oid, exc)
        return entries

    # ── Diagnostics tools ────────────────────────────────────────────

    def _collect_diagnostics_tools(self) -> list[FileEntry]:
        """Discover HP diagnostics tool downloads from SUDF scripts
        and ftp.hp.com.

        Dynamically downloads the SSF JavaScript files from
        ``sudf-resources.hpcloud.hp.com`` and extracts download URLs
        for HP Support Solutions Framework and other diagnostic tools.
        Also probes the known FTP tool paths.
        """
        entries: list[FileEntry] = []
        seen_urls: set[str] = set()

        def _add(url: str, name: str, cat: str, src: str = "") -> None:
            if url and url not in seen_urls:
                seen_urls.add(url)
                entries.append(FileEntry(
                    name=name or url.rsplit("/", 1)[-1],
                    url=url,
                    size="",
                    version="",
                    release_date="",
                    category=cat,
                    os="",
                    description="HP Support diagnostics tool",
                    source=src,
                    product="",
                ))

        # 1. Parse SUDF scripts for download URLs
        for script_name in _SUDF_SCRIPTS:
            try:
                log.info("[HP] Fetching SUDF script: %s", script_name)
                resp = self._api_get(
                    f"{_SUDF_RESOURCES}/DMDScripts/{script_name}",
                    headers={**_HEADERS, "Accept": "*/*"},
                    timeout=_REQUEST_TIMEOUT,
                )
                if resp.ok:
                    # Add the script itself
                    _add(
                        f"{_SUDF_RESOURCES}/DMDScripts/{script_name}",
                        script_name,
                        "Diagnostics Script",
                        "sudf-resources.hpcloud.hp.com",
                    )
                    # Extract ftp.hp.com download URLs from the script.
                    # Only accept URLs under the known /pub/softlib/ path.
                    for m in re.finditer(
                        r'https://ftp\.hp\.com/pub/softlib/[^\s"\'<>]+\.exe',
                        resp.text,
                    ):
                        _add(m.group(0), "", "Diagnostics Tool",
                             "ftp.hp.com (from SUDF script)")
            except Exception as exc:
                log.info("[HP] SUDF script %s fetch failed: %s",
                         script_name, exc)

        # 2. Probe known FTP tool paths (ftp.hp.com is a separate domain
        #    from support.hp.com — not subject to Akamai rate limits, so
        #    direct session.head() is used instead of _api_get()).
        log.info("[HP] Probing %d FTP tool paths …", len(_FTP_TOOL_PATHS))
        sess = self._get_session()
        for path in _FTP_TOOL_PATHS:
            url = f"{_FTP_HP}/{path}"
            if url not in seen_urls:
                try:
                    head = sess.head(url, timeout=10, allow_redirects=True)
                    if head.ok:
                        size = head.headers.get("Content-Length", "")
                        entries.append(FileEntry(
                            name=path.rsplit("/", 1)[-1],
                            url=url,
                            size=size,
                            version="",
                            release_date="",
                            category="Diagnostics Tool",
                            os="",
                            description="HP Support Solutions Framework",
                            source="ftp.hp.com",
                            product="",
                        ))
                        seen_urls.add(url)
                except Exception:
                    pass

        if entries:
            log.info("[HP] Found %d diagnostics tools/scripts", len(entries))
        return entries

    # ── Staging / QA / developer endpoint probing ────────────────────

    def _probe_staging_endpoints(
        self, cc: str, lc: str,
    ) -> list[FileEntry]:
        """Dynamically probe staging / QA / developer HP endpoints.

        Discovered from the Angular main.js bundle:
        - ``qa2.houston.hp.com`` — internal QA
        - ``ppssupport-qa2.houston.hp.com`` — internal QA
        - ``stage.portalshell.int.hp.com`` — staging portal (CloudFront)
        - ``stg.cd.id.hp.com`` / ``account.stg.cd.id.hp.com`` — staging
        - ``api2-methone.hpcloud.hp.com`` — Methone virtual-agent (prod)
        - ``api2-itg-methone.hpcloud.hp.com`` — Methone (ITG staging)

        Only accessible endpoints generate entries.  Unreachable hosts
        are silently skipped.
        """
        entries: list[FileEntry] = []
        log.info("[HP] Probing %d staging/QA hosts + 2 Methone APIs …",
                 len(_STAGING_HOSTS))

        for host in _STAGING_HOSTS:
            try:
                resp = self._api_get(
                    f"https://{host}/",
                    headers=_HEADERS,
                    timeout=10,
                    allow_redirects=True,
                )
                if resp.ok:
                    entries.append(FileEntry(
                        name=f"{host} (staging/QA)",
                        url=f"https://{host}/",
                        size=str(len(resp.content)),
                        version="",
                        release_date="",
                        category="Staging/QA Endpoint",
                        os="",
                        description=f"HTTP {resp.status_code} — {resp.headers.get('server', 'unknown')}",
                        source="main.js bundle (staging probe)",
                        product="",
                    ))
                    log.info("[HP] Staging host accessible: %s (HTTP %d)",
                             host, resp.status_code)
                else:
                    log.info("[HP] Staging host %s → HTTP %d (restricted)",
                             host, resp.status_code)
            except Exception:
                log.info("[HP] Staging host %s → unreachable", host)

        # Probe Methone API endpoints
        for methone_url, label in (
            (_METHONE_PROD, "Methone API (prod)"),
            (_METHONE_ITG, "Methone API (ITG staging)"),
        ):
            try:
                resp = self._api_get(
                    methone_url,
                    headers=_HEADERS,
                    timeout=10,
                )
                # Even 403 means the endpoint exists and is reachable
                entries.append(FileEntry(
                    name=label,
                    url=methone_url,
                    size="",
                    version="",
                    release_date="",
                    category="API Endpoint",
                    os="",
                    description=f"HTTP {resp.status_code} — {resp.headers.get('server', 'unknown')}",
                    source="main.js bundle (API probe)",
                    product="",
                ))
                log.info("[HP] Methone endpoint reachable: %s (HTTP %d)",
                         methone_url, resp.status_code)
            except Exception:
                log.info("[HP] Methone endpoint %s → unreachable", methone_url)

        if entries:
            log.info("[HP] Found %d accessible staging/QA/API endpoints",
                     len(entries))
        return entries

    # ── Session & rate-limit helpers ─────────────────────────────────

    def _get_session(self) -> "requests.Session":
        if self.session is not None:
            return self.session
        if self._hp_session is not None:
            return self._hp_session
        import requests as _req
        s = _req.Session()
        s.headers.update(_HEADERS)
        self._hp_session = s
        return s

    def _rotate_ua(self) -> None:
        """Rotate the User-Agent for the next batch of requests."""
        self._ua_index = (self._ua_index + 1) % len(_USER_AGENTS)
        ua = _USER_AGENTS[self._ua_index]
        sess = self._get_session()
        sess.headers["User-Agent"] = ua

    def _api_get(
        self, url: str, **kwargs,
    ) -> "requests.Response":
        """GET with per-request delay and 403 backoff.

        Wraps ``session.get()`` with:

        1. A minimum delay between requests (``_REQUEST_DELAY``)
        2. Automatic retry on HTTP 403 (Akamai rate-limit): rotate UA,
           clear cookies, wait 60 s, then retry once.
        """
        time.sleep(_REQUEST_DELAY)
        sess = self._get_session()
        kwargs.setdefault("headers", _HEADERS)
        kwargs.setdefault("timeout", _REQUEST_TIMEOUT)
        resp = sess.get(url, **kwargs)
        if resp.status_code == 403:
            self._handle_rate_limit()
            resp = sess.get(url, **kwargs)
        return resp

    def _api_post(
        self, url: str, **kwargs,
    ) -> "requests.Response":
        """POST with per-request delay and 403 backoff."""
        time.sleep(_REQUEST_DELAY)
        sess = self._get_session()
        kwargs.setdefault("headers", _HEADERS)
        kwargs.setdefault("timeout", _REQUEST_TIMEOUT)
        resp = sess.post(url, **kwargs)
        if resp.status_code == 403:
            self._handle_rate_limit()
            resp = sess.post(url, **kwargs)
        return resp

    def _handle_rate_limit(self) -> None:
        """Handle an Akamai 403 rate-limit: rotate UA, clear cookies,
        and wait for the ban to expire.

        Curl debugging shows:
        - ~45 burst requests trigger a 5-minute IP-level ban
        - The ban applies to ALL support.hp.com endpoints
        - No header trick (X-Forwarded-For, True-Client-IP) bypasses it
        - After 5 minutes the ban lifts automatically
        - 1 req/s sustained rate avoids triggering the ban
        """
        self._rotate_ua()
        sess = self._get_session()
        sess.cookies.clear()
        wait = 60
        log.info("[HP]   ⚠ Rate-limited (HTTP 403) — rotating UA, "
                 "clearing cookies, waiting %ds …", wait)
        time.sleep(wait)

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
        # Convert seo-name to search query: "hp-officejet-3830" → "hp officejet 3830"
        query = seo_name.replace("-", " ")
        try:
            resp = self._api_get(
                f"{_SEARCH_URL}/{cc}-{lc}",
                params={"q": query, "context": "pdp"},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                return None
            data = resp.json()
            # Walk the nested category/product tree
            _d = data.get("data") or {}
            _kaas = _d.get("kaaSResponse") or {}
            _kaas_data = _kaas.get("data") or {}
            _sr = _kaas_data.get("searchResults") or {}
            categories = _sr.get("categories") or []
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

        Parses three response structures from HP's API:

        1. ``osAvailablePlatformsAnsOS.osPlatforms[]`` — primary structure
        2. ``platformList[]`` — alternative flat structure
        3. ``osversions[]`` — grouped by OS family (e.g. "Windows 10")

        Successful results are cached so they can be reused for products
        where the API returns no data (e.g. due to rate limiting during
        large catalog crawls).
        """
        try:
            resp = self._api_get(
                _SWD_OS_URL,
                params={"cc": cc, "lc": lc, "productOid": oid},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                log.info("[HP]   osVersionData HTTP %d for OID=%s",
                         resp.status_code, oid)
                return []
            data = resp.json().get("data") or {}

            os_versions: list[dict] = []

            # Primary structure: osAvailablePlatformsAnsOS.osPlatforms[]
            platforms_data = (data.get("osAvailablePlatformsAnsOS") or {})
            platforms = (platforms_data.get("osPlatforms") or [])
            for platform in platforms:
                platform_id = platform.get("id", "")
                platform_name = platform.get("name", "")
                for version in (platform.get("osVersions") or []):
                    os_versions.append({
                        "id": version.get("id", ""),
                        "name": version.get("name", ""),
                        "platformId": platform_id,
                        "platformName": platform_name,
                    })

            # Fallback structure 1: platformList[]
            if not os_versions:
                for platform in (data.get("platformList") or []):
                    platform_id = platform.get("platformId", "")
                    platform_name = platform.get("platformName", "")
                    for version in (platform.get("osVersions") or []):
                        os_versions.append({
                            "id": version.get("osTmsId", version.get("id", "")),
                            "name": version.get("osName", version.get("name", "")),
                            "platformId": platform_id,
                            "platformName": platform_name,
                        })

            # Fallback structure 2: osversions[] (flat grouped by OS name)
            if not os_versions:
                for os_group in (data.get("osversions") or []):
                    group_name = os_group.get("name", "")
                    for version in (os_group.get("osVersionList") or []):
                        os_versions.append({
                            "id": version.get("id", ""),
                            "name": version.get("name", group_name),
                            "platformId": "",
                            "platformName": group_name,
                        })

            if os_versions:
                # Collect platform names for logging
                plat_names: dict[str, int] = {}
                for v in os_versions:
                    pn = v.get("platformName") or "Unknown"
                    plat_names[pn] = plat_names.get(pn, 0) + 1
                plat_summary = ", ".join(
                    f"{name} ({cnt})" for name, cnt in plat_names.items()
                )
                log.info("[HP]   Found %d OS versions across %d platforms: %s",
                         len(os_versions), len(plat_names), plat_summary)
            else:
                log.info("[HP]   osVersionData returned empty for OID=%s", oid)
            return os_versions
        except Exception as exc:
            log.info("[HP]   OS version fetch failed for OID=%s: %s", oid, exc)
        return []

    def _detect_os_from_init(
        self, cc: str, lc: str,
    ) -> list[dict]:
        """Dynamically detect the user's OS via ``/wcc-services/s/init``.

        This endpoint returns the detected OS TMS ID based on the
        requesting client's User-Agent.  Used as a last-resort fallback
        when ``osVersionData`` returns no results.
        """
        try:
            resp = self._api_get(
                _INIT_URL,
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                log.info("[HP]   /s/init returned HTTP %d", resp.status_code)
                return []
            data = resp.json().get("data") or {}
            os_info = (data.get("osInfo") or {})
            os_tms_id = os_info.get("osTmsId", "")
            if not os_tms_id:
                return []
            log.info("[HP]   Detected OS from /s/init: TMS ID=%s", os_tms_id)
            return [{
                "id": os_tms_id,
                "name": "Detected OS",
                "platformId": "",
                "platformName": "",
            }]
        except Exception as exc:
            log.info("[HP]   /s/init OS detection failed: %s", exc)
        return []

    # ── Driver / software metadata collection ────────────────────────

    def _fetch_driver_entries(
        self,
        oid: str,
        os_info: dict,
        cc: str,
        lc: str,
        product_name: str = "",
    ) -> tuple[list[FileEntry], bool]:
        """POST to ``/wcc-services/swd-v2/driverDetails`` and extract
        file metadata from the response.

        Returns a tuple of ``(entries, got_403)`` where *entries* is a
        list of :class:`FileEntry` dicts and *got_403* indicates whether
        the API returned HTTP 403 (rate limit).

        The POST payload matches HP's Angular SPA exactly (from JS
        analysis of ``swd-download-page`` component):

        - ``osTMSId``: the OS **version** TMS ID (e.g. Windows 10 64-bit)
        - ``osName``:  the **platform** name (e.g. ``"Windows"``), NOT
          the version name (e.g. ``"Windows 10 (64-bit)"``)
        - ``platformId``: the **platform** TMS ID, NOT the version ID
        - ``productNumberOid``: from product specs (when available)
        """
        os_name = os_info.get("name", "")

        # HP's SPA sends platformName as osName (e.g. "Windows"),
        # NOT the version display name (e.g. "Windows 10 (64-bit)").
        # JS source: ``osName: d.platformName`` in getProductDriversList()
        os_display = os_info.get("platformName", "")

        # JS source: ``platformId: d.platformId`` — this is the PLATFORM
        # TMS ID, NOT the version ID.
        platform_id = os_info.get("platformId", "")

        payload: dict = {
            "cc": cc,
            "lc": lc,
            "productSeriesOid": oid,
            "osTMSId": os_info.get("id", ""),
            "osName": os_display,
            "platformId": platform_id,
        }
        # Include extra fields from product specs if available
        # JS source: ``productLineCode: u?.productLineCode ?? ""``
        payload["productLineCode"] = os_info.get("productLineCode", "")
        # JS source: ``productNumberOid: u.productNumberOid``
        if os_info.get("productNumberOid"):
            payload["productNumberOid"] = os_info["productNumberOid"]
        # JS source: only included when NOT seriesContext
        if os_info.get("productNameOid"):
            payload["productNameOid"] = os_info["productNameOid"]

        entries: list[FileEntry] = []
        try:
            resp = self._api_post(
                _SWD_DRIVERS_URL,
                json=payload,
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if not resp.ok:
                log.info("[HP]   driverDetails HTTP %d for OID=%s",
                          resp.status_code, oid)
                return entries, resp.status_code == 403
            data = resp.json().get("data") or {}

            for sw_type in (data.get("softwareTypes") or []):
                # HAR analysis: category name is in ``accordionNameEn``
                # (canonical English name like "Driver-Network") and
                # ``accordionName`` (localized).  Use English first for
                # consistency across locales.
                category = sw_type.get(
                    "accordionNameEn",
                    sw_type.get(
                        "accordionName",
                        sw_type.get("categoryName", ""),
                    ),
                )
                # Primary structure: softwareDriversList[]
                for drv in sw_type.get("softwareDriversList", []):
                    self._collect_entries_from_driver(
                        drv, category, os_name, entries,
                        product_name=product_name,
                    )
                # Fallback structure: softwareList[]
                for item in sw_type.get("softwareList", []):
                    self._collect_entries_from_item(
                        item, category, os_name, entries,
                        product_name=product_name,
                    )
                    for sub in item.get("subCategory", {}).get("softwareList", []):
                        self._collect_entries_from_item(
                            sub, category, os_name, entries,
                            product_name=product_name,
                        )
        except Exception as exc:
            log.info("[HP]   driverDetails call failed for OID=%s: %s", oid, exc)

        return entries, False

    @staticmethod
    def _collect_entries_from_driver(
        driver: dict,
        category: str,
        os_name: str,
        entries: list[FileEntry],
        product_name: str = "",
    ) -> None:
        """Extract file entries from a ``softwareDriversList`` item."""
        latest = driver.get("latestVersionDriver") or {}

        # The real driver name is in ``title``, NOT ``name`` (which is
        # typically "N/A" or ``None`` in HP's API).  HAR analysis confirms
        # title contains human-readable names like "Realtek RTL8xxx
        # Wireless LAN Drivers".  Titles often have a BOM prefix (U+FEFF)
        # that must be stripped.
        #
        # Fallback chain:
        #   title → name (if not "N/A"/None) → detailInformation.fileName → URL
        drv_title = _strip_bom(latest.get("title"))
        drv_name_raw = _strip_bom(latest.get("name"))
        outer_name = _strip_bom(driver.get("name"))
        drv_name = drv_title or (
            drv_name_raw if drv_name_raw.lower() not in _PLACEHOLDER_VALUES
            else outer_name if outer_name.lower() not in _PLACEHOLDER_VALUES
            else ""
        )

        version = latest.get("version") or ""
        size = latest.get("fileSize") or ""
        release = latest.get("releaseDate") or ""
        release_str = latest.get("releaseDateString") or ""

        desc_html = (latest.get("detailInformation") or {}).get("description", "")
        # Strip HTML tags for plain-text description
        description = re.sub(r"<[^>]+>", " ", desc_html).strip()

        file_url = latest.get("fileUrl") or ""
        if file_url and file_url.startswith("http"):
            # Derive file name from productSoftwareFileList or URL
            sub_files = latest.get("productSoftwareFileList") or []
            if sub_files:
                fname = sub_files[0].get("fileName") or ""
                fsize = sub_files[0].get("fileSize") or size
            else:
                detail_info = latest.get("detailInformation") or {}
                fname = detail_info.get("fileName") or ""
                # HP API may return placeholder strings as fileName
                if fname.lower() in _PLACEHOLDER_VALUES:
                    fname = ""
                if not fname:
                    fname = file_url.rsplit("/", 1)[-1].split("?")[0]
                fsize = size

            # Use the human-readable title as the display name, with the
            # SoftPaq filename appended in parentheses for reference.
            # Only append filename if it differs from the title (compare
            # the base name without extension to avoid redundancy).
            display_name = drv_name or fname
            if drv_name and fname:
                fname_base = fname.rsplit(".", 1)[0].lower()
                drv_base = drv_name.lower()
                if fname_base != drv_base and fname_base not in drv_base:
                    display_name = f"{drv_name} ({fname})"

            # Prefer releaseDateString (human-readable) over ISO release date
            rel_date = release_str or (
                str(release).split("T")[0] if release else ""
            )

            entries.append(FileEntry(
                name=display_name or file_url.rsplit("/", 1)[-1],
                url=file_url,
                size=str(fsize) if fsize else "",
                version=str(version) if version else "",
                release_date=rel_date,
                category=category,
                os=os_name,
                description=description,
                source="swd-v2/driverDetails",
                product=product_name,
            ))

            # Additional sub-files with different URLs
            for sf in itertools.islice(sub_files, 1, None):
                sf_url = sf.get("fileUrl", "")
                if sf_url and sf_url.startswith("http") and sf_url != file_url:
                    sf_name = sf.get("fileName", sf_url.rsplit("/", 1)[-1])
                    sf_display = f"{drv_name} ({sf_name})" if drv_name else sf_name
                    entries.append(FileEntry(
                        name=sf_display,
                        url=sf_url,
                        size=str(sf.get("fileSize", "")) if sf.get("fileSize") else "",
                        version=str(version) if version else "",
                        release_date=str(release).split("T")[0] if release else "",
                        category=category,
                        os=os_name,
                        description=description,
                        source="swd-v2/driverDetails",
                        product=product_name,
                    ))

    @staticmethod
    def _collect_entries_from_item(
        item: dict,
        category: str,
        os_name: str,
        entries: list[FileEntry],
        product_name: str = "",
    ) -> None:
        """Extract file entries from a generic software item dict."""
        file_url = item.get("fileUrl", "")
        # Prefer ``title`` over ``name`` — HP's API uses ``title`` for
        # human-readable names (e.g., "Intel RSTO Driver") while ``name``
        # is often "N/A" or the raw SoftPaq filename.
        item_title = item.get("title", "").strip()
        item_name_raw = item.get("name", "").strip()
        item_name = item_title or (
            item_name_raw if item_name_raw and item_name_raw.upper() != "N/A"
            else ""
        )
        if file_url and file_url.startswith("http"):
            fname = file_url.rsplit("/", 1)[-1].split("?")[0]
            # Only append filename if it differs from the item name
            if item_name:
                fname_base = fname.rsplit(".", 1)[0].lower()
                if fname_base not in item_name.lower():
                    display = f"{item_name} ({fname})"
                else:
                    display = item_name
            else:
                display = fname
            entries.append(FileEntry(
                name=display,
                url=file_url,
                size=str(item.get("fileSize", "")) if item.get("fileSize") else "",
                version=str(item.get("version", "")) if item.get("version") else "",
                release_date="",
                category=category,
                os=os_name,
                description="",
                source="swd-v2/driverDetails",
                product=product_name,
            ))
        for f in item.get("productSoftwareFileList", []):
            fu = f.get("fileUrl", "")
            if fu and fu.startswith("http"):
                sf_name = f.get("fileName", fu.rsplit("/", 1)[-1])
                if item_name:
                    sf_base = sf_name.rsplit(".", 1)[0].lower()
                    if sf_base not in item_name.lower():
                        sf_display = f"{item_name} ({sf_name})"
                    else:
                        sf_display = item_name
                else:
                    sf_display = sf_name
                entries.append(FileEntry(
                    name=sf_display,
                    url=fu,
                    size=str(f.get("fileSize", "")) if f.get("fileSize") else "",
                    version="",
                    release_date="",
                    category=category,
                    os=os_name,
                    description="",
                    source="swd-v2/driverDetails",
                    product=product_name,
                ))
