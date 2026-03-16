"""
crawl4ai.extensions.sites.hp_support – Site module for support.hp.com.

HP's support site is an Angular SPA.  Download links for drivers, firmware,
and software are **not** in the static HTML – they are loaded dynamically
via the ``/wcc-services/swd-v2/`` JSON API.  This module:

1. Detects ``support.hp.com`` URLs.
2. Scrapes product OID and OS information from the page / API.
3. Calls the ``/wcc-services/swd-v2/driverDetails`` endpoint to list all
   available drivers and software for the product.
4. Returns direct download URLs (``fileUrl``) for every listed SoftPaq /
   driver / software package (exe, cab, zip, cat, msi, …).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from typing import TYPE_CHECKING

from .base import BaseSiteModule

if TYPE_CHECKING:
    import requests

__all__ = ["HPSupportModule"]

log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────

_HP_HOSTS = {"support.hp.com", "h30434.www3.hp.com", "ftp.hp.com"}

# Regex to extract product OID from the URL path
# e.g. /us-en/drivers/hp-laserjet-pro-mfp-4101-4104dwe-series/model/38429067
_OID_RE = re.compile(r"/model/(\d+)")

# Regex for locale in the URL path  e.g. /us-en/
_LOCALE_RE = re.compile(r"/([a-z]{2})-([a-z]{2})/")

# API endpoint
_SWD_DRIVERS_URL = "https://support.hp.com/wcc-services/swd-v2/driverDetails"
_SWD_OS_URL = "https://support.hp.com/wcc-services/swd-v2/osVersionData"
_INIT_URL = "https://support.hp.com/wcc-services/s/init"
_CATEGORY_URL = "https://support.hp.com/wcc-services/pdp/category-details"

_REQUEST_TIMEOUT = 30

# Default UA header
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

    Works by calling HP's internal ``/wcc-services/swd-v2/driverDetails``
    JSON API which returns all available SoftPaq packages for a product,
    including direct ``fileUrl`` download links.
    """

    name = "HP Support (drivers & software)"
    hosts = list(_HP_HOSTS)

    # ── BaseSiteModule interface ─────────────────────────────────────

    def matches(self, url: str) -> bool:
        """Match any URL whose host is in :data:`_HP_HOSTS`."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc in _HP_HOSTS

    def extra_urls(self, url: str) -> set[str]:
        """Discover driver/software download URLs via HP's SWD API.

        1. Extract product OID + locale from the URL.
        2. Fetch OS version data for the product.
        3. POST to ``/wcc-services/swd-v2/driverDetails`` with each OS.
        4. Collect all ``fileUrl`` values from the response.
        """
        urls: set[str] = set()

        parsed = urllib.parse.urlparse(url)
        oid = self._extract_oid(url)
        cc, lc = self._extract_locale(url)

        if not oid:
            log.info("[HP] No product OID found in %s – trying category scan", url)
            urls |= self._scan_sitemap_links(url, cc, lc)
            return urls

        log.info("[HP] Product OID=%s  locale=%s-%s", oid, cc, lc)

        # Get available OS versions for this product
        os_list = self._get_os_versions(oid, cc, lc)
        if not os_list:
            # Fallback: try common Windows OS IDs
            os_list = self._default_os_list()

        # For each OS, fetch the driver list
        for os_info in os_list:
            try:
                driver_urls = self._get_driver_urls(oid, os_info, cc, lc)
                urls |= driver_urls
            except Exception as exc:
                log.debug("[HP] Error fetching drivers for OS %s: %s",
                          os_info.get("name", "?"), exc)

        log.info("[HP] Discovered %d download URLs for product %s", len(urls), oid)
        return urls

    # ── Internal helpers ─────────────────────────────────────────────

    def _get_session(self) -> "requests.Session":
        """Return the session, creating a basic one if needed."""
        if self.session is not None:
            return self.session
        import requests as _req
        s = _req.Session()
        s.headers.update(_HEADERS)
        # Inherit verify setting from the caller's session if available;
        # new fallback sessions use the default (True = verify SSL).
        return s

    @staticmethod
    def _extract_oid(url: str) -> str | None:
        """Extract a numeric product OID from the URL path."""
        m = _OID_RE.search(url)
        if m:
            return m.group(1)
        # Try the last path segment if it looks numeric
        path = urllib.parse.urlparse(url).path.rstrip("/")
        last = path.rsplit("/", 1)[-1]
        if last.isdigit() and len(last) >= 5:
            return last
        return None

    @staticmethod
    def _extract_locale(url: str) -> tuple[str, str]:
        """Extract (country_code, language_code) from the URL."""
        m = _LOCALE_RE.search(url)
        if m:
            return m.group(1), m.group(2)
        return "us", "en"

    def _get_os_versions(
        self, oid: str, cc: str, lc: str,
    ) -> list[dict]:
        """Fetch available OS versions for a product from the SWD API."""
        sess = self._get_session()
        try:
            resp = sess.get(
                _SWD_OS_URL,
                params={"cc": cc, "lc": lc, "productOid": oid},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.ok:
                data = resp.json().get("data", {})
                os_versions = []
                for platform in data.get("platformList", []):
                    for version in platform.get("osVersions", []):
                        os_versions.append({
                            "id": version.get("osTmsId", ""),
                            "name": version.get("osName", ""),
                            "platformId": platform.get("platformId", ""),
                            "platformName": platform.get("platformName", ""),
                        })
                return os_versions
        except Exception as exc:
            log.debug("[HP] OS version fetch failed: %s", exc)
        return []

    def _get_driver_urls(
        self,
        oid: str,
        os_info: dict,
        cc: str,
        lc: str,
    ) -> set[str]:
        """POST to driverDetails and extract fileUrl from each software item."""
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
            for sw_type in data.get("softwareTypes", []):
                for item in sw_type.get("softwareList", []):
                    self._collect_file_urls(item, urls)
                    # Check sub-items
                    for sub in item.get("subCategory", {}).get("softwareList", []):
                        self._collect_file_urls(sub, urls)
        except Exception as exc:
            log.debug("[HP] driverDetails call failed: %s", exc)

        return urls

    @staticmethod
    def _collect_file_urls(item: dict, urls: set[str]) -> None:
        """Extract download URLs from a software item dict."""
        file_url = item.get("fileUrl", "")
        if file_url and file_url.startswith("http"):
            urls.add(file_url)
        # Also check productSoftwareFileList
        for f in item.get("productSoftwareFileList", []):
            fn = f.get("fileName", "")
            if fn and fn.startswith("http"):
                urls.add(fn)
            fu = f.get("fileUrl", "")
            if fu and fu.startswith("http"):
                urls.add(fu)

    def _scan_sitemap_links(
        self, url: str, cc: str, lc: str,
    ) -> set[str]:
        """Fallback: scan the HP sitemap/href API for product page links."""
        sess = self._get_session()
        urls: set[str] = set()
        try:
            resp = sess.get(
                "https://support.hp.com/wcc-services/sitemap/href",
                params={"cc": cc, "lc": lc},
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.ok:
                data = resp.json()
                for entry in data.get("data", []):
                    href = entry.get("href", "")
                    if href and "/drivers/" in href:
                        abs_url = urllib.parse.urljoin(url, href)
                        urls.add(abs_url)
        except Exception as exc:
            log.debug("[HP] Sitemap scan failed: %s", exc)
        return urls

    @staticmethod
    def _default_os_list() -> list[dict]:
        """Common OS IDs for when the API doesn't return OS data."""
        return [
            {
                "id": "820677652736771455015295675946251",
                "name": "Windows 11 (64-bit)",
                "platformId": "218",
                "platformName": "Windows",
            },
            {
                "id": "4063276756043847636",
                "name": "Windows 10 (64-bit)",
                "platformId": "218",
                "platformName": "Windows",
            },
        ]
