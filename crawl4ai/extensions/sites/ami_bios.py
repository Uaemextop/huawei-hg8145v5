"""
crawl4ai.extensions.sites.ami_bios – Site module for www.ami.com.

AMI (American Megatrends International) is the global leader in UEFI BIOS,
BMC firmware, and open-source firmware solutions.  Their website is a
WordPress site (powered by WP Engine + Divi/ET Builder) with downloadable
content hosted on HubSpot CDN (``hubspotusercontent`` / ``go.ami.com``).

This module:

1. Detects ``www.ami.com`` URLs (products, resources, security pages).
2. Discovers **resource pages** dynamically via the WordPress REST API
   (``/wp-json/wp/v2/project`` custom post type) — fetches all published
   resources (data sheets, tools, firmware utilities, whitepapers).
3. Discovers **product pages** via ``/wp-json/wp/v2/pages`` — fetches
   all product pages (Aptio V, MegaRAC, Tektagon, DCM, etc.).
4. Crawls each discovered page for downloadable files hosted on HubSpot
   CDN (PDFs, ZIPs) — data sheets, security advisories, utilities,
   encryption keys, whitepapers.
5. Crawls the **Security Advisories** page for all AMI-SA-* PDF links
   and CVE cross-references.
6. Discovers the **Aptio V Firmware Update Utility** ZIP and
   **Encryption Public Key** ZIP from their dedicated resource pages.
7. Discovers the **OCP Aptio Community Edition** GitHub repository link.

All data is discovered dynamically at runtime — no hardcoded file URLs.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import TYPE_CHECKING

from .base import BaseSiteModule, FileEntry

if TYPE_CHECKING:
    import requests

__all__ = ["AMIBiosModule"]

log = logging.getLogger(__name__)

# ── Hosts ────────────────────────────────────────────────────────────────

_AMI_HOSTS = {"www.ami.com", "ami.com"}

# ── HubSpot CDN domains where AMI hosts downloads ───────────────────────

_HUBSPOT_DOMAINS = {
    "f.hubspotusercontent10.net",
    "9443417.fs1.hubspotusercontent-na1.net",
    "go.ami.com",
}

# ── File extension pattern for discoverable files ────────────────────────

_DOWNLOAD_RE = re.compile(
    r'https?://[^\s"\'<>]+\.(?:pdf|zip|exe|msi|bin|efi|7z|gz|tar)'
    r'(?:\?[^\s"\'<>]*)?',
    re.IGNORECASE,
)

# ── GitHub repository pattern ────────────────────────────────────────────

_GITHUB_RE = re.compile(
    r'href="(https://github\.com/[^"]+)"',
    re.IGNORECASE,
)

# ── WP REST API endpoints ────────────────────────────────────────────────

_WP_PROJECTS_URL = "https://www.ami.com/wp-json/wp/v2/project"
_WP_PAGES_URL = "https://www.ami.com/wp-json/wp/v2/pages"

# ── Request settings ─────────────────────────────────────────────────────

_REQUEST_TIMEOUT = 20
_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
}


class AMIBiosModule(BaseSiteModule):
    """Site module for AMI BIOS/UEFI utilities and firmware resources."""

    name = "AMI BIOS/UEFI (data sheets, utilities & security advisories)"
    hosts = list(_AMI_HOSTS)

    def matches(self, url: str) -> bool:
        """Return *True* if *url* is on an AMI domain."""
        try:
            host = urllib.parse.urlparse(url).hostname or ""
            return host.lower() in _AMI_HOSTS
        except Exception:
            return False

    # ── Public API ───────────────────────────────────────────────────────

    def generate_index(self, url: str) -> list[FileEntry]:
        """Discover all downloadable files from AMI's website.

        Discovery flow:
        1. Fetch resource pages via WP REST API (``/wp-json/wp/v2/project``)
        2. Fetch product pages via WP REST API (``/wp-json/wp/v2/pages``)
        3. Crawl each page for HubSpot-hosted downloads (PDFs, ZIPs)
        4. Crawl the Security Advisories page for AMI-SA-* PDFs
        5. Deduplicate by download URL
        """
        sess = self._get_session()
        entries: list[FileEntry] = []
        seen_urls: set[str] = set()

        log.info("[AMI] ── Starting AMI file discovery ──")
        log.info("[AMI] URL: %s", url)

        # 1. Discover resource pages from WP REST API
        resource_pages = self._fetch_wp_resources(sess)
        log.info("[AMI] Discovered %d resource pages from WP API", len(resource_pages))

        # 2. Discover product pages from WP REST API
        product_pages = self._fetch_wp_product_pages(sess)
        log.info("[AMI] Discovered %d product pages from WP API", len(product_pages))

        # 3. Crawl each resource page for downloads
        all_pages = resource_pages + product_pages
        log.info("[AMI] ── Scanning %d pages for downloadable files ──", len(all_pages))

        for i, page_info in enumerate(all_pages, 1):
            page_url = page_info["url"]
            page_title = page_info["title"]
            page_type = page_info["type"]

            page_entries = self._scan_page_for_downloads(
                sess, page_url, page_title, page_type, seen_urls,
            )
            if page_entries:
                log.info(
                    "[AMI] [%d/%d] %s → %d files",
                    i, len(all_pages), page_title, len(page_entries),
                )
                entries.extend(page_entries)

        # 4. Scan security advisories page specifically
        sec_entries = self._scan_security_advisories(sess, seen_urls)
        log.info("[AMI] Security advisories → %d files", len(sec_entries))
        entries.extend(sec_entries)

        # 5. Discover GitHub repositories
        gh_entries = self._discover_github_repos(sess, seen_urls)
        if gh_entries:
            log.info("[AMI] GitHub repositories → %d entries", len(gh_entries))
            entries.extend(gh_entries)

        log.info(
            "[AMI] ── Complete: %d total files discovered ──",
            len(entries),
        )
        return entries

    def page_urls(self, url: str) -> list[str]:
        """Return additional AMI page URLs for the crawler queue."""
        sess = self._get_session()
        urls: list[str] = []

        # Add key AMI pages for deeper crawling
        resource_pages = self._fetch_wp_resources(sess)
        for p in resource_pages:
            urls.append(p["url"])

        product_pages = self._fetch_wp_product_pages(sess)
        for p in product_pages:
            urls.append(p["url"])

        # Always include security advisories and support login
        urls.append("https://www.ami.com/security-advisories/")
        urls.append("https://www.ami.com/security-center/")
        urls.append("https://www.ami.com/support-login/")

        return urls

    # ── WP REST API discovery ────────────────────────────────────────────

    def _fetch_wp_resources(
        self, sess: "requests.Session",
    ) -> list[dict[str, str]]:
        """Fetch all published resource pages via WP REST API.

        The ``project`` custom post type contains data sheets, tools,
        firmware utilities, whitepapers, press releases, etc.
        """
        pages_info: list[dict[str, str]] = []
        page_num = 1

        while True:
            try:
                resp = sess.get(
                    _WP_PROJECTS_URL,
                    params={"per_page": 100, "page": page_num},
                    headers=_HEADERS,
                    timeout=_REQUEST_TIMEOUT,
                )
                if resp.status_code != 200:
                    log.info(
                        "[AMI] WP projects API page %d returned HTTP %d",
                        page_num, resp.status_code,
                    )
                    break

                data = resp.json()
                if not isinstance(data, list) or not data:
                    break

                for item in data:
                    link = item.get("link", "")
                    title = _clean_html(
                        item.get("title", {}).get("rendered", "")
                    )
                    if link and title:
                        pages_info.append({
                            "url": link,
                            "title": title,
                            "type": "resource",
                        })

                page_num += 1
            except Exception as exc:
                log.info("[AMI] WP projects API error: %s", exc)
                break

        return pages_info

    def _fetch_wp_product_pages(
        self, sess: "requests.Session",
    ) -> list[dict[str, str]]:
        """Fetch product pages via WP REST API (``/wp-json/wp/v2/pages``)."""
        pages_info: list[dict[str, str]] = []
        page_num = 1

        while True:
            try:
                resp = sess.get(
                    _WP_PAGES_URL,
                    params={"per_page": 100, "page": page_num},
                    headers=_HEADERS,
                    timeout=_REQUEST_TIMEOUT,
                )
                if resp.status_code != 200:
                    break

                data = resp.json()
                if not isinstance(data, list) or not data:
                    break

                for item in data:
                    link = item.get("link", "")
                    title = _clean_html(
                        item.get("title", {}).get("rendered", "")
                    )
                    slug = item.get("slug", "")
                    # Only include product/solution pages
                    if link and title and _is_product_page(link, slug):
                        pages_info.append({
                            "url": link,
                            "title": title,
                            "type": "product",
                        })

                page_num += 1
            except Exception as exc:
                log.info("[AMI] WP pages API error: %s", exc)
                break

        return pages_info

    # ── Page scanning ────────────────────────────────────────────────────

    def _scan_page_for_downloads(
        self,
        sess: "requests.Session",
        page_url: str,
        page_title: str,
        page_type: str,
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Fetch a page and extract all downloadable file URLs."""
        entries: list[FileEntry] = []

        try:
            resp = sess.get(
                page_url,
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.status_code != 200:
                return entries

            resp.encoding = "utf-8"
            html = resp.text
        except Exception as exc:
            log.info("[AMI] Error fetching %s: %s", page_url, exc)
            return entries

        # Find all download URLs in the page
        for match in _DOWNLOAD_RE.finditer(html):
            file_url = _clean_url(match.group(0))
            if not file_url or file_url in seen_urls:
                continue
            if not _is_ami_download(file_url):
                continue

            seen_urls.add(file_url)
            entry = _build_entry(file_url, page_title, page_type)
            entries.append(entry)

        return entries

    def _scan_security_advisories(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Scan the security advisories page for AMI-SA-* PDFs."""
        entries: list[FileEntry] = []
        adv_url = "https://www.ami.com/security-advisories/"

        try:
            resp = sess.get(
                adv_url,
                headers=_HEADERS,
                timeout=_REQUEST_TIMEOUT,
            )
            if resp.status_code != 200:
                log.info(
                    "[AMI] Security advisories page returned HTTP %d",
                    resp.status_code,
                )
                return entries

            resp.encoding = "utf-8"
            html = resp.text
        except Exception as exc:
            log.info("[AMI] Error fetching security advisories: %s", exc)
            return entries

        for match in _DOWNLOAD_RE.finditer(html):
            file_url = _clean_url(match.group(0))
            if not file_url or file_url in seen_urls:
                continue
            if not _is_ami_download(file_url):
                continue

            seen_urls.add(file_url)
            entry = _build_entry(
                file_url, "Security Advisories", "security",
            )
            entries.append(entry)

        return entries

    def _discover_github_repos(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Discover GitHub repository links from AMI pages."""
        entries: list[FileEntry] = []

        # Check the community edition page
        for page_url, page_title in [
            (
                "https://www.ami.com/resource/aptio-communityedition/",
                "Aptio Community Edition",
            ),
            (
                "https://www.ami.com/products/aptio-v/",
                "Aptio V",
            ),
        ]:
            try:
                resp = sess.get(
                    page_url,
                    headers=_HEADERS,
                    timeout=_REQUEST_TIMEOUT,
                )
                if resp.status_code != 200:
                    continue
                resp.encoding = "utf-8"
                html = resp.text
            except Exception:
                continue

            for m in _GITHUB_RE.finditer(html):
                gh_url = m.group(1)
                if gh_url in seen_urls:
                    continue
                seen_urls.add(gh_url)
                repo_name = gh_url.rstrip("/").split("/")[-1]
                entries.append(FileEntry(
                    name=f"{repo_name} (GitHub)",
                    url=gh_url,
                    category="Source Code",
                    description=f"GitHub repository discovered from {page_title}",
                    source=page_url,
                    product=page_title,
                ))

        return entries

    # ── Session management ───────────────────────────────────────────────

    def _get_session(self) -> "requests.Session":
        """Return or create an HTTP session."""
        if self.session is not None:
            return self.session

        import requests as _requests
        sess = _requests.Session()
        sess.headers.update(_HEADERS)
        self.session = sess
        return sess


# ── Helpers ──────────────────────────────────────────────────────────────

def _clean_html(text: str) -> str:
    """Remove HTML entities and tags from text."""
    import html
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def _clean_url(raw_url: str) -> str:
    """Clean up a URL extracted from HTML."""
    # Remove HTML entities
    url = raw_url.replace("&amp;", "&").replace("&#038;", "&")
    # Remove trailing punctuation
    url = url.rstrip("\"'>;,) ")
    return url


def _is_ami_download(url: str) -> bool:
    """Return *True* if the URL is from an AMI-related download domain."""
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return False
    host = host.lower()
    return any(d in host for d in _HUBSPOT_DOMAINS) or "ami.com" in host


def _is_product_page(link: str, slug: str) -> bool:
    """Return *True* if a WP page is a product or solution page."""
    if "/products/" in link or "/solutions/" in link:
        return True
    if slug in ("security-center", "security-advisories", "support-login"):
        return True
    return False


def _build_entry(
    file_url: str,
    page_title: str,
    page_type: str,
) -> FileEntry:
    """Build a FileEntry from a download URL and its source page."""
    filename = _extract_filename(file_url)
    category = _classify_file(file_url, filename)

    return FileEntry(
        name=filename,
        url=file_url,
        category=category,
        source=page_type,
        product=page_title,
    )


def _extract_filename(url: str) -> str:
    """Extract a human-readable filename from a URL."""
    path = urllib.parse.urlparse(url).path
    # Get the last path segment
    filename = urllib.parse.unquote(path.rstrip("/").split("/")[-1])
    return filename or "Unknown"


def _classify_file(url: str, filename: str) -> str:
    """Classify a file into a category based on URL and filename."""
    url_lower = url.lower()
    filename_lower = filename.lower()

    if "security" in url_lower or "AMI-SA-" in filename:
        return "Security Advisory"
    if "CISO" in filename:
        return "Security Advisory"
    if "data_sheet" in url_lower or "data sheet" in filename_lower:
        return "Data Sheet"
    if "whitepaper" in url_lower or "white_paper" in url_lower:
        return "Whitepaper"
    if "encryption" in filename_lower or "public_key" in filename_lower:
        return "Security Key"
    if "firmware_update" in url_lower or "firmware" in filename_lower:
        return "Firmware Utility"
    if filename_lower.endswith(".zip"):
        return "Utility/Tool"
    if filename_lower.endswith(".pdf"):
        return "Documentation"
    return "Other"
