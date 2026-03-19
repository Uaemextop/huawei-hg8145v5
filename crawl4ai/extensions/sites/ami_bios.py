"""
crawl4ai.extensions.sites.ami_bios – Site module for www.ami.com.

AMI (American Megatrends International) is the global leader in UEFI BIOS,
BMC firmware, and open-source firmware solutions.  Their website is a
WordPress site (WP Engine + Divi/ET Builder + Yoast SEO) with downloads
hosted on HubSpot CDN (``f.hubspotusercontent10.net``, ``go.ami.com``).

Discovery flow (all dynamic, no hardcoded URLs):

1. **Sitemap parsing** — ``/sitemap_index.xml`` → ``project-sitemap.xml``
   and ``page-sitemap.xml`` list every published resource and page URL.
2. **WP REST API** — ``/wp-json/wp/v2/project?per_page=100`` enumerates
   the ``project`` custom post type (data sheets, tools, whitepapers,
   firmware utilities, press releases).
3. **WP AJAX API** — ``POST /wp-admin/admin-ajax.php`` with
   ``action=query_resources`` discovers resources filtered by taxonomy
   (``support-docs``, ``data-sheets``, ``white-papers``).
4. **Page crawl** — each discovered resource/product page is fetched and
   scanned for HubSpot-hosted download URLs (PDFs, ZIPs).
5. **Security Advisories** — ``/security-advisories/`` page yields all
   AMI-SA-*.pdf links plus CVE cross-references.
6. **Subdomain probing** — ``meridian.ami.com`` (nginx SPA),
   ``eip.ami.com`` (Tomcat support portal), ``account.ami.com``
   (SharePoint), ``cp.ami.com`` (SharePoint), ``go.ami.com`` (HubSpot).
7. **GitHub repos** — links to ``github.com/opencomputeproject/``
   discovered from community-edition pages.

Analyzed infrastructure:
- **www.ami.com** — Cloudflare + WP Engine, Divi theme, HubSpot tracker
- **meridian.ami.com** — nginx/1.29.4, Vue SPA, API behind /api/ (403)
- **eip.ami.com** — Apache, Tomcat, Kendo UI, login-protected EIP portal
- **account.ami.com** — SharePoint/IIS, NTLM auth, account management
- **cp.ami.com** — SharePoint/IIS, NTLM 401, customer portal
- **go.ami.com** — HubSpot CMS/redirector (portal ID 9443417)

HubSpot CDN structure (``/hubfs/9443417/``):
- ``Support/BIOS_Firmware_Update/`` — AFU utilities, encryption keys
- ``Support/AMI_Debug_Rx/`` — debug firmware, supplemental files, guides
- ``Support/BIOS_Checkpoint_and_Beep_Codes/`` — Aptio 4/V/AMIBIOS8 codes
- ``Support/Motherboard_ID_Tool/`` — motherboard identification utility
- ``Support/NwJsBin/`` — NW.js binaries (Win64/Win32/Linux64)
- ``Data_Sheets/Firmware_Solutions/`` — Aptio V, MegaRAC, Tektagon sheets
- ``Data_Sheets/Firmware_Tools_and_Utilities/`` — AMIBCP, MMTool, VeB, AFU
- ``Data_Sheets/IT_Management_Solutions/`` — AMI DCM data sheets
- ``Data_Sheets/Security_Solutions/`` — Trust Center brochure
- ``Security Advisories/`` — AMI-SA-2022* through AMI-SA-2025* PDFs
- ``Whitepapers/`` — security features, firmware whitepapers
"""

from __future__ import annotations

import html as html_mod
import logging
import re
import time
import urllib.parse
from typing import TYPE_CHECKING

from .base import BaseSiteModule, FileEntry

if TYPE_CHECKING:
    import requests

__all__ = ["AMIBiosModule"]

log = logging.getLogger(__name__)

# ── Hosts ────────────────────────────────────────────────────────────────

_AMI_HOSTS = {"www.ami.com", "ami.com"}

# ── Subdomains to probe ──────────────────────────────────────────────────

_SUBDOMAINS = {
    "meridian.ami.com": "AMI Meridian (cloud platform, nginx SPA)",
    "eip.ami.com": "EIP Support Portal (Tomcat, login-protected)",
    "account.ami.com": "Account Management (SharePoint/IIS)",
    "cp.ami.com": "Customer Portal (SharePoint/IIS, NTLM)",
    "go.ami.com": "HubSpot CMS/Redirector",
}

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

# ── Sitemap URL pattern ──────────────────────────────────────────────────

_SITEMAP_LOC_RE = re.compile(r"<loc>([^<]+)</loc>")

# ── WP REST API endpoints ────────────────────────────────────────────────

_WP_PROJECTS_URL = "https://www.ami.com/wp-json/wp/v2/project"
_WP_PAGES_URL = "https://www.ami.com/wp-json/wp/v2/pages"
_WP_AJAX_URL = "https://www.ami.com/wp-admin/admin-ajax.php"

# ── Resource type taxonomies for AJAX query ──────────────────────────────

_RESOURCE_TYPES = ("support-docs", "data-sheets", "white-papers")

# ── Request settings ─────────────────────────────────────────────────────

_REQUEST_TIMEOUT = 20
_REQUEST_DELAY = 0.15  # seconds between requests (be nice to Cloudflare)
_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Referer": "https://www.ami.com/",
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

        **Primary strategy:** The WP REST API ``content.rendered`` field
        already contains the full rendered HTML for each resource page,
        including all HubSpot download URLs and JS redirect targets.
        This lets us scan 460+ pages with just 6 API requests (100
        items/page) instead of 460 individual HTTP GETs.

        Discovery flow:
        1. WP REST API ``/wp-json/wp/v2/project`` — scan ``content.rendered``
           for download URLs across all 460+ resource pages.
        2. WP REST API ``/wp-json/wp/v2/pages`` — same for product pages.
        3. Full HTML scan for pages where API returned empty/short content.
        4. ``/security-advisories/`` page — AMI-SA-* advisory PDFs.
        5. GitHub repository links from community-edition pages.
        6. Subdomain probing (meridian, eip, account, cp, go).
        7. Deduplicate by download URL.
        """
        sess = self._get_session()
        entries: list[FileEntry] = []
        seen_urls: set[str] = set()

        log.info("[AMI] ── Starting AMI file discovery ──")
        log.info("[AMI] URL: %s", url)

        # 1–2. Scan WP REST API content for downloads (projects + pages)
        no_content_pages: list[dict[str, str]] = []
        api_entries, no_content_pages = self._scan_wp_api_content(sess, seen_urls)
        log.info(
            "[AMI] WP REST API content scan → %d files, %d pages need full HTML",
            len(api_entries), len(no_content_pages),
        )
        entries.extend(api_entries)

        # 3. Full HTML scan for pages with missing/short API content
        if no_content_pages:
            log.info(
                "[AMI] ── Full HTML scan for %d pages ──", len(no_content_pages),
            )
            for i, page_info in enumerate(no_content_pages, 1):
                page_entries = self._scan_page_for_downloads(
                    sess, page_info["url"], page_info["title"],
                    "resource", seen_urls,
                )
                if page_entries:
                    log.info(
                        "[AMI]   [%d/%d] %s → %d files",
                        i, len(no_content_pages),
                        page_info["title"], len(page_entries),
                    )
                    entries.extend(page_entries)
                time.sleep(_REQUEST_DELAY)

        # 4. Security advisories page (too complex for API content scan)
        sec_entries = self._scan_security_advisories(sess, seen_urls)
        log.info("[AMI] Security advisories → %d files", len(sec_entries))
        entries.extend(sec_entries)

        # 5. GitHub repositories
        gh_entries = self._discover_github_repos(sess, seen_urls)
        if gh_entries:
            log.info("[AMI] GitHub repositories → %d entries", len(gh_entries))
            entries.extend(gh_entries)

        # 6. Subdomain probing
        sub_entries = self._probe_subdomains(sess, seen_urls)
        if sub_entries:
            log.info("[AMI] Subdomains → %d entries", len(sub_entries))
            entries.extend(sub_entries)

        log.info(
            "[AMI] ── Complete: %d total files discovered ──",
            len(entries),
        )
        return entries

    def page_urls(self, url: str) -> list[str]:
        """Return additional AMI page URLs for the crawler queue.

        Uses sitemaps (most complete) + key pages.
        """
        sess = self._get_session()
        urls: list[str] = []

        resource_urls = self._parse_sitemap(
            sess, "https://www.ami.com/project-sitemap.xml",
        )
        urls.extend(resource_urls)

        page_urls_list = self._parse_sitemap(
            sess, "https://www.ami.com/page-sitemap.xml",
        )
        urls.extend(page_urls_list)

        urls.append("https://www.ami.com/security-advisories/")
        urls.append("https://www.ami.com/security-center/")
        urls.append("https://www.ami.com/support-login/")
        urls.append("https://www.ami.com/learning-center/")
        urls.append("https://www.ami.com/resource-type/support-docs/")
        urls.append("https://www.ami.com/resource-type/data-sheets/")
        urls.append("https://www.ami.com/resource-type/white-papers/")

        return urls

    # ── Sitemap parsing ──────────────────────────────────────────────────

    def _parse_sitemap(
        self, sess: "requests.Session", sitemap_url: str,
    ) -> list[str]:
        """Parse a Yoast sitemap XML and return all ``<loc>`` URLs."""
        try:
            resp = sess.get(
                sitemap_url, headers=_HEADERS, timeout=_REQUEST_TIMEOUT,
            )
            if resp.status_code != 200:
                log.info(
                    "[AMI] Sitemap %s → HTTP %d", sitemap_url, resp.status_code,
                )
                return []
            resp.encoding = "utf-8"
            return _SITEMAP_LOC_RE.findall(resp.text)
        except Exception as exc:
            log.info("[AMI] Sitemap %s error: %s", sitemap_url, exc)
            return []

    # ── WP REST API content scanning ────────────────────────────────────

    def _scan_wp_api_content(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> tuple[list[FileEntry], list[dict[str, str]]]:
        """Scan WP REST API ``content.rendered`` for download URLs.

        The WordPress REST API returns the full rendered HTML for each
        resource/page in ``content.rendered``.  This lets us extract all
        HubSpot download URLs and JS redirect targets without fetching
        each of the 460+ individual pages.

        Returns
        -------
        tuple
            (list of FileEntry, list of pages needing full HTML scan)
        """
        entries: list[FileEntry] = []
        no_content_pages: list[dict[str, str]] = []

        for api_url, api_name in [
            (_WP_PROJECTS_URL, "projects"),
            (_WP_PAGES_URL, "pages"),
        ]:
            page_num = 1
            while True:
                try:
                    resp = self._safe_get(
                        sess, api_url,
                        params={"per_page": 100, "page": page_num},
                    )
                    if not resp or resp.status_code != 200:
                        if resp:
                            log.info(
                                "[AMI] WP %s page %d → HTTP %d",
                                api_name, page_num, resp.status_code,
                            )
                        break
                    data = resp.json()
                    if not isinstance(data, list) or not data:
                        break

                    page_found = 0
                    for item in data:
                        link = item.get("link", "")
                        title = _clean_html(
                            (item.get("title") or {}).get("rendered", "")
                        )
                        content = (item.get("content") or {}).get("rendered", "")

                        if not title:
                            title = link.rstrip("/").split("/")[-1]

                        page_type = (
                            "product" if "/products/" in link or "/solutions/" in link
                            else "resource"
                        )

                        # Scan content for downloads
                        found = self._extract_downloads_from_html(
                            content, title, page_type, seen_urls, entries,
                        )
                        page_found += found

                        # Queue pages with missing/short content for full scan
                        if link and (not content or len(content) < 100):
                            no_content_pages.append({"url": link, "title": title})

                    log.info(
                        "[AMI] WP %s page %d: %d items, %d new files (total %d)",
                        api_name, page_num, len(data), page_found, len(entries),
                    )
                    page_num += 1
                    time.sleep(_REQUEST_DELAY * 3)  # be nice to Cloudflare
                except Exception as exc:
                    log.info("[AMI] WP %s API error: %s", api_name, exc)
                    break

        return entries, no_content_pages

    # ── Download extraction ─────────────────────────────────────────────

    @staticmethod
    def _extract_downloads_from_html(
        html: str,
        title: str,
        page_type: str,
        seen_urls: set[str],
        entries: list[FileEntry],
    ) -> int:
        """Extract download URLs from HTML content and append to entries.

        Finds both direct HubSpot file URLs and ``window.location.href``
        JS redirect targets (used by Divi popup download buttons).

        Returns the number of new entries added.
        """
        count = 0

        for match in _DOWNLOAD_RE.finditer(html):
            file_url = _clean_url(match.group(0))
            if not file_url or file_url in seen_urls:
                continue
            if not _is_ami_download(file_url):
                continue
            seen_urls.add(file_url)
            entries.append(_build_entry(file_url, title, page_type))
            count += 1

        # JS redirect downloads (Divi popup "accept" button pattern)
        for m in re.finditer(
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', html,
        ):
            js_url = _clean_url(m.group(1))
            if js_url and js_url not in seen_urls and _is_ami_download(js_url):
                seen_urls.add(js_url)
                entries.append(
                    _build_entry(js_url, title, page_type + " (JS redirect)"),
                )
                count += 1

        return count

    # ── HTTP helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _safe_get(
        sess: "requests.Session",
        url: str,
        params: dict | None = None,
    ) -> "requests.Response | None":
        """GET with retry on timeout (Cloudflare sometimes stalls)."""
        for attempt in range(3):
            try:
                return sess.get(
                    url, params=params, headers=_HEADERS,
                    timeout=_REQUEST_TIMEOUT + (attempt * 10),
                )
            except Exception:
                time.sleep(2 * (attempt + 1))
        return None

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

        resp = self._safe_get(sess, page_url)
        if not resp or resp.status_code != 200:
            return entries

        resp.encoding = "utf-8"
        self._extract_downloads_from_html(
            resp.text, page_title, page_type, seen_urls, entries,
        )
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
                adv_url, headers=_HEADERS, timeout=_REQUEST_TIMEOUT,
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
            entries.append(
                _build_entry(file_url, "Security Advisories", "security"),
            )

        return entries

    def _discover_github_repos(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Discover GitHub repository links from AMI pages."""
        entries: list[FileEntry] = []

        for page_url, page_title in [
            ("https://www.ami.com/resource/aptio-communityedition/",
             "Aptio Community Edition"),
            ("https://www.ami.com/products/aptio-v/", "Aptio V"),
        ]:
            try:
                resp = sess.get(
                    page_url, headers=_HEADERS, timeout=_REQUEST_TIMEOUT,
                )
                if resp.status_code != 200:
                    continue
                resp.encoding = "utf-8"
            except Exception:
                continue

            for m in _GITHUB_RE.finditer(resp.text):
                gh_url = m.group(1)
                if gh_url in seen_urls:
                    continue
                seen_urls.add(gh_url)
                repo_name = gh_url.rstrip("/").split("/")[-1]
                entries.append(FileEntry(
                    name=f"{repo_name} (GitHub)",
                    url=gh_url,
                    category="Source Code",
                    description=f"GitHub repository from {page_title}",
                    source=page_url,
                    product=page_title,
                ))

        return entries

    # ── Subdomain probing ────────────────────────────────────────────────

    def _probe_subdomains(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Probe AMI subdomains and record accessible endpoints.

        Discovered infrastructure:
        - ``meridian.ami.com`` — nginx/1.29.4, Vue SPA, /api/ returns 403
        - ``eip.ami.com`` — Apache/Tomcat, Kendo UI login, /eip/myStart.do
        - ``account.ami.com`` — SharePoint/IIS, public account retrieval
        - ``cp.ami.com`` — SharePoint/IIS, NTLM 401
        - ``go.ami.com`` — HubSpot CMS/redirector
        """
        entries: list[FileEntry] = []

        for domain, description in _SUBDOMAINS.items():
            url = f"https://{domain}/"
            if url in seen_urls:
                continue

            try:
                resp = sess.head(
                    url, timeout=5, allow_redirects=True,
                    headers=_HEADERS,
                )
                status = resp.status_code
                server = resp.headers.get("Server", "unknown")
            except Exception:
                log.info("[AMI] Subdomain %s — unreachable", domain)
                continue

            seen_urls.add(url)
            final_url = resp.url if hasattr(resp, "url") else url

            if status in (200, 301, 302, 401, 403):
                log.info(
                    "[AMI] Subdomain %s → HTTP %d (server: %s)",
                    domain, status, server,
                )
                entries.append(FileEntry(
                    name=f"{domain} ({server})",
                    url=final_url,
                    category="Subdomain/Portal",
                    description=f"{description} — HTTP {status}",
                    source="subdomain-probe",
                    product="AMI Infrastructure",
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
    text = html_mod.unescape(text)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def _clean_url(raw_url: str) -> str:
    """Clean up a URL extracted from HTML."""
    url = raw_url.replace("&amp;", "&").replace("&#038;", "&")
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
    if slug in (
        "security-center", "security-advisories", "support-login",
        "learning-center",
    ):
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
    filename = urllib.parse.unquote(path.rstrip("/").split("/")[-1])
    return filename or "Unknown"


def _classify_file(url: str, filename: str) -> str:
    """Classify a file into a category based on URL and filename."""
    url_lower = url.lower()
    fn_lower = filename.lower()

    if "security" in url_lower or "AMI-SA-" in filename or "CISO" in filename:
        return "Security Advisory"
    if "data_sheet" in url_lower or "data sheet" in fn_lower:
        return "Data Sheet"
    if "whitepaper" in url_lower or "white_paper" in url_lower:
        return "Whitepaper"
    if "encryption" in fn_lower or "public_key" in fn_lower:
        return "Security Key"
    if "firmware_update" in url_lower or "firmware" in fn_lower:
        return "Firmware Utility"
    if "debug" in fn_lower:
        return "Debug Tool"
    if "checkpoint" in fn_lower or "beep_code" in fn_lower:
        return "Reference Guide"
    if "motherboard" in fn_lower:
        return "Diagnostic Tool"
    if "nwjs" in fn_lower:
        return "Runtime Binary"
    if fn_lower.endswith(".zip"):
        return "Utility/Tool"
    if fn_lower.endswith(".pdf"):
        return "Documentation"
    return "Other"
