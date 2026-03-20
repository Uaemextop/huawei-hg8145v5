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

Login-protected tools (NOT publicly downloadable — require EIP portal account):
- **AMIBCP** — only data sheet PDF available publicly
- **MMTool** — only data sheet PDF available publicly
- **VeB (Visual eBIOS)** — only data sheet PDF available publicly
These tools are distributed through ``eip.ami.com`` (Tomcat/Kendo UI portal)
after customer authentication.  The public pages only offer the data sheet
PDF through a Divi popup ``window.location.href`` JS redirect.
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
    r'https?://[^\s"\'<>]+\.(?:'
    r'pdf|zip|exe|msi|bin|efi|7z|gz|tar|tgz|bz2|xz|zst'
    r'|cab|dmg|pkg|deb|rpm|apk|appimage|snap|flatpak|ipa'
    r'|iso|img|rom|fw|uf2|hex|srec|vhd|vmdk|ova'
    r'|doc|docx|xls|xlsx|ppt|pptx|rtf|odt|ods|odp'
    r'|rar|lzh|arj|ace|lz|lzma|jar|war'
    r'|dll|sys|so|dylib'
    r')'
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

# ── Additional download-link patterns ────────────────────────────────────
# onclick / data-* attributes that contain download URLs
_ONCLICK_URL_RE = re.compile(
    r"""(?:onclick|data-download-url|data-href|data-file|data-src)\s*=\s*['"]"""
    r"""[^'"]*?(https?://[^\s"'<>]+\.(?:"""
    r"""pdf|zip|exe|msi|bin|efi|7z|gz|tar|tgz|bz2|xz|cab|dmg|iso|rar"""
    r"""|doc|docx|xls|xlsx|ppt|pptx|rom|fw|img|rpm|deb"""
    r""")(?:\?[^\s"'<>]*)?)""",
    re.IGNORECASE,
)

# JSON-embedded URLs in <script> tags
_JSON_URL_RE = re.compile(
    r'["\']'
    r'(https?://[^\s"\'<>]+\.(?:'
    r'pdf|zip|exe|msi|bin|efi|7z|gz|tar|tgz|cab|dmg|iso|rar'
    r'|doc|docx|xls|xlsx|ppt|pptx|rom|fw|img'
    r')(?:\?[^\s"\'<>]*)?)'
    r'["\']',
    re.IGNORECASE,
)

# HubSpot CDN URL pattern (any file on HubSpot CDN)
_HUBSPOT_CDN_RE = re.compile(
    r'(https?://(?:f\.hubspotusercontent\d*\.net|'
    r'\d+\.fs\d+\.hubspotusercontent[a-z0-9-]*\.net|'
    r'go\.ami\.com)'
    r'/[^\s"\'<>]+)',
    re.IGNORECASE,
)

# ── WP REST API endpoints ────────────────────────────────────────────────

_WP_PROJECTS_URL = "https://www.ami.com/wp-json/wp/v2/project"
_WP_PAGES_URL = "https://www.ami.com/wp-json/wp/v2/pages"
_WP_MEDIA_URL = "https://www.ami.com/wp-json/wp/v2/media"
_WP_AJAX_URL = "https://www.ami.com/wp-admin/admin-ajax.php"

# ── Resource type taxonomies for AJAX query ──────────────────────────────

_RESOURCE_TYPES = ("support-docs", "data-sheets", "white-papers")

# ── Known HubSpot CDN binary files (confirmed accessible) ────────────────
# These are direct download URLs for AMI tools and utilities that are behind
# Divi popup license-acceptance dialogs.  Probing them directly ensures we
# capture every binary even if the JS redirect is missed during HTML scan.

_HUBSPOT_CDN_BASE = (
    "https://9443417.fs1.hubspotusercontent-na1.net/hubfs/9443417"
)

_KNOWN_CDN_BINARIES: tuple[tuple[str, str, str], ...] = (
    # (path, name, category)
    ("Support/BIOS_Firmware_Update/Aptio_V_AMI_Firmware_Update_Utility.zip",
     "Aptio V AFU (Firmware Update Utility)", "Firmware Utility"),
    ("Support/BIOS_Firmware_Update/Aptio4_AMI_Firmware_Update_Utility.zip",
     "Aptio 4 AFU (Firmware Update Utility)", "Firmware Utility"),
    ("Support/BIOS_Firmware_Update/AMIBIOS8_AMI_Firmware_Update_Utility.zip",
     "AMIBIOS8 AFU (Firmware Update Utility)", "Firmware Utility"),
    ("Support/BIOS_Firmware_Update/Encryption_Public_Key.zip",
     "Encryption Public Key", "Security Key"),
    ("Support/AMI_Debug_Rx/AMI_Debug_Rx_Firmware_Version_3.4.2.zip",
     "AMI Debug Rx Firmware v3.4.2", "Debug Tool"),
    ("Support/AMI_Debug_Rx/AMI_Debug_Rx_Firmware_Version_2.3.6.zip",
     "AMI Debug Rx Firmware v2.3.6", "Debug Tool"),
    ("Support/AMI_Debug_Rx/AMI_Debug_Rx_Supplemental_Files_Version_3.4.2.zip",
     "AMI Debug Rx Supplemental Files v3.4.2", "Debug Tool"),
    ("Support/AMI_Debug_Rx/AMI_Debug_Rx_Supplemental_Files_Version_2.3.6.zip",
     "AMI Debug Rx Supplemental Files v2.3.6", "Debug Tool"),
    ("Support/NwJsBin/NwJsBinWin64.zip",
     "NwJs Binary (Windows 64-bit)", "Runtime Binary"),
    ("Support/NwJsBin/NwJsBinWin32.zip",
     "NwJs Binary (Windows 32-bit)", "Runtime Binary"),
    ("Support/NwJsBin/NwJsBinLnx64.zip",
     "NwJs Binary (Linux 64-bit)", "Runtime Binary"),
    ("Support/Motherboard_ID_Tool/Motherboard_ID_Tool.zip",
     "Motherboard ID Tool", "Diagnostic Tool"),
)

# ── Directory paths on HubSpot CDN to probe for listings ─────────────────

_HUBSPOT_PROBE_DIRS = (
    "Support/BIOS_Firmware_Update/",
    "Support/AMI_Debug_Rx/",
    "Support/BIOS_Checkpoint_and_Beep_Codes/",
    "Support/Motherboard_ID_Tool/",
    "Support/NwJsBin/",
    "Data_Sheets/Firmware_Solutions/",
    "Data_Sheets/Firmware_Tools_and_Utilities/",
    "Data_Sheets/IT_Management_Solutions/",
    "Data_Sheets/Security_Solutions/",
    "Security Advisories/",
    "Whitepapers/",
)

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

        Discovery flow:
        1. Known HubSpot CDN binaries (confirmed ZIPs: AFU, Debug Rx, NwJs, etc.)
        2. Security advisories page (AMI-SA-* PDFs + ZIP)
        3. WP REST API projects + pages (content.rendered scan)
        4. WP AJAX resource queries (paginated JSON → resource page URLs)
        5. Full HTML scan for pages with missing/short API content
        6. GitHub repository links
        7. Subdomain probing
        8. HubSpot CDN directory probing (catch new files)
        """
        sess = self._get_session()
        entries: list[FileEntry] = []
        seen_urls: set[str] = set()

        log.info("[AMI] ── Starting AMI file discovery ──")
        log.info("[AMI] URL: %s", url)

        # 1. Known CDN binaries — these are the confirmed downloadable tools
        # (AFU, Debug Rx, NwJs, Motherboard ID Tool, Encryption Key)
        cdn_binary_count = 0
        for path, name, category in _KNOWN_CDN_BINARIES:
            file_url = f"{_HUBSPOT_CDN_BASE}/{path}"
            if file_url in seen_urls:
                continue
            try:
                resp = sess.head(
                    file_url, timeout=10, allow_redirects=True,
                    headers=_HEADERS,
                )
                if resp.status_code == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "html" not in ct.lower():
                        cl = resp.headers.get("Content-Length", "")
                        seen_urls.add(file_url)
                        entries.append(FileEntry(
                            name=name,
                            url=file_url,
                            size=self._format_size(cl),
                            category=category,
                            source="hubspot-cdn-known",
                            product="AMI",
                        ))
                        cdn_binary_count += 1
            except Exception:
                pass
        log.info("[AMI] Known CDN binaries → %d files", cdn_binary_count)

        # 2. Security advisories — scan BEFORE WP API so that advisory PDFs
        #    are added to seen_urls first.  The WP pages API may also
        #    reference these same URLs in content.rendered; by discovering
        #    them here first we get accurate per-source counts.
        sec_entries = self._scan_security_advisories(sess, seen_urls)
        log.info("[AMI] Security advisories → %d files", len(sec_entries))
        entries.extend(sec_entries)

        # 3. Scan WP REST API content for downloads (projects + pages)
        no_content_pages: list[dict[str, str]] = []
        api_entries, no_content_pages = self._scan_wp_api_content(sess, seen_urls)
        log.info(
            "[AMI] WP REST API content scan → %d files, %d pages need full HTML",
            len(api_entries), len(no_content_pages),
        )
        entries.extend(api_entries)

        # 4. WP AJAX resource queries — paginated, extracts resource page URLs
        ajax_entries = self._scan_wp_ajax_resources(sess, seen_urls)
        log.info("[AMI] WP AJAX resources → %d files", len(ajax_entries))
        entries.extend(ajax_entries)

        # 5. Full HTML scan for pages with missing/short API content
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

        # 6. GitHub repositories
        gh_entries = self._discover_github_repos(sess, seen_urls)
        if gh_entries:
            log.info("[AMI] GitHub repositories → %d entries", len(gh_entries))
            entries.extend(gh_entries)

        # 7. Subdomain probing
        sub_entries = self._probe_subdomains(sess, seen_urls)
        if sub_entries:
            log.info("[AMI] Subdomains → %d entries", len(sub_entries))
            entries.extend(sub_entries)

        # 8. HubSpot CDN directory probing (catch new files)
        cdn_entries = self._probe_hubspot_cdn(sess, seen_urls)
        if cdn_entries:
            log.info("[AMI] HubSpot CDN probing → %d entries", len(cdn_entries))
            entries.extend(cdn_entries)

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

                        # Queue resource pages for full HTML scan.
                        # The WP API content.rendered excludes Divi popup
                        # modules which contain window.location.href JS
                        # redirects to download URLs (ZIPs, PDFs).  Only
                        # a full page GET captures these popup downloads.
                        # Non-resource pages (products, solutions) are
                        # excluded — they rarely have popup downloads.
                        if link and "/resource/" in link:
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

        Finds:
        - Direct HubSpot file URLs (via ``_DOWNLOAD_RE``)
        - ``window.location.href`` JS redirect targets (Divi popup buttons)
        - ``onclick`` / ``data-*`` download attributes
        - JSON-embedded URLs in ``<script>`` tags
        - HubSpot CDN URLs (any file hosted on HubSpot CDN)

        Returns the number of new entries added.
        """
        count = 0

        # 1. Standard download URLs with known file extensions
        for match in _DOWNLOAD_RE.finditer(html):
            file_url = _clean_url(match.group(0))
            if not file_url or file_url in seen_urls:
                continue
            if not _is_ami_download(file_url):
                continue
            seen_urls.add(file_url)
            entries.append(_build_entry(file_url, title, page_type))
            count += 1

        # 2. JS redirect downloads (Divi popup "accept" button pattern)
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

        # 3. onclick / data-* download attributes
        for m in _ONCLICK_URL_RE.finditer(html):
            attr_url = _clean_url(m.group(1))
            if attr_url and attr_url not in seen_urls and _is_ami_download(attr_url):
                seen_urls.add(attr_url)
                entries.append(
                    _build_entry(attr_url, title, page_type + " (data-attr)"),
                )
                count += 1

        # 4. JSON-embedded URLs in <script> tags
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.I):
            script_body = m.group(1)
            for jm in _JSON_URL_RE.finditer(script_body):
                json_url = _clean_url(jm.group(1))
                if json_url and json_url not in seen_urls and _is_ami_download(json_url):
                    seen_urls.add(json_url)
                    entries.append(
                        _build_entry(json_url, title, page_type + " (script)"),
                    )
                    count += 1

        # 5. HubSpot CDN URLs (catch-all for any file on HubSpot CDN)
        for m in _HUBSPOT_CDN_RE.finditer(html):
            hub_url = _clean_url(m.group(1))
            if not hub_url or hub_url in seen_urls:
                continue
            # Only include if the last path segment has a recognised extension
            path = urllib.parse.urlparse(hub_url).path
            last_segment = path.rstrip("/").rsplit("/", 1)[-1]
            if "." in last_segment:
                ext = last_segment.rsplit(".", 1)[-1].lower()
                # Must be a known file extension, not a domain-like dot
                if len(ext) <= 10 and ext.isalnum():
                    seen_urls.add(hub_url)
                    entries.append(
                        _build_entry(hub_url, title, page_type + " (CDN)"),
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

    # ── WP Media Library scanning ────────────────────────────────────────

    def _scan_wp_media(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Scan WP Media Library for downloadable attachments.

        The ``/wp-json/wp/v2/media`` endpoint exposes uploaded files
        including ZIPs, EXEs, PDFs, and other binaries that may not be
        linked from any published page.
        """
        entries: list[FileEntry] = []
        page_num = 1
        while True:
            try:
                resp = self._safe_get(
                    sess, _WP_MEDIA_URL,
                    params={"per_page": 100, "page": page_num},
                )
                if not resp or resp.status_code != 200:
                    break
                data = resp.json()
                if not isinstance(data, list) or not data:
                    break

                for item in data:
                    media_url = item.get("source_url", "")
                    if not media_url or media_url in seen_urls:
                        continue
                    mime_type = item.get("mime_type", "")
                    title = _clean_html(
                        (item.get("title") or {}).get("rendered", "")
                    ) or _extract_filename(media_url)

                    # Only include binary / document types
                    if not _is_downloadable_mime(mime_type):
                        continue

                    seen_urls.add(media_url)
                    entries.append(FileEntry(
                        name=title,
                        url=media_url,
                        category=_classify_file(media_url, title),
                        source="WP Media Library",
                        product="AMI",
                        description=mime_type,
                    ))

                log.info(
                    "[AMI] WP media page %d: %d items, %d new (total %d)",
                    page_num, len(data),
                    sum(1 for e in entries if e.get("source") == "WP Media Library"),
                    len(entries),
                )
                page_num += 1
                time.sleep(_REQUEST_DELAY * 2)
            except Exception as exc:
                log.info("[AMI] WP media API error: %s", exc)
                break

        return entries

    # ── WP AJAX resource queries ─────────────────────────────────────────

    def _scan_wp_ajax_resources(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Query the WP AJAX ``query_resources`` endpoint with pagination.

        The AJAX response is JSON with an ``html`` field containing rendered
        resource cards and resource page URLs.  We:
        1. Parse the JSON to get the HTML fragment
        2. Extract resource page URLs from the HTML
        3. Scan each resource page for download links
        4. Paginate through all pages (12 items/page, up to 39 pages)
        """
        entries: list[FileEntry] = []
        resource_page_urls: set[str] = set()

        for resource_type in _RESOURCE_TYPES:
            page_num = 1
            max_pages = 1  # updated after first response
            while page_num <= max_pages:
                try:
                    resp = sess.post(
                        _WP_AJAX_URL,
                        data={
                            "action": "query_resources",
                            "resource_type": resource_type,
                            "paged": page_num,
                        },
                        headers={
                            **_HEADERS,
                            "X-Requested-With": "XMLHttpRequest",
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        timeout=_REQUEST_TIMEOUT,
                    )
                    if resp.status_code != 200:
                        break
                    resp.encoding = "utf-8"

                    # Parse JSON response
                    try:
                        data = resp.json()
                    except Exception:
                        break

                    if not isinstance(data, dict):
                        break

                    max_pages = int(data.get("total_pages") or 1)
                    html = data.get("html", "")

                    # Extract resource page URLs from AJAX HTML
                    for m in re.finditer(
                        r'href="(https://www\.ami\.com/resource/[^"]+)"',
                        html,
                    ):
                        resource_page_urls.add(m.group(1))

                    # Also extract any direct download URLs from AJAX HTML
                    self._extract_downloads_from_html(
                        html,
                        f"AJAX {resource_type}",
                        f"ajax-{resource_type}",
                        seen_urls,
                        entries,
                    )

                    page_num += 1
                    time.sleep(_REQUEST_DELAY)
                except Exception as exc:
                    log.info("[AMI] AJAX %s error: %s", resource_type, exc)
                    break

            log.info(
                "[AMI] AJAX %s: %d pages, %d resource URLs",
                resource_type, min(page_num - 1, max_pages),
                len(resource_page_urls),
            )

        # Scan discovered resource pages for downloads
        if resource_page_urls:
            log.info(
                "[AMI] ── Scanning %d AJAX resource pages ──",
                len(resource_page_urls),
            )
            for i, page_url in enumerate(sorted(resource_page_urls), 1):
                page_title = page_url.rstrip("/").split("/")[-1]
                page_entries = self._scan_page_for_downloads(
                    sess, page_url, page_title,
                    "ajax-resource", seen_urls,
                )
                if page_entries:
                    entries.extend(page_entries)
                if i % 20 == 0:
                    log.info(
                        "[AMI]   AJAX pages: %d/%d scanned, %d total files",
                        i, len(resource_page_urls), len(entries),
                    )
                time.sleep(_REQUEST_DELAY)

        return entries

    # ── HubSpot CDN probing ──────────────────────────────────────────────

    def _probe_hubspot_cdn(
        self,
        sess: "requests.Session",
        seen_urls: set[str],
    ) -> list[FileEntry]:
        """Probe HubSpot CDN directory paths for additional files.

        HubSpot CDN sometimes returns HTML pages for folder paths containing
        links to individual files.  This probes known AMI content directories
        to discover files not linked from any page.
        """
        entries: list[FileEntry] = []

        base_cdn = "https://f.hubspotusercontent10.net/hubfs/9443417"
        for path in _HUBSPOT_PROBE_DIRS:
            probe_url = f"{base_cdn}/{path}"
            if probe_url in seen_urls:
                continue

            try:
                resp = sess.get(
                    probe_url, headers=_HEADERS, timeout=_REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                if resp.status_code != 200:
                    continue
                resp.encoding = "utf-8"

                # Look for file links in the CDN response
                found = self._extract_downloads_from_html(
                    resp.text,
                    f"HubSpot CDN /{path}",
                    "hubspot-cdn",
                    seen_urls,
                    entries,
                )
                if found:
                    log.info("[AMI] CDN /%s → %d files", path, found)
                time.sleep(_REQUEST_DELAY)
            except Exception:
                pass

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
          All ``.do`` endpoints (download.do, swDownload.do, amibcp.do,
          mmtool.do, veb.do, afu.do, etc.) exist but require J2EE FORM-
          based auth (j_security_check) — no bypass possible.
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

        # Probe EIP portal .do endpoints for unauthenticated access.
        # All .do actions use J2EE FORM-based auth (j_security_check).
        # HTTP 400 = endpoint exists but needs session; this discovers
        # the full list of actions available behind the login.
        eip_base = "https://eip.ami.com/eip"
        _EIP_ACTIONS = (
            "download.do", "swDownload.do", "saDownload.do",
            "fileDownload.do", "toolDownload.do",
            "softwareRelease.do", "swRelease.do", "swList.do",
            "productList.do", "downloadList.do", "downloadCenter.do",
            "biosTools.do", "biosUtility.do", "aptioTools.do",
            "amibcp.do", "mmtool.do", "veb.do", "afu.do",
            "securityAdvisory.do", "search.do", "product.do",
        )
        eip_found = 0
        for action in _EIP_ACTIONS:
            action_url = f"{eip_base}/{action}"
            if action_url in seen_urls:
                continue
            try:
                resp = sess.get(
                    action_url, timeout=8, allow_redirects=False,
                    headers=_HEADERS,
                )
                if resp.status_code == 400:
                    # Endpoint exists but requires auth parameters
                    seen_urls.add(action_url)
                    eip_found += 1
                elif resp.status_code == 200:
                    has_login = "j_security_check" in resp.text[:1000]
                    if not has_login:
                        # Unauthenticated access! Record it.
                        seen_urls.add(action_url)
                        entries.append(FileEntry(
                            name=f"EIP {action} (unauthenticated)",
                            url=action_url,
                            category="Subdomain/Portal",
                            description=f"EIP portal action accessible without login",
                            source="eip-probe",
                            product="AMI EIP Portal",
                        ))
                        eip_found += 1
            except Exception:
                pass

        if eip_found:
            log.info(
                "[AMI] EIP portal: %d .do endpoints discovered (auth-protected)",
                eip_found,
            )

        return entries

    # ── Session management ───────────────────────────────────────────────

    def _get_session(self) -> "requests.Session":
        """Return or create an HTTP session with TLS fingerprinting."""
        if self.session is not None:
            return self.session

        try:
            from crawl4ai.extensions.bypass.tls_session import build_tls_session
            sess = build_tls_session(verify_ssl=True)
        except ImportError:
            import requests as _requests
            sess = _requests.Session()
        sess.headers.update(_HEADERS)
        self.session = sess
        return sess

    @staticmethod
    def _format_size(content_length: str) -> str:
        """Format a Content-Length header value as a human-readable size."""
        try:
            size = int(content_length)
        except (ValueError, TypeError):
            return ""
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        if size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


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
    if any(d in host for d in _HUBSPOT_DOMAINS):
        return True
    return host == "ami.com" or host.endswith(".ami.com")


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
    if fn_lower.endswith((".exe", ".msi", ".cab", ".appimage")):
        return "Executable/Installer"
    if fn_lower.endswith((".tar", ".tgz", ".bz2", ".xz", ".zst", ".rar", ".7z")):
        return "Archive"
    if fn_lower.endswith((".iso", ".img", ".vmdk", ".vhd", ".ova")):
        return "Disk Image"
    if fn_lower.endswith((".rom", ".fw", ".uf2", ".hex", ".bin", ".efi")):
        return "Firmware"
    if fn_lower.endswith((".deb", ".rpm", ".apk", ".snap", ".flatpak")):
        return "Package"
    if fn_lower.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf")):
        return "Document"
    if fn_lower.endswith(".zip"):
        return "Utility/Tool"
    if fn_lower.endswith(".pdf"):
        return "Documentation"
    return "Other"


def _is_downloadable_mime(mime_type: str) -> bool:
    """Return *True* if the MIME type represents a downloadable binary/document."""
    if not mime_type:
        return False
    mime = mime_type.lower()
    # Always include binary types
    if mime.startswith(("application/", "audio/", "video/")):
        # Exclude web-page content types
        if mime in (
            "application/json",
            "application/xml",
            "application/xhtml+xml",
            "application/rss+xml",
            "application/javascript",
            "application/x-javascript",
        ):
            return False
        return True
    return False
