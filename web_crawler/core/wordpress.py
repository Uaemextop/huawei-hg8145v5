"""WordPress and WooCommerce discovery helpers.

Standalone functions extracted from :class:`~web_crawler.core.engine.Crawler`
to keep the main engine module focused on generic crawling logic.  Every
function that needs access to crawler state receives a *crawler* instance as
its first argument.
"""

from __future__ import annotations

import datetime
import re
import time
import urllib.parse
from typing import TYPE_CHECKING

import requests

from web_crawler.config.settings import (
    REQUEST_TIMEOUT,
    WP_DISCOVERY_PATHS,
    WP_PLUGIN_FILES,
    WP_PLUGIN_PROBES,
    WP_THEME_FILES,
    WP_THEME_PROBES,
)
from web_crawler.utils.log import log
from web_crawler.utils.url import url_key

if TYPE_CHECKING:
    from web_crawler.core.engine import Crawler

# Network errors that should be caught and silenced during probing.
_NETWORK_ERRORS: tuple[type[Exception], ...] = (requests.RequestException,)

try:
    from curl_cffi.requests.exceptions import RequestException as CfRequestException

    _NETWORK_ERRORS = (requests.RequestException, CfRequestException)
except ImportError:  # pragma: no cover
    pass

# Regex used to locate a WP REST API nonce in page HTML.
_WP_NONCE_RE = re.compile(
    r"""(?:wp_rest_nonce|wpApiSettings[^}]*nonce)\W*[=:]\s*['"]([a-f0-9]+)['"]""",
    re.I,
)

# Archive-extension pattern for scanning product descriptions.
_ARCHIVE_RE = re.compile(
    r'https?://[^\s"\'<>]+\.(?:zip|rar|7z|tar|gz|bz2|xz|bin|exe'
    r'|img|iso|hwnp|fwu|pkg)(?:\?[^\s"\'<>]*)?',
    re.I,
)

# Pattern for extracting download links from directory listing HTML.
_DIR_LISTING_RE = re.compile(
    r'href=["\']([^"\']*\.(?:zip|rar|7z|bin|tar\.gz|tar|gz|bz2'
    r'|xz|exe|img|iso|hwnp|fwu|pkg'
    r'|mp4|webm|ogv|avi|mov|flv|mkv|wmv|m4v|3gp|3g2'
    r'|ts|mpeg|mpg|f4v|asf|vob|m2ts|mts'
    r'|mp3|ogg|wav|flac|aac|m4a|weba'
    r'|m3u8|mpd))["\']',
    re.I,
)


# ------------------------------------------------------------------
# Detection
# ------------------------------------------------------------------

def detect_wordpress(html: str) -> bool:
    """Return *True* if *html* contains WordPress fingerprints."""
    lower = html.lower()
    indicators = [
        "wp-content/",
        "wp-includes/",
        'name="generator" content="wordpress',
        "/wp-json/",
        "wp-emoji-release.min.js",
    ]
    return any(ind in lower for ind in indicators)


# ------------------------------------------------------------------
# Discovery
# ------------------------------------------------------------------

def enqueue_wp_discovery(crawler: Crawler, depth: int) -> None:
    """Enqueue WordPress-specific discovery URLs."""
    if crawler._wp_probed:
        return
    crawler._wp_probed = True

    for path in WP_DISCOVERY_PATHS:
        wp_url = crawler.base + path
        crawler._probe_urls.add(url_key(wp_url))
        crawler._enqueue(wp_url, 0)

    # Plugin enumeration (readme.txt to confirm existence)
    for slug in WP_PLUGIN_PROBES:
        wp_url = crawler.base + f"/wp-content/plugins/{slug}/readme.txt"
        crawler._probe_urls.add(url_key(wp_url))
        crawler._enqueue(wp_url, 0)

    # Theme enumeration (style.css to confirm existence)
    for slug in WP_THEME_PROBES:
        wp_url = crawler.base + f"/wp-content/themes/{slug}/style.css"
        crawler._probe_urls.add(url_key(wp_url))
        crawler._enqueue(wp_url, 0)

    # Author enumeration (users 1-10)
    for n in range(1, 11):
        wp_url = crawler.base + f"/?author={n}"
        crawler._probe_urls.add(url_key(wp_url))
        crawler._enqueue(wp_url, 0)

    total = (
        len(WP_DISCOVERY_PATHS) + len(WP_PLUGIN_PROBES)
        + len(WP_THEME_PROBES) + 10
    )
    log.info("[WP] WordPress detected – enqueued %d discovery URLs", total)

    # Discover media file URLs (images, ZIPs) via REST API
    discover_wp_media(crawler)
    # Discover WooCommerce product pages and any linked files
    discover_wc_products(crawler)


def discover_wp_media(crawler: Crawler) -> None:
    """Use the WP REST API to discover downloadable media files
    (images, ZIPs, etc.) and enqueue their direct URLs."""
    page = 1
    total = 0
    while page <= 20:  # safety cap
        api_url = (
            f"{crawler.base}/wp-json/wp/v2/media"
            f"?per_page=100&page={page}"
        )
        try:
            resp = crawler.session.get(api_url, timeout=REQUEST_TIMEOUT)
        except _NETWORK_ERRORS:
            log.debug("  [WP-MEDIA] Network error on page %d", page)
            break
        if resp.status_code != 200:
            break
        try:
            items = resp.json()
        except ValueError:
            log.warning("[WP-MEDIA] Invalid JSON on page %d", page)
            break
        if not items:
            break
        for item in items:
            src = item.get("source_url", "")
            if src and crawler.allowed_host in src:
                crawler._enqueue(src, 0, priority=True)
                total += 1
        if len(items) < 100:
            break
        page += 1
        time.sleep(crawler.delay)
    if total:
        log.debug(
            "  [WP-MEDIA] Discovered %d media files via REST API", total
        )


def discover_wc_products(crawler: Crawler) -> None:
    """Enumerate WooCommerce products via the Store API and enqueue:

    * every product permalink (HTML product page)
    * every image / thumbnail URL
    * any archive/binary files linked in the product description

    Also probes the WooCommerce uploads directory with common
    year/month sub-paths when *download_extensions* is set.
    """
    page = 1
    product_total = 0
    file_total = 0

    while page <= 50:  # WC sites rarely have >5 000 products (100/page)
        api_url = (
            f"{crawler.base}/wp-json/wc/store/v1/products"
            f"?per_page=100&page={page}"
        )
        try:
            resp = crawler.session.get(api_url, timeout=REQUEST_TIMEOUT)
        except _NETWORK_ERRORS:
            log.debug("  [WC] Network error on page %d", page)
            break
        if resp.status_code != 200:
            break
        try:
            items = resp.json()
        except ValueError:
            log.warning("[WC] Invalid JSON on page %d", page)
            break
        if not isinstance(items, list) or not items:
            break
        for item in items:
            # Product page
            permalink = item.get("permalink", "")
            if permalink and crawler.allowed_host in permalink:
                crawler._enqueue(permalink, 1)
                product_total += 1
            # Product images
            for img in item.get("images", []):
                src = img.get("src", "")
                if src and crawler.allowed_host in src:
                    crawler._enqueue(src, 0)
            # Archive files embedded in description HTML
            desc = item.get("description", "") + item.get(
                "short_description", ""
            )
            for m in _ARCHIVE_RE.finditer(desc):
                link = m.group(0)
                if crawler.allowed_host in link:
                    crawler._enqueue(link, 0, priority=True)
                    file_total += 1
        if len(items) < 100:
            break
        page += 1
        time.sleep(crawler.delay)

    if product_total:
        log.info(
            "[WC] Discovered %d product pages, %d archive links",
            product_total,
            file_total,
        )

    # Probe WooCommerce uploads sub-directories for archive files.
    # woocommerce_uploads/ is protected by robots.txt but we probe it
    # when robots is disabled or when download_extensions is set.
    if crawler.download_extensions:
        probe_wc_uploads(crawler)


def probe_wc_uploads(crawler: Crawler) -> None:
    """Probe ``wp-content/uploads/woocommerce_uploads/`` with recent
    year/month paths to discover directly accessible firmware ZIPs."""
    now = datetime.datetime.now()
    # Probe the last 18 months
    paths_to_probe: list[str] = []
    for delta in range(18):
        month = (now.month - delta - 1) % 12 + 1
        year = now.year - ((now.month - delta - 1) // 12)
        for base_dir in (
            f"/wp-content/uploads/woocommerce_uploads/{year}/{month:02d}/",
            f"/wp-content/uploads/{year}/{month:02d}/",
        ):
            paths_to_probe.append(base_dir)

    probed = 0
    for path in paths_to_probe:
        try:
            r = crawler.session.get(
                crawler.base + path,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
        except _NETWORK_ERRORS:
            log.debug("  [WC-UPLOADS] Network error probing %s", path)
            continue
        if not r.ok:
            continue
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct.lower():
            continue
        for m in _DIR_LISTING_RE.finditer(r.text):
            link = urllib.parse.urljoin(crawler.base + path, m.group(1))
            if crawler.allowed_host in link:
                crawler._enqueue(link, 0, priority=True)
                probed += 1
    if probed:
        log.info(
            "[WC-UPLOADS] Found %d archive files in uploads dirs", probed
        )


# ------------------------------------------------------------------
# Deep-crawl helpers
# ------------------------------------------------------------------

def deep_crawl_wp_plugin(crawler: Crawler, slug: str, depth: int) -> None:
    """Enqueue internal files for a confirmed WordPress plugin."""
    if slug in crawler._wp_confirmed_plugins:
        return
    crawler._wp_confirmed_plugins.add(slug)
    base_path = f"/wp-content/plugins/{slug}/"
    for f in WP_PLUGIN_FILES:
        crawler._enqueue(crawler.base + base_path + f, depth + 1)
    log.debug(
        "  [WP-PLUGIN] Deep-crawling plugin '%s' (%d files)",
        slug,
        len(WP_PLUGIN_FILES),
    )


def deep_crawl_wp_theme(crawler: Crawler, slug: str, depth: int) -> None:
    """Enqueue internal files for a confirmed WordPress theme."""
    if slug in crawler._wp_confirmed_themes:
        return
    crawler._wp_confirmed_themes.add(slug)
    base_path = f"/wp-content/themes/{slug}/"
    for f in WP_THEME_FILES:
        crawler._enqueue(crawler.base + base_path + f, depth + 1)
    log.debug(
        "  [WP-THEME] Deep-crawling theme '%s' (%d files)",
        slug,
        len(WP_THEME_FILES),
    )


def extract_wp_nonce(crawler: Crawler, html: str) -> None:
    """Extract a WP REST nonce from page HTML.

    NOTE: The nonce is intentionally NOT added to the session's default
    headers.  Sending ``X-WP-Nonce`` on every request tells WordPress to
    treat the request as authenticated; when the nonce is not tied to a
    logged-in user (which is always the case for a crawler) WordPress
    returns **403 Forbidden** on every REST endpoint instead of the
    normal anonymous 200 response.  We store it only so sub-classes can
    use it selectively if needed.
    """
    m = _WP_NONCE_RE.search(html)
    if m:
        crawler._wp_nonce = m.group(1)
        log.debug("  WP nonce extracted: %s", crawler._wp_nonce)


def check_wp_deep_crawl(
    crawler: Crawler, path_lower: str, depth: int
) -> None:
    """If a WP plugin/theme slug is confirmed (its ``readme.txt`` or
    ``style.css`` was fetched successfully), deep-crawl its internal
    files."""
    # Plugin: /wp-content/plugins/<slug>/readme.txt
    m = re.match(
        r"/wp-content/plugins/([a-z0-9_-]+)/readme\.txt$",
        path_lower,
    )
    if m:
        deep_crawl_wp_plugin(crawler, m.group(1), depth)
        return
    # Theme: /wp-content/themes/<slug>/style.css
    m = re.match(
        r"/wp-content/themes/([a-z0-9_-]+)/style\.css$",
        path_lower,
    )
    if m:
        deep_crawl_wp_theme(crawler, m.group(1), depth)
