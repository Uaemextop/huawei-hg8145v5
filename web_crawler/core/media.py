"""Video, audio, CDN and download-link helpers extracted from the crawl engine.

Functions in this module operate on a :class:`~web_crawler.core.engine.Crawler`
instance (passed explicitly as the first argument) but live outside the class
so that *engine.py* stays focused on the BFS crawl loop.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import TYPE_CHECKING

import requests

try:
    from curl_cffi.requests.exceptions import RequestException as CfRequestException
except ImportError:
    CfRequestException = None  # type: ignore[misc,assignment]

from web_crawler.config.settings import CLOUD_STORAGE_HOSTS, REQUEST_TIMEOUT
from web_crawler.core.storage import file_content_hash, smart_local_path
from web_crawler.utils.log import log

if TYPE_CHECKING:
    from web_crawler.core.engine import Crawler

# ---------------------------------------------------------------------------
# Network exception tuple (mirrors engine._NETWORK_ERRORS)
# ---------------------------------------------------------------------------
_NETWORK_ERRORS: tuple[type[Exception], ...] = (requests.RequestException,)
if CfRequestException is not None:
    _NETWORK_ERRORS = (requests.RequestException, CfRequestException)

# ---------------------------------------------------------------------------
# Media extension sets
# ---------------------------------------------------------------------------

VIDEO_EXTENSIONS: frozenset[str] = frozenset((
    ".mp4", ".webm", ".ogv", ".avi", ".mov", ".flv", ".mkv", ".wmv",
    ".m4v", ".3gp", ".3g2", ".ts", ".mpeg", ".mpg", ".f4v", ".asf",
    ".m3u8",
))

AUDIO_EXTENSIONS: frozenset[str] = frozenset((
    ".mp3", ".ogg", ".wav", ".flac", ".aac", ".m4a", ".weba",
))

MEDIA_EXTENSIONS: frozenset[str] = VIDEO_EXTENSIONS | AUDIO_EXTENSIONS


# ---------------------------------------------------------------------------
# Pure helpers (no crawler state)
# ---------------------------------------------------------------------------

def is_media_url(url: str) -> bool:
    """Return ``True`` if *url* points to a media file (video/audio)."""
    path_lower = urllib.parse.urlparse(url).path.lower()
    return any(path_lower.endswith(ext) for ext in MEDIA_EXTENSIONS)


def is_media_content_type(ct: str) -> bool:
    """Return ``True`` if *ct* is a video or audio MIME type."""
    return ct.startswith("video/") or ct.startswith("audio/")


def sanitize_meta_value(value: str) -> str:
    """Sanitize a metadata value for pipe-separated output.

    Replaces pipe characters and newlines so they do not break
    the ``video_urls.txt`` line format.
    """
    return value.replace("|", "-").replace("\n", " ").replace("\r", "")


def merge_video_meta(
    existing: dict[str, str],
    incoming: dict[str, str],
) -> None:
    """Merge *incoming* metadata into *existing*, filling empty fields.

    Non-empty values in *existing* are kept; only blank fields are
    filled from *incoming*.
    """
    for key, val in incoming.items():
        if val and not existing.get(key):
            existing[key] = val


def build_direct_download_url(url: str) -> str:
    """Convert a cloud-storage sharing URL to a direct-download URL.

    Supported providers:

    * **Google Drive**: ``/file/d/ID/view`` → ``/uc?export=download&id=ID&confirm=t``
    * **Dropbox**: ``?dl=0`` → ``?dl=1``
    * **MediaFire**: kept as-is (requires JS)
    * **Mega**: kept as-is (requires client decryption)

    Returns the direct URL or the original URL if no transformation
    is available.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()

    # Google Drive: /file/d/<ID>/view → direct download
    if "drive.google.com" in host or "docs.google.com" in host:
        m = re.search(r"/(?:file/d/|open\?id=)([a-zA-Z0-9_-]+)", url)
        if m:
            file_id = m.group(1)
            return (
                f"https://drive.usercontent.google.com/download"
                f"?id={file_id}&export=download&confirm=t"
            )

    # Dropbox: change dl=0 to dl=1
    if "dropbox.com" in host:
        if "dl=0" in url:
            return url.replace("dl=0", "dl=1")
        if "dl=" not in url:
            sep = "&" if "?" in url else "?"
            return url + sep + "dl=1"

    # 1drv.ms / OneDrive: change type=embed to type=download
    if "1drv.ms" in host or "onedrive" in host:
        if "download=1" not in url:
            sep = "&" if "?" in url else "?"
            return url + sep + "download=1"

    return url


def resolve_ajax_params(
    links: set[str], page_url: str,
) -> set[str]:
    """Expand AJAX endpoints whose query string has empty values.

    When the JS extractor finds ``fetch('ajax_url.php?firmid=' + var)``
    it produces a bare URL like ``…/ajax_url.php?firmid=``.  If the
    page URL contains a query parameter whose name partially matches
    (e.g. ``firm=27162`` matches ``firmid``), fill in the value so the
    crawler can actually fetch the endpoint.
    """
    page_qs = urllib.parse.parse_qs(
        urllib.parse.urlparse(page_url).query, keep_blank_values=True,
    )
    if not page_qs:
        return set()
    extra: set[str] = set()
    for link in list(links):
        link_parsed = urllib.parse.urlparse(link)
        link_qs = urllib.parse.parse_qs(
            link_parsed.query, keep_blank_values=True,
        )
        if not link_qs:
            continue
        filled = False
        new_params: dict[str, str] = {}
        for param, vals in link_qs.items():
            val = vals[0] if vals else ""
            if val:
                new_params[param] = val
                continue
            # Try to match against page URL params (substring match)
            for pname, pvals in page_qs.items():
                if not pvals or not pvals[0]:
                    continue
                # Match: "firmid" contains "firm", or "firm" contains
                # "firmid", or exact match.
                pname_l = pname.lower()
                param_l = param.lower()
                if (pname_l in param_l or param_l in pname_l
                        or pname_l == param_l):
                    new_params[param] = pvals[0]
                    filled = True
                    break
            else:
                new_params[param] = val
        if filled:
            new_query = urllib.parse.urlencode(new_params)
            resolved = urllib.parse.urlunparse((
                link_parsed.scheme, link_parsed.netloc,
                link_parsed.path, "", new_query, "",
            ))
            extra.add(resolved)
    return extra


# ---------------------------------------------------------------------------
# Crawler-aware helpers (require a Crawler instance)
# ---------------------------------------------------------------------------

def track_video_url(crawler: Crawler, url: str) -> None:
    """Append *url* to the video list if it has a video extension.

    Must be called while ``crawler._lock`` is held.
    """
    path_lower = urllib.parse.urlparse(url).path.lower()
    if any(path_lower.endswith(ext) for ext in VIDEO_EXTENSIONS):
        crawler._video_urls.append(url)


def record_download_link(crawler: Crawler, url: str) -> None:
    """Write *url* to ``download_links.txt`` as a ready-to-run curl command.

    The command includes all session headers (Authorization, guid,
    Request-Tag, etc.) so users can paste it into a terminal and download
    the file directly.

    Must be called while ``crawler._lock`` is held.
    """
    if url in crawler._download_links_seen:
        return
    crawler._download_links_seen.add(url)

    # Build curl header flags from the current session headers.
    header_parts: list[str] = []
    for name, value in crawler.session.headers.items():
        # Skip headers that curl adds automatically or that vary per request
        if name.lower() in ("host", "content-length", "transfer-encoding",
                             "connection", "accept-encoding"):
            continue
        # Escape single quotes in header values
        safe_value = value.replace("'", "'\\''")
        header_parts.append(f"-H '{name}: {safe_value}'")

    # Derive a safe output filename from the URL path
    path = urllib.parse.urlparse(url).path
    filename = path.rstrip("/").rsplit("/", 1)[-1] or "download"
    # URL-decode special characters in the filename
    filename = urllib.parse.unquote(filename)

    headers_str = " \\\n  ".join(header_parts)
    if headers_str:
        cmd = f"curl -L -o '{filename}' \\\n  {headers_str} \\\n  '{url}'"
    else:
        cmd = f"curl -L -o '{filename}' '{url}'"

    # Also write a wget-compatible line
    wget_headers = " ".join(
        f"--header='{n}: {v.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'"
        for n, v in crawler.session.headers.items()
        if n.lower() not in ("host", "content-length", "transfer-encoding",
                              "connection", "accept-encoding")
    )
    if wget_headers:
        wget_cmd = f"wget {wget_headers} -O '{filename}' '{url}'"
    else:
        wget_cmd = f"wget -O '{filename}' '{url}'"

    crawler.output_dir.mkdir(parents=True, exist_ok=True)
    with crawler._download_links_path.open("a", encoding="utf-8") as fh:
        fh.write(f"# {url}\n")
        fh.write(f"{cmd}\n\n")
        fh.write(f"# wget alternative:\n# {wget_cmd}\n\n")
        fh.write("# ─" * 40 + "\n\n")


def write_video_url_list(crawler: Crawler) -> None:
    """Write tracked video URLs to ``video_urls.txt``.

    Each line uses the pipe-separated format (6 fields)::

        URL|Title|Author|ThumbnailUrl|Duration|UploadDate

    Metadata is sourced from JSON-LD ``VideoObject``, Schema.org
    microdata (``itemprop`` tags), or page-level OG/meta tags (in
    that priority order).  Pipe characters and newlines inside
    metadata values are sanitized to preserve the format.
    """
    if not crawler._video_urls:
        return
    video_list = crawler.output_dir / "video_urls.txt"
    video_list.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for url in crawler._video_urls:
        meta = crawler._video_meta.get(url, {})
        parts = [
            url,
            sanitize_meta_value(meta.get("title", "")),
            sanitize_meta_value(meta.get("author", "")),
            sanitize_meta_value(meta.get("thumbnail", "")),
            sanitize_meta_value(meta.get("duration", "")),
            sanitize_meta_value(meta.get("upload_date", "")),
        ]
        lines.append("|".join(parts))
    video_list.write_text(
        "\n".join(lines) + "\n", encoding="utf-8",
    )
    log.info("Video URL list: %d URL(s) → %s",
              len(crawler._video_urls), video_list)


def write_url_list(crawler: Crawler) -> None:
    """Write all **video** URLs to ``url_list.txt``.

    Includes URLs whose path ends with a known video extension
    (``VIDEO_EXTENSIONS``) from both saved downloads and tracked
    video URLs (e.g. media files recorded when ``--skip-media-files``
    is active).
    """
    saved_videos = [
        u for u in crawler._saved_urls
        if any(urllib.parse.urlparse(u).path.lower().endswith(ext)
               for ext in VIDEO_EXTENSIONS)
    ]
    # Merge saved video URLs with tracked video URLs, preserving order
    # and removing duplicates.
    snapshot = list(dict.fromkeys(saved_videos + crawler._video_urls))
    if not snapshot:
        return
    url_list = crawler.output_dir / "url_list.txt"
    url_list.parent.mkdir(parents=True, exist_ok=True)
    url_list.write_text(
        "\n".join(snapshot) + "\n", encoding="utf-8",
    )


def populate_video_meta(
    crawler: Crawler, html: str, links: set[str],
) -> None:
    """Extract metadata from an HTML page and associate it with video links.

    Per-video metadata from JSON-LD ``VideoObject`` entries and
    Schema.org microdata (``itemprop`` meta tags) takes priority
    over page-level metadata (title, author, thumbnail, duration,
    upload_date).

    When a video URL already has metadata from a previous call
    (e.g. from a JSON API response with empty fields), non-empty
    values from the new source are merged in rather than blocked.
    """
    from web_crawler.extraction.html import (
        extract_page_metadata,
        extract_jsonld_video_meta,
        extract_microdata_video_meta,
    )
    page_meta = extract_page_metadata(html)
    video_meta = extract_jsonld_video_meta(html)
    microdata_meta = extract_microdata_video_meta(html)

    # Enrich page-level fallback with shared fields from the
    # page's structured data (e.g. author) so that video URLs
    # that are NOT the microdata contentURL still get them.
    for src in (microdata_meta, video_meta):
        if src:
            first = next(iter(src.values()))
            if not page_meta.get("author") and first.get("author"):
                page_meta["author"] = first["author"]
            break  # use the first available source

    with crawler._lock:
        # Store JSON-LD per-video metadata (highest priority)
        for vurl, vmeta in video_meta.items():
            existing = crawler._video_meta.get(vurl)
            if existing is None:
                crawler._video_meta[vurl] = vmeta
            else:
                merge_video_meta(existing, vmeta)

        # Store microdata per-video metadata (second priority)
        for vurl, vmeta in microdata_meta.items():
            existing = crawler._video_meta.get(vurl)
            if existing is None:
                crawler._video_meta[vurl] = vmeta
            else:
                merge_video_meta(existing, vmeta)

        # For discovered links that look like video URLs, use
        # page-level metadata as a fallback.
        for link in links:
            path_lower = urllib.parse.urlparse(link).path.lower()
            if any(path_lower.endswith(ext) for ext in VIDEO_EXTENSIONS):
                existing = crawler._video_meta.get(link)
                if existing is None:
                    crawler._video_meta[link] = dict(page_meta)
                else:
                    merge_video_meta(existing, page_meta)


def record_external_download(
    crawler: Crawler,
    page_url: str,
    sharing_url: str,
    direct_url: str,
) -> None:
    """Append an external download link to ``download_urls.txt``.

    Each entry contains:

    * The source page URL
    * The cloud-storage sharing URL (as returned by the AJAX endpoint)
    * A direct-download URL (with provider-specific bypass)
    * Ready-to-run ``curl`` and ``wget`` commands

    Must be called while ``crawler._lock`` is held.
    """
    dl_path = crawler.output_dir / "download_urls.txt"
    crawler.output_dir.mkdir(parents=True, exist_ok=True)
    with dl_path.open("a", encoding="utf-8") as fh:
        fh.write(f"# Source page: {page_url}\n")
        fh.write(f"# Sharing URL: {sharing_url}\n")
        fh.write(f"{direct_url}\n")
        fh.write(f"curl -L -o download_file '{direct_url}'\n")
        fh.write(f"wget -O download_file '{direct_url}'\n")
        fh.write("# " + "─" * 60 + "\n\n")


def write_download_url_list(crawler: Crawler) -> None:
    """Write all discovered external download URLs to ``download_urls.txt``.

    This is called at the end of the crawl.  If individual entries
    were already written during crawl (by :func:`record_external_download`),
    this method also writes a summary section at the end.
    """
    if not crawler._external_download_urls:
        return
    dl_path = crawler.output_dir / "download_urls.txt"
    dl_path.parent.mkdir(parents=True, exist_ok=True)
    with dl_path.open("a", encoding="utf-8") as fh:
        fh.write("\n# " + "═" * 60 + "\n")
        fh.write(f"# SUMMARY: {len(crawler._external_download_urls)}"
                  " download URL(s) discovered\n")
        fh.write("# " + "═" * 60 + "\n\n")
        for page_url, ajax_ep, download_url in crawler._external_download_urls:
            direct = build_direct_download_url(download_url)
            fh.write(f"{direct}\n")
    log.info(
        "Download URLs: %d URL(s) → %s",
        len(crawler._external_download_urls), dl_path,
    )


def discover_download_links(
    crawler: Crawler, links: set[str], page_url: str,
) -> None:
    """Follow AJAX endpoints that return cloud-storage download URLs.

    Sites like getwayrom.com hide the real download link behind an
    AJAX call (``fetch('ajax_url.php?firmid=' + id)``).  The
    response body is a plain-text URL pointing to Google Drive,
    OneDrive, Mega, etc.

    This method:

    1. Identifies candidate AJAX endpoints in *links* (PHP/ASP
       URLs whose path suggests a download handler).
    2. GETs each endpoint with the crawler's session.
    3. If the response is a cloud-storage URL, records it in
       ``download_urls.txt`` with a ready-to-use direct link.
    """
    _AJAX_HINT_RE = re.compile(
        r"(?:ajax|download|get[_-]?(?:link|url|file)|dl|fetch)[^/]*\.php",
        re.I,
    )
    for link in list(links):
        parsed = urllib.parse.urlparse(link)
        if parsed.netloc != crawler.allowed_host:
            continue
        # Only follow candidates with a query string (parameterised)
        if not parsed.query:
            continue
        # Check that the query has at least one non-empty param value
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        has_value = any(v and v[0] for v in qs.values())
        if not has_value:
            continue
        # Must match the AJAX download-endpoint heuristic
        if not _AJAX_HINT_RE.search(parsed.path):
            continue
        # Skip if already discovered
        with crawler._lock:
            if link in crawler._download_links_seen:
                continue
            crawler._download_links_seen.add(link)

        log.debug("[AJAX-DL] Probing download endpoint: %s", link)
        try:
            resp = crawler.session.get(
                link,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": page_url,
                },
            )
        except _NETWORK_ERRORS as exc:
            log.debug("[AJAX-DL] Request failed: %s – %s", link, exc)
            continue

        if not resp.ok:
            log.debug("[AJAX-DL] HTTP %s for %s", resp.status_code, link)
            continue

        body = resp.text.strip()
        if not body or len(body) > 2000:
            continue

        # Check if the response is a URL
        if not body.startswith(("http://", "https://")):
            continue

        download_url = body
        dl_parsed = urllib.parse.urlparse(download_url)
        is_cloud = dl_parsed.netloc in CLOUD_STORAGE_HOSTS
        # Also match subdomains (e.g. dl.dropboxusercontent.com)
        if not is_cloud:
            for host in CLOUD_STORAGE_HOSTS:
                if dl_parsed.netloc.endswith("." + host):
                    is_cloud = True
                    break

        if not is_cloud and dl_parsed.netloc == crawler.allowed_host:
            # Same-host download – enqueue it normally
            continue

        # Build direct-download URL for known cloud providers
        direct_url = build_direct_download_url(download_url)

        log.info(
            "  [DOWNLOAD] %s → %s",
            link, download_url,
        )
        with crawler._lock:
            crawler._external_download_urls.append(
                (page_url, link, download_url)
            )

        # Also write to download_urls.txt immediately (with curl cmd)
        with crawler._lock:
            record_external_download(
                crawler, page_url, download_url, direct_url,
            )


def fetch_cdn_media(crawler: Crawler, url: str) -> None:
    """Download a media file from an external CDN host.

    CDN URLs are always streamed directly to disk.  No link
    extraction, probe, or WAF checks are performed — these are
    trusted media resources discovered from the crawled site's HTML.
    Files are saved under a ``_cdn/<hostname>/`` subdirectory.
    """
    log.debug("[CDN] GET %s", url)

    try:
        resp = crawler.session.get(
            url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
            stream=True,
        )
    except _NETWORK_ERRORS as exc:
        log.warning("[CDN] Request failed for %s – %s", url, exc)
        crawler._stats["err"] += 1
        return

    if not resp.ok:
        log.debug("[CDN] HTTP %s for %s – skipping", resp.status_code, url)
        crawler._stats["err"] += 1
        return

    content_type = resp.headers.get("Content-Type", "application/octet-stream")
    content_disp = resp.headers.get("Content-Disposition", "")
    ct_lower_cdn = content_type.split(";")[0].strip().lower()

    # Skip media files if requested – record URL but don't download
    if crawler.skip_media_files and (
        is_media_url(url) or is_media_content_type(ct_lower_cdn)
    ):
        with crawler._lock:
            track_video_url(crawler, url)
            crawler._stats["skip"] += 1
        log.info("[CDN] [SKIP-MEDIA] %s (media file skipped)", url)
        resp.close()
        time.sleep(crawler.delay)
        return

    # Skip-download: record curl command instead of downloading
    cdn_url_ext = urllib.parse.urlparse(url).path.rsplit(".", 1)[-1].lower()
    if crawler.skip_download_exts and cdn_url_ext in crawler.skip_download_exts:
        with crawler._lock:
            record_download_link(crawler, url)
            crawler._stats["skip"] += 1
        log.info("[CDN] [SKIP-DOWNLOAD] %s (link recorded, not downloaded)", url)
        resp.close()
        time.sleep(crawler.delay)
        return

    # Build local path: _cdn/<hostname>/<path>
    parsed = urllib.parse.urlparse(url)
    cdn_dir = crawler.output_dir / "_cdn" / parsed.netloc
    rel_path = parsed.path.lstrip("/")
    if not rel_path:
        rel_path = "index"
    local_stream = cdn_dir / rel_path
    # Apply extension from Content-Type if file has no extension
    if not local_stream.suffix:
        hint = smart_local_path(url, cdn_dir, content_type, content_disp)
        if hint.suffix:
            local_stream = local_stream.with_suffix(hint.suffix)

    try:
        chunks = resp.iter_content(chunk_size=524288)
        first_chunk = next(chunks, b"")
    except _NETWORK_ERRORS as exc:
        log.warning("[CDN] Stream error for %s – %s", url, exc)
        crawler._stats["err"] += 1
        return

    if not first_chunk:
        log.debug("[CDN] Empty response for %s – skipping", url)
        crawler._stats["err"] += 1
        return

    local_stream.parent.mkdir(parents=True, exist_ok=True)
    written = len(first_chunk)
    with local_stream.open("wb") as fh:
        fh.write(first_chunk)
        for chunk in chunks:
            if chunk:
                fh.write(chunk)
                written += len(chunk)

    ch = file_content_hash(local_stream)
    with crawler._lock:
        if ch in crawler._hashes:
            log.debug("[CDN] Duplicate for %s – removing", url)
            local_stream.unlink(missing_ok=True)
            crawler._stats["dup"] += 1
        else:
            crawler._hashes.add(ch)
            log.info(
                "  [CDN-DOWNLOAD] %s → %s (%.1f MiB)",
                url, local_stream.name, written / (1024 * 1024),
            )
            crawler._stats["ok"] += 1
            crawler._saved_urls.append(url)
            track_video_url(crawler, url)
            if crawler.debug:
                crawler._save_http_headers(local_stream, resp, url)
            crawler._maybe_git_push()

    time.sleep(crawler.delay)


def extract_extension_links(
    crawler: Crawler,
    content: bytes,
    page_url: str,
    extensions: frozenset[str],
) -> set[str]:
    """Scan *content* for href/src attributes pointing to files
    with any of the target *extensions*.  Returns absolute URLs.
    """
    if crawler._ext_link_re is None:
        return set()
    text = content.decode("utf-8", errors="replace")
    found: set[str] = set()
    for m in crawler._ext_link_re.finditer(text):
        link = m.group(1).strip()
        if not link:
            continue
        link = urllib.parse.urljoin(page_url, link)
        found.add(link)
    return found
