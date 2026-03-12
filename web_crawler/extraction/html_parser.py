"""
HTML/ASP attribute extraction via BeautifulSoup.
"""

import json
import re
import warnings

from web_crawler.utils.url import normalise_url
from web_crawler.extraction.css import extract_css_urls
from web_crawler.extraction.javascript import extract_js_paths

try:
    import lxml  # noqa: F401
    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"

try:
    from bs4 import BeautifulSoup
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    BeautifulSoup = None  # type: ignore[misc,assignment]


# Open Graph and Twitter Card properties that contain media URLs
_OG_MEDIA_PROPS = frozenset({
    "og:image", "og:video", "og:video:url",
    "og:video:secure_url", "og:audio",
    "og:audio:url", "og:audio:secure_url",
})
_TW_MEDIA_PROPS = frozenset({"twitter:image", "twitter:player"})


def _parse_srcset(srcset: str) -> list[str]:
    """Extract individual URLs from an ``srcset`` or ``imagesrcset`` value.

    Each entry in srcset looks like ``url 1x`` or ``url 300w``.  This
    function splits by comma, strips descriptors and returns raw URLs.
    """
    urls: list[str] = []
    for entry in srcset.split(","):
        parts = entry.strip().split()
        if parts:
            urls.append(parts[0])
    return urls


# data-* attributes that commonly carry navigable/crawlable URLs across
# many platforms (XenForo, WordPress, generic JS frameworks).
# Values containing unresolved template placeholders (``{…}``) are skipped.
_DATA_URL_ATTRS = (
    "data-href",
    "data-url",
    "data-preview-url",
    "data-page-url",
    "data-acurl",
    "data-xf-href",
)


def extract_html_attrs(html: str, page_url: str, base: str) -> set[str]:
    """
    Extract every resource URL from HTML/ASP content using BeautifulSoup.
    Also parses inline ``<style>`` and ``<script>`` blocks.
    """
    found: set[str] = set()

    if BeautifulSoup is None:
        return found

    def _add(raw: str, *, allow_external: bool = False) -> None:
        n = normalise_url(raw.strip(), page_url, base,
                          allow_external=allow_external)
        if n:
            found.add(n)

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return found

    # Tags whose media attributes may reference external CDNs
    _MEDIA_TAGS = {"video", "source", "audio", "track"}

    # Attributes whose values use the srcset multi-URL format
    _SRCSET_ATTRS = {"srcset", "imagesrcset"}

    attr_map = {
        "a":       ["href"],
        "link":    ["href", "imagesrcset"],
        "script":  ["src"],
        "img":     ["src", "srcset", "data-src", "data-lazy-src",
                    "data-srcset"],
        "picture": [],
        "source":  ["src", "srcset", "data-src", "data-video-src",
                    "data-srcset"],
        "iframe":  ["src"],
        "frame":   ["src"],
        "form":    ["action"],
        "input":   ["src"],
        "body":    ["background"],
        "meta":    [],
        "object":  ["data"],
        "embed":   ["src"],
        "audio":   ["src", "data-src"],
        "video":   ["src", "poster", "data-src", "data-lazy-src",
                    "data-video-src", "data-video-url"],
        "track":   ["src"],
        "use":     ["href", "xlink:href"],
    }
    for tag, attrs in attr_map.items():
        is_media = tag in _MEDIA_TAGS
        for el in soup.find_all(tag):
            for attr in attrs:
                val = el.get(attr)
                if not val:
                    continue
                if attr in _SRCSET_ATTRS:
                    for src_url in _parse_srcset(val):
                        _add(src_url, allow_external=is_media)
                else:
                    _add(val, allow_external=is_media)

            if tag == "meta":
                content = el.get("content", "")
                m = re.search(r"url=([^\s;\"']+)", content, re.I)
                if m:
                    _add(m.group(1))
                # Schema.org itemprop with URL values (contentURL,
                # embedURL, thumbnailUrl, url, image, etc.)
                itemprop = (el.get("itemprop") or "").lower()
                if itemprop and content:
                    _url_props = {
                        "contenturl", "embedurl", "thumbnailurl",
                        "url", "image",
                    }
                    if itemprop in _url_props and content.startswith(
                        ("http://", "https://", "/")
                    ):
                        _add(content, allow_external=True)
                # Open Graph (og:image, og:video, og:audio, og:url)
                # and Twitter Card (twitter:image) media meta tags
                og_prop = (el.get("property") or "").lower()
                tw_name = (el.get("name") or "").lower()
                if content and content.startswith(
                    ("http://", "https://", "/")
                ):
                    if og_prop in _OG_MEDIA_PROPS or tw_name in _TW_MEDIA_PROPS:
                        _add(content, allow_external=True)

            # XenForo / generic: <picture data-variations='{"default":{"1":"/path",...}}'>
            if tag == "picture":
                variations_raw = el.get("data-variations", "")
                if variations_raw:
                    _extract_variations_urls(variations_raw, _add)

    # ------------------------------------------------------------------
    # Generic data-* URL attributes (XenForo data-href, data-preview-url,
    # data-page-url, data-acurl, data-xf-href, data-url, etc.)
    # Scans ALL tags because these attributes are not tag-specific.
    # Skips values with unresolved template placeholders like {url}.
    # ------------------------------------------------------------------
    for attr_name in _DATA_URL_ATTRS:
        for el in soup.find_all(attrs={attr_name: True}):
            val = el.get(attr_name, "")
            if val and "{" not in val:
                _add(val)

    for style_el in soup.find_all("style"):
        found |= extract_css_urls(style_el.get_text(), page_url, base)

    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            found |= extract_js_paths(script_el.get_text(), page_url, base)

    # JSON-LD structured data – extract media URLs from VideoObject,
    # AudioObject and other Schema.org types that embed content URLs.
    # Both camelCase (Schema.org canonical) and lowercase variants are
    # checked because some implementations deviate from the spec.
    _JSONLD_URL_KEYS = frozenset({
        "contenturl", "embedurl", "thumbnailurl", "url",
        "contentUrl", "embedUrl", "thumbnailUrl",
    })
    for ld_el in soup.find_all("script", type="application/ld+json"):
        try:
            ld_data = json.loads(ld_el.get_text())
        except (json.JSONDecodeError, TypeError):
            continue
        _extract_jsonld_urls(ld_data, _JSONLD_URL_KEYS, _add)

    return found


def _extract_jsonld_urls(
    obj: object,
    keys: frozenset[str],
    add_fn,
) -> None:
    """Recursively walk a JSON-LD structure and pass media URLs to *add_fn*."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str) and v.startswith(
                ("http://", "https://", "/")
            ):
                add_fn(v, allow_external=True)
            else:
                _extract_jsonld_urls(v, keys, add_fn)
    elif isinstance(obj, list):
        for item in obj:
            _extract_jsonld_urls(item, keys, add_fn)


def _extract_variations_urls(raw: str, add_fn) -> None:
    """Extract image URLs from a XenForo ``data-variations`` JSON attribute.

    The value is HTML-entity-encoded JSON, e.g.::

        {"default":{"1":"/data/assets/logo_default/xenforo.jpg","2":null},
         "alternate":{"1":"/data/assets/logo_alternate/xenforo.jpg","2":null}}

    Each string value that looks like a path is passed to *add_fn*.
    """
    try:
        import html as _html
        data = json.loads(_html.unescape(raw))
    except (json.JSONDecodeError, TypeError, ValueError):
        return
    _walk_variations(data, add_fn)


def _walk_variations(obj: object, add_fn) -> None:
    """Recursively walk a data-variations structure for URL strings."""
    if isinstance(obj, dict):
        for v in obj.values():
            _walk_variations(v, add_fn)
    elif isinstance(obj, list):
        for item in obj:
            _walk_variations(item, add_fn)
    elif isinstance(obj, str) and obj.startswith(("http://", "https://", "/")):
        add_fn(obj)


# ------------------------------------------------------------------
# Download-link extraction (XenForo XFRM, attachments, file-hosting)
# ------------------------------------------------------------------

# Regex matching XenForo Resource Manager download endpoints.
_XFRM_DOWNLOAD_RE = re.compile(
    r"/resources/[^\"'<>\s]+/download",
    re.I,
)

# Regex matching XenForo attachment URLs.
_XF_ATTACHMENT_RE = re.compile(
    r"/attachments/[^\"'<>\s]+",
    re.I,
)


def extract_download_links(
    html: str,
    page_url: str,
    base: str,
) -> set[str]:
    """Extract download-worthy URLs from HTML content.

    This includes:

    * XenForo XFRM ``/resources/{slug}/download`` endpoints (even when
      they 303-redirect for guests — VIP users can follow them).
    * XenForo attachment URLs (``/attachments/{name}.{id}/``).
    * URLs pointing to known file-hosting services (Google Drive, Mega,
      Dropbox, Mediafire, OneDrive, etc.) found in ``href``, ``data-url``,
      ``data-href``, and bbCode unfurl blocks.
    * Direct links to common downloadable file extensions (``.zip``,
      ``.rar``, ``.7z``, ``.exe``, ``.bin``, ``.pac``, ``.scatter``,
      ``.img``, ``.tar.gz``, etc.).

    Returns a set of absolute, normalised URLs.
    """
    from web_crawler.config import is_file_hosting_url

    found: set[str] = set()

    def _add(raw: str) -> None:
        url = normalise_url(raw.strip(), page_url, base,
                            allow_external=True)
        if url:
            found.add(url)

    # --- 1. Raw regex scan (catches URLs in JS, inline text, etc.) ---
    # XFRM download endpoints
    for m in _XFRM_DOWNLOAD_RE.finditer(html):
        _add(m.group())

    # XenForo attachments
    for m in _XF_ATTACHMENT_RE.finditer(html):
        _add(m.group())

    # --- 2. BeautifulSoup structured scan ---
    if BeautifulSoup is None:
        return found

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return found

    # Collect candidate URLs from link-bearing attributes.
    _LINK_ATTRS = ("href", "src", "data-src", "data-url", "data-href",
                   "data-xf-href")

    for tag in soup.find_all(True):
        for attr in _LINK_ATTRS:
            val = tag.get(attr)
            if not val or not isinstance(val, str):
                continue
            # Skip template placeholders like {url}
            if "{" in val:
                continue
            abs_url = normalise_url(val.strip(), page_url, base,
                                    allow_external=True)
            if not abs_url:
                continue

            # File-hosting domain?
            if is_file_hosting_url(abs_url):
                found.add(abs_url)
                continue

            # XFRM download?
            if _XFRM_DOWNLOAD_RE.search(abs_url):
                found.add(abs_url)
                continue

            # XF attachment?
            if _XF_ATTACHMENT_RE.search(abs_url):
                found.add(abs_url)
                continue

            # Downloadable file extension?
            if _has_download_extension(abs_url):
                found.add(abs_url)

    # --- 3. bbCode unfurl blocks: <… class="bbCodeBlock--unfurl" data-url="…"> ---
    for el in soup.find_all(
        attrs={"class": re.compile(r"bbCodeBlock--unfurl")},
    ):
        data_url = el.get("data-url", "")
        if data_url:
            _add(data_url)

    return found


# Common downloadable file extensions.
_DOWNLOAD_EXTENSIONS = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".apk", ".aab",
    ".bin", ".img", ".iso",
    ".pac", ".scatter", ".ops", ".pit", ".kdz", ".tot", ".ozip",
    ".dat", ".md5", ".ta",
    ".rom", ".fw", ".efs", ".nvram", ".persist", ".dump",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
})


def _has_download_extension(url: str) -> bool:
    """Return ``True`` if *url* ends with a known downloadable extension."""
    from urllib.parse import urlparse
    path = urlparse(url).path.lower().rstrip("/")
    for ext in _DOWNLOAD_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


# ------------------------------------------------------------------
# Page & video metadata extraction
# ------------------------------------------------------------------

# Metadata keys written to video_urls.txt (pipe-separated).
_VIDEO_META_KEYS = (
    "title", "author",
    "thumbnail", "duration", "upload_date",
)


def extract_page_metadata(html: str) -> dict[str, str]:
    """Extract page-level metadata from HTML.

    Returns a dict with keys matching :data:`_VIDEO_META_KEYS`.
    Missing values are represented as empty strings.
    """
    meta: dict[str, str] = {k: "" for k in _VIDEO_META_KEYS}
    if BeautifulSoup is None:
        return meta

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return meta

    # Title: prefer og:title, then <title>
    og_title = soup.find("meta", attrs={"property": "og:title"})
    if og_title and og_title.get("content"):
        meta["title"] = og_title["content"].strip()
    elif soup.title and soup.title.string:
        meta["title"] = soup.title.string.strip()

    # Author: prefer meta author, then og:site_name
    author_el = soup.find("meta", attrs={"name": "author"})
    if author_el and author_el.get("content"):
        meta["author"] = author_el["content"].strip()
    else:
        site_name = soup.find("meta", attrs={"property": "og:site_name"})
        if site_name and site_name.get("content"):
            meta["author"] = site_name["content"].strip()

    # Thumbnail: og:image
    og_image = soup.find("meta", attrs={"property": "og:image"})
    if og_image and og_image.get("content"):
        meta["thumbnail"] = og_image["content"].strip()

    return meta


def extract_jsonld_video_meta(html: str) -> dict[str, dict[str, str]]:
    """Extract per-video metadata from JSON-LD ``VideoObject`` entries.

    Returns a dict mapping video content URLs to metadata dicts with
    keys matching :data:`_VIDEO_META_KEYS`.
    """
    result: dict[str, dict[str, str]] = {}
    if BeautifulSoup is None:
        return result

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return result

    for ld_el in soup.find_all("script", type="application/ld+json"):
        try:
            ld_data = json.loads(ld_el.get_text())
        except (json.JSONDecodeError, TypeError):
            continue
        _collect_video_objects(ld_data, result)

    return result


def _collect_video_objects(
    obj: object,
    out: dict[str, dict[str, str]],
) -> None:
    """Recursively collect metadata from VideoObject nodes."""
    if isinstance(obj, dict):
        obj_type = obj.get("@type", "")
        if isinstance(obj_type, list):
            obj_type = " ".join(obj_type)
        if "VideoObject" in obj_type:
            url = obj.get("contentUrl") or obj.get("embedUrl") or ""
            if url:
                title = obj.get("name", "")
                author_obj = obj.get("author") or obj.get("creator") or ""
                if isinstance(author_obj, dict):
                    author = author_obj.get("name", "")
                elif isinstance(author_obj, str):
                    author = author_obj
                else:
                    author = ""
                # Thumbnail: may be a string or a list of strings
                thumb = obj.get("thumbnailUrl", "")
                if isinstance(thumb, list):
                    thumb = thumb[0] if thumb else ""
                duration = obj.get("duration", "")
                upload_date = obj.get("uploadDate", "")
                out[url] = {
                    "title": str(title).strip(),
                    "author": str(author).strip(),
                    "thumbnail": str(thumb).strip(),
                    "duration": str(duration).strip(),
                    "upload_date": str(upload_date).strip(),
                }
        # Recurse into all values
        for v in obj.values():
            _collect_video_objects(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_video_objects(item, out)


# ------------------------------------------------------------------
# Schema.org microdata extraction (itemprop-based VideoObject)
# ------------------------------------------------------------------

# Mapping from itemprop names (lowercased) to metadata dict keys.
_ITEMPROP_TO_META = {
    "name": "title",
    "author": "author",
    "duration": "duration",
    "thumbnailurl": "thumbnail",
    "uploaddate": "upload_date",
}


def extract_microdata_video_meta(html: str) -> dict[str, dict[str, str]]:
    """Extract per-video metadata from Schema.org microdata.

    Looks for elements with ``itemtype`` containing ``VideoObject``
    (typically ``<article>`` or ``<div>`` with ``itemscope``) and
    reads ``<meta itemprop="…" content="…">`` tags inside them.

    Returns a dict mapping video content URLs to metadata dicts with
    keys matching :data:`_VIDEO_META_KEYS`.
    """
    result: dict[str, dict[str, str]] = {}
    if BeautifulSoup is None:
        return result

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return result

    for container in soup.find_all(
        attrs={"itemtype": re.compile(r"schema\.org/VideoObject", re.I)},
    ):
        meta: dict[str, str] = {k: "" for k in _VIDEO_META_KEYS}
        content_url = ""

        for el in container.find_all("meta", attrs={"itemprop": True}):
            prop = (el.get("itemprop") or "").lower()
            val = (el.get("content") or "").strip()
            if not val:
                continue
            if prop == "contenturl":
                content_url = val
            elif prop == "embedurl" and not content_url:
                content_url = val
            key = _ITEMPROP_TO_META.get(prop)
            if key:
                meta[key] = val

        if content_url:
            result[content_url] = meta

    return result
