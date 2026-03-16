"""
HTML/ASP attribute extraction via BeautifulSoup.
"""

import json
import re
import urllib.parse
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


def extract_html_attrs(html: str, page_url: str, base: str) -> set[str]:
    """
    Extract every resource URL from HTML/ASP content using BeautifulSoup.
    Also parses inline ``<style>`` and ``<script>`` blocks.

    Handles ``<base href="…">`` per HTML spec §4.2.3: relative URLs
    are resolved against the base href instead of the page URL.
    """
    found: set[str] = set()

    if BeautifulSoup is None:
        return found

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return found

    # Honour <base href="…"> — resolve relative URLs against it
    resolve_base = page_url
    base_tag = soup.find("base", href=True)
    if base_tag:
        href = base_tag["href"]
        resolve_base = urllib.parse.urljoin(page_url, href)

    def _add(raw: str, *, allow_external: bool = False) -> None:
        n = normalise_url(raw.strip(), resolve_base, base,
                          allow_external=allow_external)
        if n:
            found.add(n)

    # Tags whose media attributes may reference external CDNs
    _MEDIA_TAGS = {"video", "source", "audio", "track"}

    attr_map = {
        "a":       ["href"],
        "link":    ["href"],
        "script":  ["src"],
        "img":     ["src", "data-src", "data-lazy-src"],
        "source":  ["src", "srcset", "data-src", "data-video-src"],
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
    }
    for tag, attrs in attr_map.items():
        is_media = tag in _MEDIA_TAGS
        for el in soup.find_all(tag):
            for attr in attrs:
                val = el.get(attr)
                if val:
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

    for style_el in soup.find_all("style"):
        found |= extract_css_urls(style_el.get_text(), resolve_base, base)

    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            found |= extract_js_paths(script_el.get_text(), resolve_base, base)

    # Extract FTP/SFTP/FTPS links from anchor tags and other elements
    _FTP_RE = re.compile(r'((?:ftp|ftps|sftp)://[^\s"\'<>]+)', re.I)
    for m in _FTP_RE.finditer(html):
        found.add(m.group(1).rstrip('.,;)'))

    # Extract links with download attribute (explicit download links)
    for a_el in soup.find_all("a", download=True):
        href = a_el.get("href")
        if href:
            _add(href, allow_external=True)

    # Inline event-handler attributes (onclick, onmouseover, onsubmit, …)
    # contain JavaScript snippets that may navigate via window.location,
    # window.open(), or fetch().  Run JS extraction on every handler value.
    _EVENT_ATTRS = frozenset({
        "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
        "onchange", "onsubmit", "onfocus", "onblur", "onload", "onerror",
    })
    for el in soup.find_all(attrs=lambda attrs: attrs and any(
        a in _EVENT_ATTRS for a in attrs
    )):
        for attr_name in _EVENT_ATTRS:
            handler = el.get(attr_name)
            if handler:
                found |= extract_js_paths(handler, resolve_base, base)

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
