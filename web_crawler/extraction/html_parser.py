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


def _parse_srcset(srcset_value: str) -> list[str]:
    """Parse an ``srcset`` or ``imagesrcset`` attribute value and return
    the individual image URLs.

    The ``srcset`` format is a comma-separated list of entries where each
    entry is ``<url> [<descriptor>]``.  Descriptors are optional width
    (e.g. ``320w``) or pixel-density (e.g. ``2x``) tokens.  URLs may
    contain commas inside percent-encoded sequences (``%2C``) so we
    split carefully on commas that are followed by whitespace + a URL.
    """
    urls: list[str] = []
    if not srcset_value or not srcset_value.strip():
        return urls
    # Skip data: URIs entirely – they may contain internal commas that
    # would produce garbage entries when split.
    if srcset_value.strip().startswith(("data:", "javascript:", "mailto:")):
        return urls
    # Split on commas that separate srcset entries.  Each entry is
    # ``<url> [<descriptor>]`` where descriptor is ``\d+w`` or ``\d+(\.\d+)?x``.
    for entry in srcset_value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        # The URL is everything up to the first whitespace; the rest
        # is the optional width/density descriptor.
        parts = entry.split(None, 1)
        if parts:
            url = parts[0].strip()
            if url and not url.startswith(("data:", "javascript:", "mailto:")):
                # Must look like a URL: starts with http(s), //, or /
                if url.startswith(("http://", "https://", "//", "/")):
                    urls.append(url)
    return urls


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

    def _add_srcset(val: str, *, allow_external: bool = False) -> None:
        """Parse a ``srcset`` / ``imagesrcset`` value and add each URL."""
        for url in _parse_srcset(val):
            _add(url, allow_external=allow_external)

    try:
        soup = BeautifulSoup(html, _BS4_PARSER)
    except Exception:
        return found

    # Tags whose media attributes may reference external CDNs.
    # <img> is included because CDN-hosted images (e.g. Cloudflare Image
    # Delivery on cdn.androidacy.com) use external hosts for srcset URLs.
    _MEDIA_TAGS = {"video", "source", "audio", "track", "img"}

    # Attributes that use srcset format (comma-separated URL + descriptor)
    _SRCSET_ATTRS = frozenset({"srcset", "imagesrcset"})

    attr_map = {
        "a":       ["href"],
        "link":    ["href", "imagesrcset"],
        "script":  ["src"],
        "img":     ["src", "data-src", "data-lazy-src", "srcset"],
        "source":  ["src", "data-src", "data-video-src", "srcset"],
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
                    if attr in _SRCSET_ATTRS:
                        _add_srcset(val, allow_external=is_media)
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

    for style_el in soup.find_all("style"):
        found |= extract_css_urls(style_el.get_text(), page_url, base)

    for script_el in soup.find_all("script"):
        if not script_el.get("src"):
            found |= extract_js_paths(script_el.get_text(), page_url, base)
        # Flying Press / lazy-loading: <script data-src="data:text/javascript,...">
        # defers script execution by URL-encoding JS source into a data: URI
        # stored in data-src.  The actual tag text is empty, so the standard
        # path above misses the embedded URLs.  Decode and parse the JS.
        # The decoded JS often contains JSON config objects (``var X = {...}``)
        # with absolute URLs, so we also try JSON extraction on embedded
        # object literals.
        data_src = script_el.get("data-src") or ""
        if data_src.startswith("data:text/javascript,"):
            encoded_js = data_src[len("data:text/javascript,"):]
            decoded_js = urllib.parse.unquote(encoded_js)
            if decoded_js:
                found |= extract_js_paths(decoded_js, page_url, base)
                # Try to extract JSON config objects (``var X = {...};``)
                # that contain absolute URLs as string values.
                from web_crawler.extraction.json_extract import extract_json_paths
                for json_m in re.finditer(r'\{[^{}]{10,}\}', decoded_js):
                    found |= extract_json_paths(json_m.group(0), page_url, base)

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
