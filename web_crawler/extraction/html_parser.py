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


# ------------------------------------------------------------------
# Page & video metadata extraction
# ------------------------------------------------------------------

# Metadata keys written to video_urls.txt (pipe-separated).
_VIDEO_META_KEYS = (
    "title", "author", "description",
    "thumbnail", "duration", "upload_date", "genre",
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

    # Description: prefer og:description, then meta description
    og_desc = soup.find("meta", attrs={"property": "og:description"})
    if og_desc and og_desc.get("content"):
        meta["description"] = og_desc["content"].strip()
    else:
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            meta["description"] = meta_desc["content"].strip()

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

    # Genre: article:tag or keywords meta
    tag_el = soup.find("meta", attrs={"property": "article:tag"})
    if tag_el and tag_el.get("content"):
        meta["genre"] = tag_el["content"].strip()
    else:
        kw_el = soup.find("meta", attrs={"name": "keywords"})
        if kw_el and kw_el.get("content"):
            meta["genre"] = kw_el["content"].strip()

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
                desc = obj.get("description", "")
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
                genre = obj.get("genre", "")
                out[url] = {
                    "title": str(title).strip(),
                    "author": str(author).strip(),
                    "description": str(desc).strip(),
                    "thumbnail": str(thumb).strip(),
                    "duration": str(duration).strip(),
                    "upload_date": str(upload_date).strip(),
                    "genre": str(genre).strip(),
                }
        # Recurse into all values
        for v in obj.values():
            _collect_video_objects(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_video_objects(item, out)
