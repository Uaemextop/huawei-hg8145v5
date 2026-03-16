"""
crawl4ai.extensions.extraction – Link / URL extraction helpers.

Ported from the ``web_crawler.extraction`` package (originally split across
``base.py``, ``html.py``, ``css.py``, ``javascript.py``, ``json_extract.py``,
and ``google_drive.py``).  All classes, functions, and the ``extract_all``
registry are merged into this single self-contained module.

The ``normalise_url`` helper (originally in ``web_crawler.utils.url``) is
inlined here so that this module has **no** imports from ``web_crawler``.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import warnings
from abc import ABC, abstractmethod

# ===================================================================
# normalise_url – inlined from web_crawler.utils.url
# ===================================================================


def normalise_url(
    raw: str,
    page_url: str,
    base: str,
    *,
    allow_external: bool = False,
) -> str | None:
    """Convert *raw* to an absolute URL on the same host.

    Strips cache-buster query strings (pure numeric / hex tokens) but keeps
    meaningful query strings so dynamic endpoints are not broken.

    Enforces the same scheme as *base* (e.g. upgrades ``http://`` to
    ``https://`` when the base URL uses HTTPS) so that session cookies and
    TLS settings are applied consistently to every request.

    Returns ``None`` for external, ``data:``, ``javascript:``, ``mailto:``
    URLs.  When *allow_external* is ``True``, external URLs are kept as-is
    (scheme is NOT enforced for external hosts).
    """
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    # Fix JSON-escaped forward slashes (e.g. \/wp-json\/… from WP REST API)
    if "\\/" in raw:
        raw = raw.replace("\\/", "/")

    parsed = urllib.parse.urlparse(raw)

    if not parsed.scheme:
        raw = urllib.parse.urljoin(page_url, raw)
        parsed = urllib.parse.urlparse(raw)

    base_parsed = urllib.parse.urlparse(base)
    host = base_parsed.netloc
    is_external = parsed.netloc and parsed.netloc != host
    if is_external and not allow_external:
        return None

    qs = parsed.query
    if qs and re.fullmatch(r"[0-9a-f]{10,}", qs, re.IGNORECASE):
        qs = ""

    if parsed.path.endswith((",", ";")):
        return None

    if is_external:
        scheme = parsed.scheme
    else:
        scheme = base_parsed.scheme if base_parsed.scheme else parsed.scheme

    canonical = urllib.parse.urlunparse(
        (scheme, parsed.netloc, parsed.path, "", qs, "")
    )
    return canonical


# ===================================================================
# BaseExtractor
# ===================================================================


class BaseExtractor(ABC):
    """Base class for all link extractors."""

    name: str = ""

    @abstractmethod
    def extract(self, content: str, url: str, base: str) -> set[str]:
        ...

    @abstractmethod
    def can_handle(self, content_type: str, url: str) -> bool:
        ...


# ===================================================================
# CSS extraction
# ===================================================================

_CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^)'">\s]+)['"]?\s*\)""", re.I)
_CSS_IMPORT_RE = re.compile(r"""@import\s+['"]([^'"]+)['"]""", re.I)


def extract_css_urls(css: str, page_url: str, base: str) -> set[str]:
    """Extract all URLs from CSS ``url()`` and ``@import`` statements."""
    found: set[str] = set()
    for pat in (_CSS_URL_RE, _CSS_IMPORT_RE):
        for m in pat.finditer(css):
            n = normalise_url(m.group(1), page_url, base)
            if n:
                found.add(n)
    return found


# ===================================================================
# JavaScript extraction
# ===================================================================

# window.location = "..." or window.location.href = "..."
_WIN_LOC_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href|location\.replace)\s*[=(]\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# window.open('url', ...) – popup / new-tab navigations
_WIN_OPEN_RE = re.compile(
    r"""window\.open\s*\(\s*['"`](https?://[^'"`\n]+|/[^'"`\n]+|[a-zA-Z0-9_\-./]+\.[a-zA-Z]{2,5}[^'"`\n]*)['"`]""",
    re.I,
)

# Form action patterns
_FORM_ACTION_RE = re.compile(
    r"""\.(?:setAction|setAttribute\s*\(\s*['"]action['"])\s*[,(]\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# $.ajax({ url: '/path', ... }) / fetch('/path') / axios.get('/path')
_AJAX_URL_RE = re.compile(
    r"""(?:['"]url['"]\s*:|url\s*:|fetch\s*\(|axios\.(?:get|post)\s*\()\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# fetch('endpoint?param=' + var) / $.get('url?id=' + val)
_AJAX_CONCAT_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post)|(?:\$\.(?:get|post|ajax)))\s*\(\s*['"`]([^'"`\n]+)['"`]\s*\+""",
    re.I,
)

# document.write('<tag src="/path/to/file.js">')
_DOC_WRITE_RE = re.compile(
    r"""document\.write\s*\(\s*['"`](.+?)['"`]""",
    re.I | re.DOTALL,
)

# Absolute URLs pointing to HLS/DASH streams or video files in JS strings.
_STREAM_URL_RE = re.compile(
    r"""['"`](https?://[^'"`\s\n]{5,300}\.(?:m3u8|mpd|mp4|webm|mkv|mov|avi|flv|wmv|m4v|ts|mp3|ogg|wav|flac|aac|m4a|weba)(?:\?[^'"`\s\n]*)?)['"`]""",
    re.I,
)

# All root-relative quoted path strings: '/anything/here'
_ABS_QUOTED_PATH_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Relative paths with a known web extension
_REL_EXT_PATH_RE = re.compile(
    r"""['"`]([.]{0,2}/[a-zA-Z0-9_\-./]+\.(?:"""
    r"html|htm|php|asp|aspx|cgi|jsp|do|action|"
    r"js|mjs|cjs|ts|jsx|tsx|vue|svelte|"
    r"css|scss|sass|less|styl|"
    r"png|jpg|jpeg|gif|ico|svg|bmp|webp|avif|tiff|"
    r"json|xml|yml|yaml|toml|ini|cfg|conf|config|hst|"
    r"woff2?|ttf|eot|otf|"
    r"pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods|"
    r"zip|tar|gz|tgz|bz2|rar|7z|"
    r"bin|exe|cmd|"
    r"mp3|mp4|ogg|wav|webm|avi|mov|flv|mkv|wmv|m4v|m4a|"
    r"3gp|3g2|mpeg|mpg|f4v|asf|vob|m2ts|mts|ts|"
    r"m3u8|mpd|flac|aac|weba|"
    r"env|log|sql|md|rst|txt|csv|tsv|"
    r"swf|swp|bak|old|orig|save|tmp|"
    r"py|rb|pl|sh|bat|ps1|lua|go|rs|java|c|cpp|h|"
    r"htaccess|htpasswd|gitignore|dockerignore|editorconfig"
    r"""))['"`]""",
    re.I,
)

# Hidden/dot-files referenced in source: ".env", ".htaccess", etc.
_HIDDEN_FILE_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_\-./]*\.(?:"""
    r"htaccess|htpasswd|htgroups|htdigest|"
    r"env(?:\.\w+)?|"
    r"config|cfg|conf|hst|ini|toml|"
    r"gitignore|gitattributes|gitmodules|"
    r"dockerignore|editorconfig|"
    r"babelrc(?:\.json)?|eslintrc(?:\.(?:json|js|yml))?|"
    r"prettierrc(?:\.json)?|stylelintrc(?:\.json)?|"
    r"npmrc|npmignore|yarnrc(?:\.yml)?|nvmrc|"
    r"flake8|pylintrc|rubocop\.yml|coveragerc|"
    r"python-version|ruby-version|java-version|node-version|tool-versions|"
    r"browserslistrc|postcssrc|graphqlrc(?:\.yml)?|"
    r"travis\.yml|circleci|gitlab-ci\.yml|"
    r"DS_Store|vimrc|viminfo|"
    r"bash_history|bashrc|bash_profile|profile|zshrc|zsh_history|sh_history|"
    r"swp|swo|p12|pfx|pem|key|crt|cer"
    r"""))['"`]""",
    re.I,
)

# var/let/const  varName = '/path'
_VAR_ASSIGN_RE = re.compile(
    r"""(?:var|let|const)\s+\w+\s*=\s*['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# JS object / array literal paths
_OBJ_PROP_PATH_RE = re.compile(
    r"""[\[,{]\s*['"`](/[a-zA-Z0-9_./%?&=+\-][^'"`\n]{0,150})['"`]\s*[,\]}]""",
    re.I,
)

# Webpack/Babel transpiler helper module names – internal chunk references.
_WEBPACK_HELPER_RE = re.compile(
    r"^[a-zA-Z]{16,}\.(js|mjs|cjs|css)$",
)


def _is_garbage_path(raw: str) -> bool:
    """Return True if *raw* looks like a webpack/Babel internal module
    reference rather than a real server path.
    """
    segment = raw.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
    if _WEBPACK_HELPER_RE.match(segment):
        return True
    if " " in raw:
        return True
    return False


def extract_js_paths(js: str, page_url: str, base: str) -> set[str]:
    """Exhaustively extract every URL/path reference from JavaScript source."""
    found: set[str] = set()

    def _add(raw: str) -> None:
        if "${" in raw or "'" in raw or '"' in raw:
            return
        if _is_garbage_path(raw):
            return
        n = normalise_url(raw.strip(), page_url, base)
        if n:
            found.add(n)

    for pat in (
        _WIN_LOC_RE,
        _FORM_ACTION_RE,
        _AJAX_URL_RE,
        _AJAX_CONCAT_RE,
        _ABS_QUOTED_PATH_RE,
        _REL_EXT_PATH_RE,
        _HIDDEN_FILE_RE,
        _OBJ_PROP_PATH_RE,
        _VAR_ASSIGN_RE,
    ):
        for m in pat.finditer(js):
            _add(m.group(1))

    # window.open() often targets external URLs (popups, share links)
    for m in _WIN_OPEN_RE.finditer(js):
        raw = m.group(1)
        if "${" not in raw and not _is_garbage_path(raw):
            n = normalise_url(raw.strip(), page_url, base,
                              allow_external=True)
            if n:
                found.add(n)

    for m in _DOC_WRITE_RE.finditer(js):
        snippet = m.group(1).replace("\\'", "'").replace('\\"', '"')
        found |= extract_html_attrs(snippet, page_url, base)

    # Extract absolute stream/media URLs (often on external CDN hosts)
    for m in _STREAM_URL_RE.finditer(js):
        raw = m.group(1)
        if "${" not in raw:
            n = normalise_url(raw.strip(), page_url, base,
                              allow_external=True)
            if n:
                found.add(n)

    return found


# ===================================================================
# JSON extraction
# ===================================================================

# WP REST API "self-referential" URL patterns that create queue loops.
_WP_REST_LOOP_RE = re.compile(
    r"/wp-json/wp/v2/[^/]+/\d+/revisions"
    r"|/wp-json/wp/v2/[^/]+\?[^\"]*\bparent=\d+"
    r"|/wp-json/wc/store/v1/cart/"
    r"|/wp-json/wc/store/v1/batch\b"
    r"|/wp-json/wc/store/v1/checkout\b"
    r"|/wp-json/wc-telemetry/"
    r"|/wp-json/wccom-site/"
    r"|/wp-json/wp/v2/(?:posts|pages|categories|tags"
    r"|users|media|comments)\?",
    re.IGNORECASE,
)


def extract_json_paths(text: str, page_url: str, base: str) -> set[str]:
    """Parse JSON responses and extract string values that look like URL
    paths or absolute URLs on the same host.

    Filters out self-referential WP REST API links (revisions, pagination,
    cart actions) that would cause unbounded queue growth.
    """
    found: set[str] = set()
    try:
        obj = json.loads(text)
        queue = [obj]
        while queue:
            item = queue.pop()
            if isinstance(item, dict):
                queue.extend(item.values())
            elif isinstance(item, list):
                queue.extend(item)
            elif isinstance(item, str):
                if item.startswith("/") or item.startswith(("http://", "https://")):
                    if _WP_REST_LOOP_RE.search(item):
                        continue
                    n = normalise_url(item, page_url, base)
                    if n:
                        found.add(n)
    except (json.JSONDecodeError, ValueError):
        pass
    return found


# ===================================================================
# Google Drive / cloud-storage link extraction
# ===================================================================

_CLOUD_PATTERNS = [
    re.compile(r'https?://drive\.google\.com/(?:file/d/|open\?id=|uc\?[^"\'>\s]*id=|drive/folders/)[a-zA-Z0-9_-]+[^"\'>\s]*', re.I),
    re.compile(r'https?://docs\.google\.com/(?:document|spreadsheets|presentation|forms)/d/[a-zA-Z0-9_-]+[^"\'>\s]*', re.I),
    re.compile(r'https?://mega\.(?:nz|co\.nz)/(?:file|folder)/[^"\'>\s]+', re.I),
    re.compile(r'https?://(?:www\.)?mediafire\.com/(?:file|download)/[a-zA-Z0-9]+[^"\'>\s]*', re.I),
    re.compile(r'https?://1drv\.ms/[a-zA-Z]/[^"\'>\s]+', re.I),
    re.compile(r'https?://(?:www\.)?dropbox\.com/s[a-z]?/[^"\'>\s]+', re.I),
]


class GoogleDriveExtractor(BaseExtractor):
    """Extract Google Drive and other cloud storage links."""

    name = "google_drive"

    def can_handle(self, content_type: str, url: str) -> bool:
        ct = content_type.split(";")[0].strip().lower()
        return ct in (
            "text/html", "application/xhtml+xml",
            "application/javascript", "text/javascript",
        )

    def extract(self, content: str, url: str, base: str) -> set[str]:
        return extract_cloud_links(content)


def extract_cloud_links(content: str) -> set[str]:
    """Extract all cloud storage links from content."""
    found: set[str] = set()
    for pat in _CLOUD_PATTERNS:
        for m in pat.finditer(content):
            found.add(m.group(0))
    return found


# ===================================================================
# HTML attribute extraction (BeautifulSoup)
# ===================================================================

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
    """Extract every resource URL from HTML/ASP content using BeautifulSoup.

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
                # Schema.org itemprop with URL values
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
                # Open Graph / Twitter Card media meta tags
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

    # Inline event-handler attributes (onclick, onmouseover, onsubmit, …)
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
                found |= extract_js_paths(handler, page_url, base)

    # JSON-LD structured data – extract media URLs from VideoObject etc.
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


# -------------------------------------------------------------------
# Page & video metadata extraction
# -------------------------------------------------------------------

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
        for v in obj.values():
            _collect_video_objects(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_video_objects(item, out)


# -------------------------------------------------------------------
# Schema.org microdata extraction (itemprop-based VideoObject)
# -------------------------------------------------------------------

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
    and reads ``<meta itemprop="…" content="…">`` tags inside them.

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


# ===================================================================
# extract_all – registry that dispatches to all extractors
# ===================================================================


def extract_all(
    content: str | bytes,
    content_type: str,
    url: str,
    base: str,
) -> set[str]:
    """Extract all links using all available extractors.

    Also extracts cloud storage links (Google Drive, Mega, etc.).
    """
    found: set[str] = set()
    ct = content_type.split(";")[0].strip().lower()

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    parsed_url = urllib.parse.urlparse(url)
    path_lower = parsed_url.path.lower()
    is_html_ext = path_lower.endswith((".asp", ".php", ".html", ".htm"))

    if ct in ("text/html", "application/xhtml+xml",
              "application/x-httpd-php", "text/x-php",
              "application/php") or is_html_ext:
        found |= extract_html_attrs(content, url, base)
        found |= extract_js_paths(content, url, base)
        found |= extract_cloud_links(content)
    elif ct in ("application/javascript", "text/javascript"):
        found |= extract_js_paths(content, url, base)
        found |= extract_cloud_links(content)
    elif ct in ("text/css",):
        found |= extract_css_urls(content, url, base)
    elif ct in ("application/json", "text/json"):
        found |= extract_json_paths(content, url, base)
        found |= extract_js_paths(content, url, base)
    elif ct in ("text/plain", "text/xml", "application/xml",
                "application/rss+xml", "application/atom+xml"):
        found |= extract_js_paths(content, url, base)

    return found


def extract_links(
    content: str | bytes,
    content_type: str,
    url: str,
    base: str,
) -> set[str]:
    """Backward-compatible alias for :func:`extract_all`."""
    return extract_all(content, content_type, url, base)


__all__ = [
    "normalise_url",
    "BaseExtractor",
    "extract_all",
    "extract_links",
    "extract_html_attrs",
    "extract_css_urls",
    "extract_js_paths",
    "extract_json_paths",
    "extract_cloud_links",
    "extract_page_metadata",
    "extract_jsonld_video_meta",
    "extract_microdata_video_meta",
    "GoogleDriveExtractor",
]
