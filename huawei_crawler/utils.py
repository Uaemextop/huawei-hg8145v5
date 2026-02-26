"""
huawei_crawler.utils
=====================
URL normalisation and file-path utilities shared across the package.
"""

import hashlib
import re
import urllib.parse
from pathlib import Path


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def base_url(host: str) -> str:
    """Return ``http://<host>``."""
    return f"http://{host}"


def normalise_url(raw: str, page_url: str, base: str) -> "str | None":
    """
    Convert *raw* to an absolute URL on the same router host.

    * Strips cache-buster query strings (pure numeric / hex tokens like
      ``?202406291158020553184798``) but keeps meaningful query strings so
      that CGI endpoints with required parameters are not broken.
    * Returns ``None`` for external, data:, javascript:, or mailto: URLs.
    * Returns ``None`` for paths ending in a comma (JS regex false-positive:
      ``replace(/\\'/g, ...)`` → path ``'/g, '``).
    """
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    parsed = urllib.parse.urlparse(raw)

    # Resolve relative URLs against the page they were found on
    if not parsed.scheme:
        raw = urllib.parse.urljoin(page_url, raw)
        parsed = urllib.parse.urlparse(raw)

    # Reject external hosts
    host = urllib.parse.urlparse(base).netloc
    if parsed.netloc and parsed.netloc != host:
        return None

    # Strip pure cache-buster query strings (all digits/hex, ≥ 10 chars)
    qs = parsed.query
    if qs and re.fullmatch(r"[0-9a-f]{10,}", qs, re.IGNORECASE):
        qs = ""

    # Reject paths that end with a comma (JS regex literal false-positive).
    if parsed.path.endswith((",", ";")):
        return None

    canonical = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, "", qs, "")
    )
    return canonical


def url_key(url: str) -> str:
    """
    Deduplication key: path only (no query, no fragment).
    Two URLs differing only in cache-buster params are treated as the same
    resource for the purpose of 'have we visited this?'.
    """
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


# ---------------------------------------------------------------------------
# File-path helpers
# ---------------------------------------------------------------------------

def url_to_local_path(url: str, output_dir: Path) -> Path:
    """
    Map an absolute URL to a local file-system path inside *output_dir*,
    mirroring the server's directory structure.

    ``/index.asp``          → ``<output>/index.asp``
    ``/Cuscss/login.css``   → ``<output>/Cuscss/login.css``
    ``/``                   → ``<output>/index.html``
    ``/html/ssmp/``         → ``<output>/html/ssmp/index.html``
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path += "index.html"

    return output_dir / Path(path)


def smart_local_path(
    url: str,
    output_dir: Path,
    content_type: str,
    content_disposition: str = "",
) -> Path:
    """
    Determine the local save path for a response.

    Priority:
      1. ``filename=`` from Content-Disposition header
      2. Filename from URL path
      3. If URL path has no extension but Content-Type suggests one, append it
      4. Extensionless URLs become ``<name>.html`` when CT is ``text/html``
    """
    if content_disposition:
        m = re.search(r'filename\s*=\s*["\']?([^\s"\']+)', content_disposition, re.I)
        if m:
            fname = m.group(1).strip()
            parsed = urllib.parse.urlparse(url)
            dir_part = Path(parsed.path.lstrip("/")).parent
            return output_dir / dir_part / fname

    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path += "index.html"
    else:
        stem = Path(path)
        if not stem.suffix:
            ct = content_type.split(";")[0].strip().lower()
            ext_map = {
                "text/html":                "html",
                "application/xhtml+xml":    "html",
                "text/css":                 "css",
                "application/javascript":   "js",
                "text/javascript":          "js",
                "application/json":         "json",
                "text/xml":                 "xml",
                "application/xml":          "xml",
                "image/png":                "png",
                "image/jpeg":               "jpg",
                "image/gif":                "gif",
                "image/svg+xml":            "svg",
                "image/x-icon":             "ico",
                "image/vnd.microsoft.icon": "ico",
            }
            if ct in ext_map:
                path += "." + ext_map[ct]

    return output_dir / Path(path)


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def save_file(local_path: Path, content: bytes) -> None:
    """Write *content* to *local_path*, creating all parent directories."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)


def content_hash(data: bytes) -> str:
    """Return a short SHA-256 hex digest for deduplication."""
    return hashlib.sha256(data).hexdigest()[:16]
