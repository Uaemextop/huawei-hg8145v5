"""
URL normalisation and path-mapping helpers.
"""

import hashlib
import html as html_mod
import re
import urllib.parse
from pathlib import Path

# Extensions whose query strings carry semantic meaning (dynamic scripts).
# Pages served through these endpoints depend on query parameters to
# select content (e.g. ``index.php?a=downloads&b=file&id=1826``).
_DYNAMIC_EXTENSIONS = frozenset({
    ".php", ".asp", ".aspx", ".cgi", ".pl", ".jsp",
    ".jspx", ".do", ".action", ".cfm", ".shtml",
})

# Simple version-only query strings used as cache busters.
# Matches patterns like ``?v=1.2.3``, ``?ver=4``, ``?v12``.
_CACHE_BUSTER_RE = re.compile(
    r"^v(?:er)?=?[\d.]+$", re.IGNORECASE,
)


def normalise_url(raw: str, page_url: str, base: str,
                  *, allow_external: bool = False) -> str | None:
    """
    Convert *raw* to an absolute URL on the same host.

    Strips cache-buster query strings (pure numeric / hex tokens and
    ``?v=…`` / ``?ver=…`` patterns) but keeps meaningful query strings
    so dynamic endpoints are not broken.

    Decodes HTML entities (``&amp;`` → ``&``) that may appear in URLs
    extracted from inline JavaScript or non-HTML contexts.

    Enforces the same scheme as *base* (e.g. upgrades ``http://`` to
    ``https://`` when the base URL uses HTTPS) so that session cookies
    and TLS settings are applied consistently to every request.

    Returns ``None`` for external, ``data:``, ``javascript:``, ``mailto:`` URLs.
    When *allow_external* is ``True``, external URLs are kept as-is
    (scheme is NOT enforced for external hosts).
    """
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    # Decode HTML entities (e.g. &amp; → &, &#38; → &) that may leak
    # into URLs extracted from inline JS or non-attribute contexts.
    if "&amp;" in raw or "&#" in raw:
        raw = html_mod.unescape(raw)

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
    # Strip pure numeric/hex cache-buster query strings
    if qs and re.fullmatch(r"[0-9a-f]{10,}", qs, re.IGNORECASE):
        qs = ""
    # Strip simple version-style cache busters (e.g. ?v=1.2.3, ?ver=4)
    if qs and _CACHE_BUSTER_RE.fullmatch(qs):
        qs = ""

    if parsed.path.endswith((",", ";")):
        return None

    # Enforce the base URL's scheme so every request uses the same
    # protocol (e.g. always HTTPS when the site is HTTPS-only).
    # This prevents the SG-CAPTCHA session cookie, which is tied to
    # the HTTPS scheme, from being omitted on plain-HTTP requests.
    # For external URLs, keep their original scheme.
    if is_external:
        scheme = parsed.scheme
    else:
        scheme = base_parsed.scheme if base_parsed.scheme else parsed.scheme

    canonical = urllib.parse.urlunparse(
        (scheme, parsed.netloc, parsed.path, "", qs, "")
    )
    return canonical


def _is_dynamic_path(path: str) -> bool:
    """Return ``True`` if *path* ends with a dynamic-script extension."""
    lower = path.lower()
    return any(lower.endswith(ext) for ext in _DYNAMIC_EXTENSIONS)


def url_key(url: str) -> str:
    """Deduplication key.

    For dynamic script URLs (e.g. ``.php``, ``.asp``) the query string
    is included in the key because different parameters select entirely
    different content.  For all other URLs the query string is stripped
    to avoid cache-buster duplicates.
    """
    p = urllib.parse.urlparse(url)
    if _is_dynamic_path(p.path) and p.query:
        return urllib.parse.urlunparse(
            (p.scheme, p.netloc, p.path, "", p.query, "")
        )
    return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def _query_slug(query: str) -> str:
    """Create a filesystem-safe slug from a query string.

    Returns ``_<short_hash>`` when *query* is non-empty.  The hash is
    an 8-character hex string derived from the full query so that
    different query parameters map to different files without creating
    excessively long filenames.
    """
    if not query:
        return ""
    digest = hashlib.md5(query.encode()).hexdigest()[:8]  # noqa: S324
    return f"_{digest}"


def url_to_local_path(url: str, output_dir: Path) -> Path:
    """
    Map an absolute URL to a local file-system path inside *output_dir*,
    mirroring the server's directory structure.

    For dynamic pages whose query string is meaningful (e.g.
    ``index.php?a=downloads&b=file&id=1826``) a short hash of the query
    is appended to the filename so that different parameter combinations
    produce distinct files on disk.
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path += "index.html"

    # For dynamic scripts, embed a query hash in the filename so
    # different parameter sets don't overwrite each other on disk.
    if _is_dynamic_path(path) and parsed.query:
        p = Path(path)
        slug = _query_slug(parsed.query)
        path = str(p.parent / f"{p.stem}{slug}{p.suffix}")

    return output_dir / Path(path)
