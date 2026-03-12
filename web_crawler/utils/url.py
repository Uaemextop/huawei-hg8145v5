"""
URL normalisation and path-mapping helpers.
"""

import re
import urllib.parse
from pathlib import Path


def normalise_url(raw: str, page_url: str, base: str,
                  *, allow_external: bool = False) -> str | None:
    """
    Convert *raw* to an absolute URL on the same host.

    Strips cache-buster query strings (pure numeric / hex tokens) but keeps
    meaningful query strings so dynamic endpoints are not broken.

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


def url_key(url: str) -> str:
    """Deduplication key: scheme + host + path + sorted query string.

    Query parameters are preserved so that dynamic pages routed via query
    strings (e.g. ``index.php?a=downloads&b=file&id=123``) are treated as
    distinct pages.  Parameters are sorted for consistent deduplication
    regardless of the order they appear in different links.
    """
    p = urllib.parse.urlparse(url)
    # Sort query params for stable deduplication
    if p.query:
        sorted_qs = urllib.parse.urlencode(
            sorted(urllib.parse.parse_qsl(p.query, keep_blank_values=True))
        )
    else:
        sorted_qs = ""
    return urllib.parse.urlunparse(
        (p.scheme, p.netloc, p.path, "", sorted_qs, "")
    )


def url_to_local_path(url: str, output_dir: Path) -> Path:
    """
    Map an absolute URL to a local file-system path inside *output_dir*,
    mirroring the server's directory structure.

    Query parameters are encoded into the filename so that dynamic pages
    routed via query strings (e.g. ``index.php?a=downloads&b=file&id=123``)
    produce distinct files on disk.
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path += "index.html"

    # Encode query parameters into the filename to avoid overwriting
    if parsed.query:
        safe_qs = _query_to_filename_suffix(parsed.query)
        stem = Path(path)
        if stem.suffix:
            path = str(stem.with_suffix("")) + "_" + safe_qs + stem.suffix
        else:
            path = path + "_" + safe_qs

    return output_dir / Path(path)


def _query_to_filename_suffix(query: str) -> str:
    """Convert a query string into a safe filename suffix.

    Sorts parameters for consistency and replaces filesystem-unsafe
    characters with underscores.  Truncates to avoid overly long names.
    """
    pairs = sorted(urllib.parse.parse_qsl(query, keep_blank_values=True))
    parts = [f"{k}={v}" for k, v in pairs]
    raw = "&".join(parts)
    # Replace characters that are unsafe in filenames
    safe = re.sub(r'[<>:"/\\|?*&=%]', '_', raw)
    # Collapse multiple underscores
    safe = re.sub(r'_+', '_', safe).strip("_")
    # Truncate to 120 chars to stay within filesystem limits
    if len(safe) > 120:
        safe = safe[:120]
    return safe
