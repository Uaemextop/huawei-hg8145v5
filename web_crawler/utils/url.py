"""
URL normalisation and path-mapping helpers.
"""

import re
import urllib.parse
from pathlib import Path


def normalise_url(raw: str, page_url: str, base: str) -> str | None:
    """
    Convert *raw* to an absolute URL on the same router host.

    Strips cache-buster query strings (pure numeric / hex tokens) but keeps
    meaningful query strings so CGI endpoints are not broken.

    Returns ``None`` for external, ``data:``, ``javascript:``, ``mailto:`` URLs.
    """
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    parsed = urllib.parse.urlparse(raw)

    if not parsed.scheme:
        raw = urllib.parse.urljoin(page_url, raw)
        parsed = urllib.parse.urlparse(raw)

    host = urllib.parse.urlparse(base).netloc
    if parsed.netloc and parsed.netloc != host:
        return None

    qs = parsed.query
    if qs and re.fullmatch(r"[0-9a-f]{10,}", qs, re.IGNORECASE):
        qs = ""

    if parsed.path.endswith((",", ";")):
        return None

    canonical = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, "", qs, "")
    )
    return canonical


def url_key(url: str) -> str:
    """Deduplication key: path only (no query, no fragment)."""
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def url_to_local_path(url: str, output_dir: Path) -> Path:
    """
    Map an absolute URL to a local file-system path inside *output_dir*,
    mirroring the server's directory structure.
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lstrip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path += "index.html"

    return output_dir / Path(path)
