"""
URL normalisation and path-mapping helpers.
"""

import re
import urllib.parse
from pathlib import Path


def normalise_url(raw: str, page_url: str, base: str) -> str | None:
    """
    Convert *raw* to an absolute URL on the same host.

    Strips cache-buster query strings (pure numeric / hex tokens) but keeps
    meaningful query strings so dynamic endpoints are not broken.

    Enforces the same scheme as *base* (e.g. upgrades ``http://`` to
    ``https://`` when the base URL uses HTTPS) so that session cookies
    and TLS settings are applied consistently to every request.

    Returns ``None`` for external, ``data:``, ``javascript:``, ``mailto:`` URLs.
    """
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    parsed = urllib.parse.urlparse(raw)

    if not parsed.scheme:
        raw = urllib.parse.urljoin(page_url, raw)
        parsed = urllib.parse.urlparse(raw)

    base_parsed = urllib.parse.urlparse(base)
    host = base_parsed.netloc
    if parsed.netloc and parsed.netloc != host:
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
    scheme = base_parsed.scheme if base_parsed.scheme else parsed.scheme

    canonical = urllib.parse.urlunparse(
        (scheme, parsed.netloc, parsed.path, "", qs, "")
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
