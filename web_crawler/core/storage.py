"""
File storage helpers – saving content and mapping URLs to local paths.
"""

import hashlib
import logging
import re
import urllib.parse
from pathlib import Path

log = logging.getLogger("web-crawler")


def save_file(local_path: Path, content: bytes) -> None:
    """Write *content* to *local_path*, creating parent directories."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)
    log.debug("Saved → %s (%d bytes)", local_path, len(content))


def content_hash(data: bytes) -> str:
    """Return a short SHA-256 hex digest for deduplication."""
    return hashlib.sha256(data).hexdigest()[:16]


def smart_local_path(
    url: str,
    output_dir: Path,
    content_type: str,
    content_disposition: str = "",
) -> Path:
    """
    Determine the local save path for a response.

    Priority:
      1. filename= from Content-Disposition header
      2. filename from URL path
      3. If URL path has no extension but Content-Type suggests one, append it
      4. Extensionless URLs become ``<name>.html`` when CT is text/html
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
                "text/html":             ".html",
                "application/xhtml+xml": ".html",
                "text/css":              ".css",
                "application/javascript": ".js",
                "text/javascript":       ".js",
                "application/json":      ".json",
                "text/xml":              ".xml",
                "application/xml":       ".xml",
                "image/png":             ".png",
                "image/jpeg":            ".jpg",
                "image/gif":             ".gif",
                "image/svg+xml":         ".svg",
                "image/x-icon":          ".ico",
                "image/vnd.microsoft.icon": ".ico",
            }
            if ct in ext_map:
                path += ext_map[ct]

    return output_dir / Path(path)
