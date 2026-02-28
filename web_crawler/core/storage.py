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
                "application/rss+xml":   ".xml",
                "application/atom+xml":  ".xml",
                "text/plain":            ".txt",
                "text/csv":              ".csv",
                "text/tab-separated-values": ".tsv",
                "text/markdown":         ".md",
                "application/x-httpd-php": ".php",
                "text/x-php":            ".php",
                "application/php":       ".php",
                "image/png":             ".png",
                "image/jpeg":            ".jpg",
                "image/gif":             ".gif",
                "image/svg+xml":         ".svg",
                "image/x-icon":          ".ico",
                "image/vnd.microsoft.icon": ".ico",
                "image/webp":            ".webp",
                "image/avif":            ".avif",
                "image/bmp":             ".bmp",
                "image/tiff":            ".tiff",
                "font/woff":             ".woff",
                "font/woff2":            ".woff2",
                "font/ttf":              ".ttf",
                "font/otf":              ".otf",
                "application/font-woff":  ".woff",
                "application/font-woff2": ".woff2",
                "application/vnd.ms-fontobject": ".eot",
                "application/pdf":       ".pdf",
                "application/zip":       ".zip",
                "application/gzip":      ".gz",
                "application/x-gzip":    ".gz",
                "application/x-tar":     ".tar",
                "application/x-bzip2":   ".bz2",
                "application/x-7z-compressed": ".7z",
                "application/x-rar-compressed": ".rar",
                "application/vnd.rar":   ".rar",
                "application/x-msdownload": ".exe",
                "application/x-ms-dos-executable": ".exe",
                "application/x-exe":     ".exe",
                "application/x-winexe":  ".exe",
                "application/octet-stream": ".bin",
                "application/x-yaml":    ".yml",
                "text/yaml":             ".yml",
                "text/x-ini":            ".ini",
                "application/toml":      ".toml",
                "application/msword":    ".doc",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
                "application/vnd.ms-excel": ".xls",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
                "application/vnd.ms-powerpoint": ".ppt",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
                "application/x-shockwave-flash": ".swf",
                "application/wasm":      ".wasm",
                "audio/mpeg":            ".mp3",
                "audio/ogg":             ".ogg",
                "audio/wav":             ".wav",
                "audio/webm":            ".weba",
                "audio/flac":            ".flac",
                "audio/aac":             ".aac",
                "video/mp4":             ".mp4",
                "video/webm":            ".webm",
                "video/ogg":             ".ogv",
                "video/x-msvideo":       ".avi",
                "video/quicktime":       ".mov",
                "video/x-flv":           ".flv",
                "video/x-matroska":      ".mkv",
                "application/x-sqlite3": ".sqlite",
                "application/sql":       ".sql",
            }
            if ct in ext_map:
                path += ext_map[ct]

    return output_dir / Path(path)
