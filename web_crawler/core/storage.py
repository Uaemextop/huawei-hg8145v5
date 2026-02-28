"""
File storage helpers – saving content and mapping URLs to local paths.
"""

import hashlib
import logging
import re
import urllib.parse
from pathlib import Path
from typing import Iterator

log = logging.getLogger("web-crawler")

# Chunk size for streaming large binary files to disk (512 KiB)
_STREAM_CHUNK = 524288


def save_file(local_path: Path, content: bytes) -> None:
    """Write *content* to *local_path*, creating parent directories."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)
    log.debug("Saved → %s (%d bytes)", local_path, len(content))


def stream_to_file(local_path: Path, chunks: Iterator[bytes]) -> int:
    """Write streaming *chunks* to *local_path*.

    Returns the total number of bytes written.  Creates parent
    directories as needed.
    """
    local_path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with local_path.open("wb") as fh:
        for chunk in chunks:
            if chunk:
                fh.write(chunk)
                total += len(chunk)
    log.debug("Streamed → %s (%d bytes)", local_path, total)
    return total


def content_hash(data: bytes) -> str:
    """Return a short SHA-256 hex digest for deduplication."""
    return hashlib.sha256(data).hexdigest()[:16]


def file_content_hash(path: Path) -> str:
    """Return a short SHA-256 hex digest for a file already on disk."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_STREAM_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _filename_from_disposition(header: str) -> str:
    """Extract the filename from a Content-Disposition header.

    Handles (in priority order):
    1. RFC 5987 extended notation:  ``filename*=UTF-8''my%20file.zip``
    2. Quoted value with spaces:    ``filename="my file.zip"``
    3. Unquoted value:              ``filename=myfile.zip``

    Returns an empty string when no usable filename is found.
    """
    if not header:
        return ""

    # RFC 5987 – charset'language'percent-encoded (highest priority)
    m = re.search(
        r"filename\*\s*=\s*([^']+)''([^;,\s]+)",
        header, re.I,
    )
    if m:
        charset = m.group(1).strip() or "utf-8"
        try:
            return urllib.parse.unquote(m.group(2), encoding=charset)
        except Exception:
            pass

    # Quoted filename (may contain spaces)
    m = re.search(r'filename\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"', header, re.I)
    if m:
        # Unescape backslash sequences
        fname = m.group(1).replace('\\"', '"').replace("\\\\", "\\")
        # Percent-decode if the server also encoded within quotes
        return urllib.parse.unquote(fname)

    # Unquoted filename (no spaces, no semicolons)
    m = re.search(r"filename\s*=\s*([^\s;,\"']+)", header, re.I)
    if m:
        return urllib.parse.unquote(m.group(1).strip())

    return ""


def smart_local_path(
    url: str,
    output_dir: Path,
    content_type: str,
    content_disposition: str = "",
) -> Path:
    """
    Determine the local save path for a response.

    Priority:
      1. filename= from Content-Disposition header (RFC 5987 + RFC 6266)
      2. filename from URL path
      3. If URL path has no extension but Content-Type suggests one, append it
      4. Extensionless URLs become ``<name>.html`` when CT is text/html
    """
    if content_disposition:
        fname = _filename_from_disposition(content_disposition)
        if fname:
            # Sanitise: strip any path traversal characters
            fname = Path(fname).name
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
                "application/x-tar":     ".tar",
                "application/x-bzip2":   ".bz2",
                "application/x-7z-compressed": ".7z",
                "application/x-rar-compressed": ".rar",
                "application/vnd.rar":       ".rar",
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
                "application/octet-stream": ".bin",
                "application/x-msdownload": ".exe",
                "application/x-msdos-program": ".exe",
                "application/x-executable": ".exe",
                "application/x-sh":          ".sh",
                "application/x-shellscript": ".sh",
                "application/x-bat":         ".bat",
                "application/x-msdos-batch": ".bat",
                "application/x-cmd":         ".cmd",
                "application/x-powershell":  ".ps1",
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
