"""Local web-based file index for Motorola Firmware Downloader.

Launches a lightweight HTTP server that displays an interactive HTML page
listing all ROMs, tools, flash-flows, and firmware files discovered across
every host, region, category, and model.

Features:
  - Real-time search/filter box (client-side JavaScript).
  - Columns: Filename, Type, Model, Region, Server, Download link.
  - Click-to-download: clicking a filename starts the browser download.
  - Modern responsive design with dark theme (pure HTML/CSS/JS, no deps).
  - Compatible with any modern browser on Windows, macOS, and Linux.

Usage (from CLI menu option "File Index Online") or standalone::

    python -m motorola_downloader.search.file_index_server
"""

import html
import http.server
import json
import os
import socket
import sys
import threading
import webbrowser
from typing import Any, Dict, List, Optional, Tuple

from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Web assets directory (HTML, CSS, JS files served separately)
# ---------------------------------------------------------------------------

_WEB_DIR = os.path.join(os.path.dirname(__file__), "web")


def _collect_all_files(
    api_client: Any,
    settings: Any = None,
) -> List[Tuple[str, str, str, str, str, str]]:
    """Collect every file from both LMSA hosts.

    When *settings* is provided, per-host credentials (prod vs test)
    are applied before querying each server.

    Returns a list of tuples:
        (filename, type, model, region, server_tag, download_url)
    """
    from motorola_downloader.utils.api_client import (
        LMSA_BASE_URLS,
        FIRMWARE_CATEGORIES,
        FIRMWARE_COUNTRIES,
    )
    from motorola_downloader.utils.url_utils import normalize_url

    # Read per-host credentials (prod / test may differ)
    prod_guid = prod_jwt = test_guid = test_jwt = ""
    if settings is not None:
        prod_guid = settings.get("motorola_server", "guid", fallback="")
        prod_jwt = settings.get("motorola_server", "jwt_token", fallback="")
        test_guid = settings.get("motorola_server_test", "guid_test", fallback="")
        test_jwt = settings.get("motorola_server_test", "jwt_token_test", fallback="")

    files: List[Tuple[str, str, str, str, str, str]] = []
    seen: set[str] = set()
    original_base = api_client.base_url

    def _add(name: str, ftype: str, model: str, region: str,
             server: str, url: str) -> None:
        if not name or not url:
            return
        key = name
        if key in seen:
            return
        seen.add(key)
        files.append((name, ftype, model, region, server, url))

    try:
        for host_url in LMSA_BASE_URLS:
            api_client.base_url = host_url
            tag = "prod" if "lsatest" not in host_url else "test"

            # Apply per-host credentials (prod/test use different JWT+GUID)
            if "lsatest" in host_url and (test_guid or test_jwt):
                api_client.apply_credentials(test_guid, test_jwt)
            elif "lsatest" not in host_url and (prod_guid or prod_jwt):
                api_client.apply_credentials(prod_guid, prod_jwt)

            _logger.info("[%s] Collecting ROM catalogue…", tag)
            try:
                roms = api_client.get_all_roms()
                for rom in roms:
                    name = rom.get("name", "")
                    uri = normalize_url(rom.get("uri", ""))
                    rtype = "ROM" if rom.get("type", 0) == 0 else "Tools"
                    _add(name, rtype, "", "", tag, uri)
            except Exception:
                pass

            _logger.info("[%s] Collecting model firmware…", tag)
            seen_models: set[str] = set()
            for country in FIRMWARE_COUNTRIES:
                for category in FIRMWARE_CATEGORIES:
                    try:
                        model_list = api_client.get_model_names(
                            country=country, category=category,
                        )
                    except Exception:
                        continue
                    for m in model_list:
                        mn = m.get("modelName", "")
                        mk = m.get("marketName", "")
                        mkey = f"{mn}|{mk}"
                        if mkey in seen_models:
                            continue
                        seen_models.add(mkey)

                        try:
                            resolved = api_client.resolve_resource(mn, mk)
                        except Exception:
                            continue

                        model_label = f"{mn} ({mk})" if mk else mn
                        for item in resolved:
                            region = item.get("comments", "") or ""
                            for res_key in ("romResource", "otaResource",
                                            "countryCodeResource"):
                                res = item.get(res_key)
                                if isinstance(res, dict) and res.get("uri"):
                                    _add(
                                        res.get("name", ""),
                                        "Firmware",
                                        model_label,
                                        region, tag,
                                        normalize_url(res["uri"]),
                                    )
                            tool = item.get("toolResource")
                            if isinstance(tool, dict) and tool.get("uri"):
                                platform = item.get("platform", "")
                                _add(
                                    tool.get("name", ""),
                                    f"FlashTool ({platform})" if platform else "FlashTool",
                                    model_label,
                                    region, tag,
                                    normalize_url(tool["uri"]),
                                )
                            ff = item.get("flashFlow")
                            if ff:
                                _add(
                                    f"{mn}_flashFlow.json",
                                    "FlashFlow",
                                    model_label,
                                    region, tag,
                                    normalize_url(ff),
                                )

            _logger.info("[%s] %d unique files so far", tag, len(files))
    finally:
        api_client.base_url = original_base
        # Restore prod credentials
        if prod_guid or prod_jwt:
            api_client.apply_credentials(prod_guid, prod_jwt)

    _logger.info("File collection complete: %d unique files total", len(files))
    return files


def build_index_html(files: List[Tuple[str, str, str, str, str, str]]) -> str:
    """Build the index page by reading web/index.html and injecting data.

    The index.html template contains ``/*__DATA__*/[]`` as a placeholder
    for the JSON array.  CSS and JS are loaded via ``<link>`` and
    ``<script src>`` tags that the HTTP handler resolves to the local
    ``web/`` directory.
    """
    html_path = os.path.join(_WEB_DIR, "index.html")
    with open(html_path, "r", encoding="utf-8") as fh:
        template = fh.read()
    data_json = json.dumps(
        [list(row) for row in files],
        ensure_ascii=False,
    )
    return template.replace("/*__DATA__*/[]", data_json)


# MIME types for static assets
_MIME_TYPES: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


class _Handler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that serves the file-explorer page and static assets.

    ``/``           → index.html (with injected DATA)
    ``/style.css``  → web/style.css
    ``/app.js``     → web/app.js
    Other paths     → 404
    """

    index_html: str = ""  # populated by start_server() with injected DATA

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]  # strip query string

        if path == "/" or path == "/index.html":
            self._serve_bytes(self.index_html.encode("utf-8"), "text/html; charset=utf-8")
            return

        # Serve static files from the web/ directory
        safe_name = os.path.basename(path.lstrip("/"))
        local_path = os.path.join(_WEB_DIR, safe_name)
        if os.path.isfile(local_path):
            ext = os.path.splitext(safe_name)[1].lower()
            content_type = _MIME_TYPES.get(ext, "application/octet-stream")
            with open(local_path, "rb") as fh:
                data = fh.read()
            self._serve_bytes(data, content_type)
            return

        self.send_error(404, "Not Found")

    def _serve_bytes(self, data: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # silence per-request logs


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def start_server(
    api_client: Any,
    port: int = 0,
    open_browser: bool = True,
    settings: Any = None,
) -> None:
    """Collect files and start the local web server.

    Args:
        api_client: Authenticated LMSAClient instance.
        port: TCP port (0 = auto-pick a free port).
        open_browser: Whether to open the page in the default browser.
        settings: Application Settings instance (for per-host credentials).
    """
    _logger.info("Building file index (this may take a few minutes)…")

    files = _collect_all_files(api_client, settings=settings)
    if not files:
        _logger.info("No files found — check authentication.")
        return

    html_page = build_index_html(files)
    _Handler.index_html = html_page

    if port == 0:
        port = _find_free_port()

    server = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    url = f"http://127.0.0.1:{port}"

    _logger.info("File index ready at %s  (%d files)", url, len(files))
    print(f"\n  🌐  File Index Online: {url}")
    print(f"      {len(files)} files indexed")
    print("      Press Ctrl+C to stop the server\n")

    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _logger.info("File index server stopped")
