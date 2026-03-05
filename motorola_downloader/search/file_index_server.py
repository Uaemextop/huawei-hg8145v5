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
# HTML template (self-contained: CSS + JS inlined)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Motorola Firmware — File Index</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;
      --muted:#8b949e;--accent:#58a6ff;--accent2:#3fb950;--row-hover:#1c2128}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
     background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--surface);border-bottom:1px solid var(--border);
       padding:16px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header h1{font-size:1.3rem;font-weight:600;white-space:nowrap}
header .badge{background:var(--accent);color:#000;padding:2px 10px;
              border-radius:12px;font-size:.75rem;font-weight:700}
.toolbar{display:flex;gap:12px;align-items:center;flex:1;min-width:240px}
#search{flex:1;min-width:200px;padding:8px 14px;border-radius:6px;
        border:1px solid var(--border);background:var(--bg);color:var(--text);
        font-size:.9rem;outline:none;transition:border .2s}
#search:focus{border-color:var(--accent)}
#count{color:var(--muted);font-size:.85rem;white-space:nowrap}
main{padding:16px 24px}
table{width:100%;border-collapse:collapse;table-layout:fixed}
thead{position:sticky;top:0;z-index:2}
th{background:var(--surface);color:var(--muted);font-weight:600;font-size:.8rem;
   text-transform:uppercase;letter-spacing:.04em;padding:10px 12px;
   text-align:left;border-bottom:2px solid var(--border);cursor:pointer;
   user-select:none}
th:hover{color:var(--text)}
td{padding:8px 12px;border-bottom:1px solid var(--border);font-size:.85rem;
   overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:var(--row-hover)}
a.dl{color:var(--accent);text-decoration:none;font-weight:500}
a.dl:hover{text-decoration:underline;color:#79c0ff}
.type{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;
      font-weight:600;text-transform:uppercase}
.type-rom{background:#1f3a2e;color:var(--accent2)}
.type-firmware{background:#1a2740;color:var(--accent)}
.type-tools,.type-flashtool{background:#2d1f3a;color:#d2a8ff}
.type-flashflow{background:#3a2e1f;color:#e3b341}
.server-prod{color:var(--accent2)}.server-test{color:#f0883e}
footer{text-align:center;padding:24px;color:var(--muted);font-size:.8rem}
@media(max-width:768px){td,th{padding:6px 8px;font-size:.78rem}
  header{padding:12px 16px}main{padding:12px 16px}}
</style>
</head>
<body>
<header>
  <h1>📱 Motorola Firmware — File Index</h1>
  <span class="badge" id="total"></span>
  <div class="toolbar">
    <input id="search" type="search" placeholder="Search files, models, regions…" autofocus>
    <span id="count"></span>
  </div>
</header>
<main><table>
<thead><tr>
  <th style="width:36%" onclick="sortBy(0)">Filename ↕</th>
  <th style="width:10%" onclick="sortBy(1)">Type ↕</th>
  <th style="width:16%" onclick="sortBy(2)">Model ↕</th>
  <th style="width:16%" onclick="sortBy(3)">Region ↕</th>
  <th style="width:10%" onclick="sortBy(4)">Server ↕</th>
  <th style="width:12%">Download</th>
</tr></thead>
<tbody id="tbody"></tbody>
</table></main>
<footer>Motorola Firmware Downloader — File Index Online</footer>
<script>
const DATA=/*__DATA__*/[];
const tbody=document.getElementById('tbody');
const searchBox=document.getElementById('search');
const countEl=document.getElementById('count');
const totalEl=document.getElementById('total');
let sortCol=-1,sortAsc=true;

function typeClass(t){
  const l=t.toLowerCase();
  if(l.includes('flashtool'))return 'type-flashtool';
  if(l.includes('flashflow'))return 'type-flashflow';
  if(l==='rom')return 'type-rom';
  if(l==='firmware')return 'type-firmware';
  if(l.includes('tool'))return 'type-tools';
  return 'type-firmware';
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function render(rows){
  const html=rows.map(r=>{
    const sclass=r[4].includes('test')?'server-test':'server-prod';
    return `<tr>
      <td><a class="dl" href="${esc(r[5])}" title="${esc(r[0])}">${esc(r[0])}</a></td>
      <td><span class="type ${typeClass(r[1])}">${esc(r[1])}</span></td>
      <td title="${esc(r[2])}">${esc(r[2])}</td>
      <td title="${esc(r[3])}">${esc(r[3])}</td>
      <td><span class="${sclass}">${esc(r[4])}</span></td>
      <td><a class="dl" href="${esc(r[5])}">⬇ Download</a></td>
    </tr>`;
  }).join('');
  tbody.innerHTML=html;
  countEl.textContent=rows.length+' shown';
}
function filter(){
  const q=searchBox.value.toLowerCase().trim();
  const filtered=q?DATA.filter(r=>r.slice(0,5).some(c=>c.toLowerCase().includes(q))):DATA;
  render(filtered);
}
function sortBy(col){
  if(sortCol===col)sortAsc=!sortAsc; else{sortCol=col;sortAsc=true}
  DATA.sort((a,b)=>{const v=a[col].localeCompare(b[col]);return sortAsc?v:-v});
  filter();
}
searchBox.addEventListener('input',filter);
totalEl.textContent=DATA.length+' files';
render(DATA);
</script>
</body>
</html>"""


def _collect_all_files(api_client: Any) -> List[Tuple[str, str, str, str, str, str]]:
    """Collect every file from both LMSA hosts.

    Returns a list of tuples:
        (filename, type, model, region, server_tag, download_url)
    """
    from motorola_downloader.utils.api_client import (
        LMSA_BASE_URLS,
        FIRMWARE_CATEGORIES,
        FIRMWARE_COUNTRIES,
    )
    from motorola_downloader.utils.url_utils import normalize_url

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

    _logger.info("File collection complete: %d unique files total", len(files))
    return files


def build_html(files: List[Tuple[str, str, str, str, str, str]]) -> str:
    """Build the self-contained HTML page with embedded data."""
    data_json = json.dumps(
        [list(row) for row in files],
        ensure_ascii=False,
    )
    return _HTML_TEMPLATE.replace("/*__DATA__*/[]", data_json)


class _Handler(http.server.BaseHTTPRequestHandler):
    """Simple handler that serves the single-page index."""

    html_content: str = ""

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.html_content.encode("utf-8"))

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # silence request logs


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def start_server(
    api_client: Any,
    port: int = 0,
    open_browser: bool = True,
) -> None:
    """Collect files and start the local web server.

    Args:
        api_client: Authenticated LMSAClient instance.
        port: TCP port (0 = auto-pick a free port).
        open_browser: Whether to open the page in the default browser.
    """
    _logger.info("Building file index (this may take a few minutes)…")

    files = _collect_all_files(api_client)
    if not files:
        _logger.info("No files found — check authentication.")
        return

    html_page = build_html(files)
    _Handler.html_content = html_page

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
