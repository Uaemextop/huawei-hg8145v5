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
<title>Motorola Firmware — File Explorer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#f7f8fa;--surface:#fff;--border:#e1e4e8;--text:#24292f;
  --muted:#656d76;--accent:#0969da;--accent-light:#ddf4ff;
  --accent2:#1a7f37;--accent2-light:#dafbe1;--hover:#f3f4f6;
  --sidebar:#1b1f23;--sidebar-text:#e6edf3;--sidebar-hover:#30363d;
  --shadow:0 1px 3px rgba(0,0,0,.08);--shadow-lg:0 4px 12px rgba(0,0,0,.12);
  --radius:8px;--purple:#8250df;--orange:#bf5700;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
     background:var(--bg);color:var(--text);display:flex;height:100vh;overflow:hidden}

/* ── Sidebar ─────────────────────────────────────────────── */
.sidebar{width:260px;background:var(--sidebar);color:var(--sidebar-text);
         display:flex;flex-direction:column;flex-shrink:0}
.sidebar-header{padding:20px;border-bottom:1px solid rgba(255,255,255,.1)}
.sidebar-header h1{font-size:1rem;font-weight:600;display:flex;align-items:center;gap:8px}
.sidebar-header .logo{font-size:1.4rem}
.sidebar-nav{flex:1;overflow-y:auto;padding:12px 0}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;
          color:var(--sidebar-text);cursor:pointer;transition:.15s;font-size:.88rem}
.nav-item:hover{background:var(--sidebar-hover)}
.nav-item.active{background:var(--accent);color:#fff;font-weight:600}
.nav-item .icon{width:20px;text-align:center;font-size:1rem;opacity:.8}
.nav-item .badge{margin-left:auto;background:rgba(255,255,255,.15);
                 padding:1px 8px;border-radius:10px;font-size:.72rem}
.sidebar-footer{padding:16px 20px;border-top:1px solid rgba(255,255,255,.1);
                font-size:.75rem;color:rgba(255,255,255,.4)}

/* ── Main content ────────────────────────────────────────── */
.content{flex:1;display:flex;flex-direction:column;overflow:hidden}

/* Toolbar */
.toolbar{display:flex;align-items:center;gap:12px;padding:16px 24px;
         background:var(--surface);border-bottom:1px solid var(--border)}
.search-box{flex:1;max-width:480px;position:relative}
.search-box input{width:100%;padding:9px 12px 9px 36px;border:1px solid var(--border);
                  border-radius:var(--radius);font-size:.88rem;background:var(--bg);
                  color:var(--text);outline:none;transition:.2s}
.search-box input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-light)}
.search-box .search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);
                         color:var(--muted);font-size:.9rem;pointer-events:none}
.toolbar-stats{color:var(--muted);font-size:.82rem;white-space:nowrap}
.view-toggle{display:flex;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.view-btn{padding:6px 12px;cursor:pointer;background:var(--surface);border:none;
          color:var(--muted);font-size:.82rem;transition:.15s}
.view-btn:hover{background:var(--hover)}
.view-btn.active{background:var(--accent);color:#fff}

/* Breadcrumb */
.breadcrumb{padding:8px 24px;font-size:.82rem;color:var(--muted);
            background:var(--surface);border-bottom:1px solid var(--border)}
.breadcrumb span{cursor:pointer;color:var(--accent)}
.breadcrumb span:hover{text-decoration:underline}

/* File list — list view (default) */
.file-area{flex:1;overflow-y:auto;padding:0}
.file-table{width:100%;border-collapse:collapse}
.file-table thead{position:sticky;top:0;z-index:2}
.file-table th{background:var(--bg);color:var(--muted);font-weight:600;font-size:.76rem;
               text-transform:uppercase;letter-spacing:.04em;padding:10px 16px;
               text-align:left;border-bottom:1px solid var(--border);cursor:pointer;
               user-select:none}
.file-table th:hover{color:var(--text)}
.file-table td{padding:10px 16px;border-bottom:1px solid var(--border);font-size:.86rem}
.file-table tr:hover td{background:var(--hover)}
.file-row{cursor:pointer}

/* File icon + name */
.file-name{display:flex;align-items:center;gap:10px;font-weight:500}
.file-name .ficon{width:32px;height:32px;border-radius:6px;display:flex;
                  align-items:center;justify-content:center;font-size:.8rem;
                  font-weight:700;flex-shrink:0}
.ficon-rom{background:var(--accent2-light);color:var(--accent2)}
.ficon-firmware{background:var(--accent-light);color:var(--accent)}
.ficon-tools,.ficon-flashtool{background:#f5f0ff;color:var(--purple)}
.ficon-flashflow{background:#fff8e1;color:var(--orange)}
.file-name a{color:var(--text);text-decoration:none}
.file-name a:hover{color:var(--accent);text-decoration:underline}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.72rem;
       font-weight:600}
.badge-rom{background:var(--accent2-light);color:var(--accent2)}
.badge-firmware{background:var(--accent-light);color:var(--accent)}
.badge-tools,.badge-flashtool{background:#f5f0ff;color:var(--purple)}
.badge-flashflow{background:#fff8e1;color:var(--orange)}
.badge-prod{background:var(--accent2-light);color:var(--accent2)}
.badge-test{background:#fff1e5;color:var(--orange)}

/* Grid view */
.file-grid{display:none;padding:20px 24px;gap:16px;
           grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
.file-grid.active{display:grid}
.file-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
           padding:16px;cursor:pointer;transition:.15s;display:flex;flex-direction:column;gap:10px}
.file-card:hover{box-shadow:var(--shadow-lg);border-color:var(--accent)}
.card-icon{width:40px;height:40px;border-radius:8px;display:flex;align-items:center;
           justify-content:center;font-size:1rem;font-weight:700}
.card-name{font-size:.84rem;font-weight:500;word-break:break-all;line-height:1.3}
.card-name a{color:var(--text);text-decoration:none}
.card-name a:hover{color:var(--accent)}
.card-meta{font-size:.72rem;color:var(--muted);display:flex;flex-wrap:wrap;gap:6px}

/* Empty state */
.empty{text-align:center;padding:80px 20px;color:var(--muted)}
.empty .icon{font-size:3rem;margin-bottom:12px}

@media(max-width:768px){
  .sidebar{display:none}
  .toolbar{flex-wrap:wrap}
  .search-box{max-width:100%}
  .file-table td,.file-table th{padding:8px 10px;font-size:.78rem}
}
</style>
</head>
<body>

<!-- Sidebar -->
<aside class="sidebar">
  <div class="sidebar-header">
    <h1><span class="logo">📱</span> Firmware Explorer</h1>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-item active" data-filter="all">
      <span class="icon">📁</span> All Files <span class="badge" id="nav-all"></span>
    </div>
    <div class="nav-item" data-filter="rom">
      <span class="icon">💿</span> ROMs <span class="badge" id="nav-rom"></span>
    </div>
    <div class="nav-item" data-filter="firmware">
      <span class="icon">📦</span> Firmware <span class="badge" id="nav-firmware"></span>
    </div>
    <div class="nav-item" data-filter="flashtool">
      <span class="icon">🔧</span> Flash Tools <span class="badge" id="nav-flashtool"></span>
    </div>
    <div class="nav-item" data-filter="flashflow">
      <span class="icon">📋</span> Flash Flows <span class="badge" id="nav-flashflow"></span>
    </div>
    <div class="nav-item" data-filter="tools">
      <span class="icon">🛠️</span> Tools <span class="badge" id="nav-tools"></span>
    </div>
    <hr style="border-color:rgba(255,255,255,.1);margin:8px 20px">
    <div class="nav-item" data-filter="server-prod">
      <span class="icon">🟢</span> Production Server
    </div>
    <div class="nav-item" data-filter="server-test">
      <span class="icon">🟠</span> Test Server
    </div>
  </nav>
  <div class="sidebar-footer">Motorola Firmware Downloader</div>
</aside>

<!-- Main content -->
<div class="content">
  <!-- Toolbar -->
  <div class="toolbar">
    <div class="search-box">
      <span class="search-icon">🔍</span>
      <input id="search" type="search" placeholder="Search files, models, regions…" autofocus>
    </div>
    <span class="toolbar-stats" id="count"></span>
    <div class="view-toggle">
      <button class="view-btn active" id="btn-list" onclick="setView('list')">☰ List</button>
      <button class="view-btn" id="btn-grid" onclick="setView('grid')">⊞ Grid</button>
    </div>
  </div>

  <!-- Breadcrumb -->
  <div class="breadcrumb">
    <span onclick="resetFilter()">All Files</span> / <span id="crumb-filter">Showing all</span>
  </div>

  <!-- List view -->
  <div class="file-area" id="list-view">
    <table class="file-table">
      <thead><tr>
        <th style="width:38%" onclick="sortBy(0)">Name ↕</th>
        <th style="width:10%" onclick="sortBy(1)">Type ↕</th>
        <th style="width:18%" onclick="sortBy(2)">Model ↕</th>
        <th style="width:14%" onclick="sortBy(3)">Region ↕</th>
        <th style="width:10%" onclick="sortBy(4)">Server ↕</th>
        <th style="width:10%"></th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

  <!-- Grid view -->
  <div class="file-grid" id="grid-view"></div>
</div>

<script>
const DATA=/*__DATA__*/[];
let currentFilter='all', sortCol=-1, sortAsc=true, currentView='list';

const tbody=document.getElementById('tbody');
const gridView=document.getElementById('grid-view');
const searchBox=document.getElementById('search');
const countEl=document.getElementById('count');
const crumbEl=document.getElementById('crumb-filter');

function iconClass(t){
  const l=t.toLowerCase();
  if(l.includes('flashtool'))return 'ficon-flashtool';
  if(l.includes('flashflow'))return 'ficon-flashflow';
  if(l==='rom')return 'ficon-rom';
  if(l==='firmware')return 'ficon-firmware';
  if(l.includes('tool'))return 'ficon-tools';
  return 'ficon-firmware';
}
function badgeClass(t){
  const l=t.toLowerCase();
  if(l.includes('flashtool'))return 'badge-flashtool';
  if(l.includes('flashflow'))return 'badge-flashflow';
  if(l==='rom')return 'badge-rom';
  if(l==='firmware')return 'badge-firmware';
  if(l.includes('tool'))return 'badge-tools';
  return 'badge-firmware';
}
function iconLetter(t){
  const l=t.toLowerCase();
  if(l.includes('flashtool'))return '⚡';
  if(l.includes('flashflow'))return '📋';
  if(l==='rom')return '💿';
  if(l==='firmware')return '📦';
  if(l.includes('tool'))return '🛠';
  return '📄';
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

function getFiltered(){
  const q=searchBox.value.toLowerCase().trim();
  let rows=DATA;
  if(currentFilter==='server-prod') rows=rows.filter(r=>!r[4].toLowerCase().includes('test'));
  else if(currentFilter==='server-test') rows=rows.filter(r=>r[4].toLowerCase().includes('test'));
  else if(currentFilter!=='all') rows=rows.filter(r=>r[1].toLowerCase().includes(currentFilter));
  if(q) rows=rows.filter(r=>r.slice(0,5).some(c=>c.toLowerCase().includes(q)));
  return rows;
}

function renderList(rows){
  tbody.innerHTML=rows.map(r=>{
    const sclass=r[4].includes('test')?'badge-test':'badge-prod';
    return `<tr class="file-row" ondblclick="window.open('${esc(r[5])}')">
      <td><div class="file-name">
        <div class="ficon ${iconClass(r[1])}">${iconLetter(r[1])}</div>
        <a href="${esc(r[5])}" title="${esc(r[0])}">${esc(r[0])}</a>
      </div></td>
      <td><span class="badge ${badgeClass(r[1])}">${esc(r[1])}</span></td>
      <td title="${esc(r[2])}">${esc(r[2])}</td>
      <td>${esc(r[3])}</td>
      <td><span class="badge ${sclass}">${esc(r[4])}</span></td>
      <td><a href="${esc(r[5])}" style="color:var(--accent);text-decoration:none;font-size:.82rem">⬇ Download</a></td>
    </tr>`;
  }).join('');
}

function renderGrid(rows){
  gridView.innerHTML=rows.map(r=>{
    return `<div class="file-card" onclick="window.open('${esc(r[5])}')">
      <div class="card-icon ${iconClass(r[1])}">${iconLetter(r[1])}</div>
      <div class="card-name"><a href="${esc(r[5])}" onclick="event.stopPropagation()">${esc(r[0])}</a></div>
      <div class="card-meta">
        <span class="badge ${badgeClass(r[1])}">${esc(r[1])}</span>
        <span class="badge ${r[4].includes('test')?'badge-test':'badge-prod'}">${esc(r[4])}</span>
      </div>
      <div class="card-meta">${esc(r[2])} ${r[3]?'· '+esc(r[3]):''}</div>
    </div>`;
  }).join('');
}

function render(){
  const rows=getFiltered();
  countEl.textContent=rows.length+' of '+DATA.length+' files';
  renderList(rows);
  renderGrid(rows);
  if(!rows.length){
    tbody.innerHTML='<tr><td colspan="6"><div class="empty"><div class="icon">📂</div>No files match your search</div></td></tr>';
    gridView.innerHTML='<div class="empty"><div class="icon">📂</div>No files match your search</div>';
  }
}

function sortBy(col){
  if(sortCol===col)sortAsc=!sortAsc;else{sortCol=col;sortAsc=true}
  DATA.sort((a,b)=>{const v=a[col].localeCompare(b[col]);return sortAsc?v:-v});
  render();
}

function setView(v){
  currentView=v;
  document.getElementById('list-view').style.display=v==='list'?'block':'none';
  document.getElementById('grid-view').classList.toggle('active',v==='grid');
  document.getElementById('btn-list').classList.toggle('active',v==='list');
  document.getElementById('btn-grid').classList.toggle('active',v==='grid');
}

function setFilter(f){
  currentFilter=f;
  document.querySelectorAll('.nav-item').forEach(el=>{
    el.classList.toggle('active',el.dataset.filter===f);
  });
  const labels={all:'Showing all',rom:'ROMs',firmware:'Firmware',
    flashtool:'Flash Tools',flashflow:'Flash Flows',tools:'Tools',
    'server-prod':'Production server','server-test':'Test server'};
  crumbEl.textContent=labels[f]||f;
  render();
}

function resetFilter(){setFilter('all')}

// Sidebar nav clicks
document.querySelectorAll('.nav-item').forEach(el=>{
  el.addEventListener('click',()=>setFilter(el.dataset.filter));
});
searchBox.addEventListener('input',render);

// Sidebar badge counts
function updateCounts(){
  const c={all:DATA.length,rom:0,firmware:0,flashtool:0,flashflow:0,tools:0};
  DATA.forEach(r=>{
    const l=r[1].toLowerCase();
    if(l==='rom')c.rom++;
    else if(l==='firmware')c.firmware++;
    else if(l.includes('flashtool'))c.flashtool++;
    else if(l.includes('flashflow'))c.flashflow++;
    else if(l.includes('tool'))c.tools++;
  });
  for(const[k,v]of Object.entries(c)){
    const el=document.getElementById('nav-'+k);
    if(el)el.textContent=v;
  }
}
updateCounts();
render();
</script>
</body>
</html>"""


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
