"""
HTML index page generator for crawled sites.

Generates a browsable ``index.html`` with a dark-themed file-browser UI so
that crawled content can be explored directly on GitHub Pages or any static
web server.
"""

from __future__ import annotations

import html
import os
from pathlib import Path
from typing import NamedTuple

from web_crawler.utils.log import log

# ── File category classification ────────────────────────────────────────────

_CATEGORY_MAP: dict[str, str] = {}
_FIRMWARE_EXTS = {
    ".bin", ".img", ".fw", ".rom", ".hex", ".elf", ".srec", ".s19",
    ".mot", ".uf2", ".dfu",
}
_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz"}
_CONFIG_EXTS = {
    ".xml", ".json", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".toml",
    ".properties", ".env",
}
_DOCUMENT_EXTS = {
    ".html", ".htm", ".pdf", ".doc", ".docx", ".txt", ".md", ".rst",
    ".csv", ".xls", ".xlsx", ".rtf", ".odt",
}
_EXECUTABLE_EXTS = {
    ".exe", ".msi", ".apk", ".ipa", ".deb", ".rpm", ".sh", ".bat",
    ".cmd", ".ps1", ".jar", ".war", ".ear", ".iso", ".dmg", ".app",
}
_IMAGE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".tiff", ".tif",
}
_VIDEO_EXTS = {
    ".mp4", ".webm", ".ogv", ".avi", ".mov", ".flv", ".mkv", ".wmv",
    ".m4v", ".3gp", ".mpeg", ".mpg",
}
_AUDIO_EXTS = {".mp3", ".ogg", ".wav", ".flac", ".aac", ".m4a", ".weba"}

for _ext in _FIRMWARE_EXTS:
    _CATEGORY_MAP[_ext] = "firmware"
for _ext in _ARCHIVE_EXTS:
    _CATEGORY_MAP[_ext] = "archive"
for _ext in _CONFIG_EXTS:
    _CATEGORY_MAP[_ext] = "config"
for _ext in _DOCUMENT_EXTS:
    _CATEGORY_MAP[_ext] = "document"
for _ext in _EXECUTABLE_EXTS:
    _CATEGORY_MAP[_ext] = "executable"
for _ext in _IMAGE_EXTS:
    _CATEGORY_MAP[_ext] = "image"
for _ext in _VIDEO_EXTS:
    _CATEGORY_MAP[_ext] = "video"
for _ext in _AUDIO_EXTS:
    _CATEGORY_MAP[_ext] = "audio"


def _classify(path: Path) -> str:
    """Return a category string for *path* based on its extension."""
    return _CATEGORY_MAP.get(path.suffix.lower(), "other")


# ── Size formatting ─────────────────────────────────────────────────────────

def _human_size(size_bytes: int) -> str:
    """Convert bytes to a human-friendly string (e.g. ``1.2 GB``)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024:
            if unit == "B":
                return f"{size_bytes} {unit}"
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} PB"


# ── Directory statistics ────────────────────────────────────────────────────

class _DirStats(NamedTuple):
    total_files: int
    total_size: int
    subdirectories: int
    direct_files: int
    archives: int
    configs: int
    documents: int
    executables: int
    firmwares: int
    images: int


def _compute_stats(root: Path) -> _DirStats:
    """Walk *root* and collect statistics (ignoring ``.git``)."""
    total_files = 0
    total_size = 0
    subdirs: set[str] = set()
    direct_files = 0
    cats: dict[str, int] = {
        "archive": 0, "config": 0, "document": 0,
        "executable": 0, "firmware": 0, "image": 0,
    }

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip hidden dirs (especially .git)
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]

        rel = Path(dirpath).relative_to(root)
        for fname in filenames:
            if fname.startswith("."):
                continue
            fpath = Path(dirpath) / fname
            total_files += 1
            try:
                total_size += fpath.stat().st_size
            except OSError:
                pass
            cat = _classify(fpath)
            if cat in cats:
                cats[cat] += 1

            if rel == Path("."):
                direct_files += 1
            else:
                subdirs.add(str(rel).split(os.sep)[0])

    return _DirStats(
        total_files=total_files,
        total_size=total_size,
        subdirectories=len(subdirs),
        direct_files=direct_files,
        archives=cats["archive"],
        configs=cats["config"],
        documents=cats["document"],
        executables=cats["executable"],
        firmwares=cats["firmware"],
        images=cats["image"],
    )


# ── Entry listing ───────────────────────────────────────────────────────────

class _Entry(NamedTuple):
    name: str
    is_dir: bool
    size: int
    category: str


def _list_entries(directory: Path) -> list[_Entry]:
    """Return immediate children of *directory* (excluding hidden files)."""
    entries: list[_Entry] = []
    try:
        children = sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except OSError:
        return entries

    for child in children:
        if child.name.startswith("."):
            continue
        if child.is_dir():
            entries.append(_Entry(child.name, True, 0, "folder"))
        else:
            try:
                sz = child.stat().st_size
            except OSError:
                sz = 0
            entries.append(_Entry(child.name, False, sz, _classify(child)))
    return entries


# ── HTML template ───────────────────────────────────────────────────────────

_ICON_MAP = {
    "folder": "📁",
    "firmware": "💾",
    "archive": "📦",
    "config": "⚙️",
    "document": "📄",
    "executable": "⚡",
    "image": "🖼️",
    "video": "🎬",
    "audio": "🎵",
    "other": "📎",
}


def _render_html(
    title: str,
    stats: _DirStats,
    entries: list[_Entry],
) -> str:
    """Render the full HTML page."""
    # Build table rows
    rows = []
    for e in entries:
        icon = _ICON_MAP.get(e.category, "📎")
        name_escaped = html.escape(e.name)
        if e.is_dir:
            link = f'<a href="{html.escape(e.name)}/">{icon} {name_escaped}</a>'
            size_str = "—"
        else:
            link = f'<a href="{html.escape(e.name)}">{icon} {name_escaped}</a>'
            size_str = _human_size(e.size)
        cat_escaped = html.escape(e.category)
        rows.append(
            f'        <tr data-name="{name_escaped.lower()}" '
            f'data-cat="{cat_escaped}">\n'
            f"          <td>{link}</td>\n"
            f'          <td class="size">{size_str}</td>\n'
            f'          <td class="cat">{cat_escaped}</td>\n'
            f"        </tr>"
        )
    rows_html = "\n".join(rows)
    title_escaped = html.escape(title)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_escaped}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#c9d1d9;--text-muted:#8b949e;--accent:#58a6ff;
  --green:#3fb950;--row-hover:#1c2128;
}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.5}}
header{{background:var(--surface);border-bottom:1px solid var(--border);
  padding:12px 20px;display:flex;align-items:center;gap:12px}}
header h1{{font-size:1.15rem;font-weight:600}}
header .icon{{font-size:1.4rem}}
.container{{max-width:960px;margin:0 auto;padding:16px}}
.search-bar{{display:flex;gap:8px;margin:12px 0;flex-wrap:wrap}}
.search-bar input{{flex:1;min-width:200px;padding:8px 12px;border-radius:6px;
  border:1px solid var(--border);background:var(--surface);color:var(--text);
  font-size:.9rem}}
.search-bar input:focus{{outline:none;border-color:var(--accent)}}
.search-bar select{{padding:8px 10px;border-radius:6px;
  border:1px solid var(--border);background:var(--surface);color:var(--text);
  font-size:.85rem;cursor:pointer}}
.summary{{background:var(--surface);border:1px solid var(--border);
  border-radius:8px;padding:16px;margin:12px 0}}
.summary h2{{font-size:.95rem;margin-bottom:10px;color:var(--text-muted)}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px}}
.stat{{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px}}
.stat .label{{font-size:.7rem;text-transform:uppercase;color:var(--text-muted);
  letter-spacing:.05em}}
.stat .value{{font-size:1.3rem;font-weight:600;margin-top:2px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th{{text-align:left;font-size:.75rem;text-transform:uppercase;
  color:var(--text-muted);padding:8px 12px;border-bottom:1px solid var(--border);
  letter-spacing:.05em;cursor:pointer;user-select:none}}
th:hover{{color:var(--accent)}}
td{{padding:10px 12px;border-bottom:1px solid var(--border);font-size:.9rem}}
tr:hover{{background:var(--row-hover)}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
.size{{text-align:right;color:var(--text-muted);white-space:nowrap}}
.cat{{color:var(--text-muted);font-size:.8rem;text-transform:capitalize}}
.empty{{text-align:center;color:var(--text-muted);padding:32px}}
@media(max-width:600px){{
  .stats-grid{{grid-template-columns:repeat(2,1fr)}}
  .cat{{display:none}}
}}
</style>
</head>
<body>
<header>
  <span class="icon">📂</span>
  <h1>{title_escaped}</h1>
</header>
<div class="container">
  <div class="search-bar">
    <input type="text" id="search" placeholder="Search files…" autocomplete="off">
    <select id="filter">
      <option value="">All types</option>
      <option value="folder">Folders</option>
      <option value="firmware">Firmware</option>
      <option value="archive">Archives</option>
      <option value="config">Configs</option>
      <option value="document">Documents</option>
      <option value="executable">Executables</option>
      <option value="image">Images</option>
      <option value="video">Video</option>
      <option value="audio">Audio</option>
      <option value="other">Other</option>
    </select>
  </div>
  <details class="summary" open>
    <summary><strong>📊 Directory summary</strong></summary>
    <div class="stats-grid">
      <div class="stat"><div class="label">Total files</div><div class="value">{stats.total_files}</div></div>
      <div class="stat"><div class="label">Total size</div><div class="value">{_human_size(stats.total_size)}</div></div>
      <div class="stat"><div class="label">Subdirectories</div><div class="value">{stats.subdirectories}</div></div>
      <div class="stat"><div class="label">Direct files</div><div class="value">{stats.direct_files}</div></div>
      <div class="stat"><div class="label">Archives</div><div class="value">{stats.archives}</div></div>
      <div class="stat"><div class="label">Configs</div><div class="value">{stats.configs}</div></div>
      <div class="stat"><div class="label">Documents</div><div class="value">{stats.documents}</div></div>
      <div class="stat"><div class="label">Executables</div><div class="value">{stats.executables}</div></div>
      <div class="stat"><div class="label">Firmwares</div><div class="value">{stats.firmwares}</div></div>
      <div class="stat"><div class="label">Images</div><div class="value">{stats.images}</div></div>
    </div>
  </details>
  <table>
    <thead>
      <tr>
        <th id="col-name" data-sort="name">Name ▲</th>
        <th id="col-size" data-sort="size" style="text-align:right">Size</th>
        <th id="col-cat" data-sort="cat">Type</th>
      </tr>
    </thead>
    <tbody id="listing">
{rows_html}
    </tbody>
  </table>
  <p class="empty" id="no-results" hidden>No matching files.</p>
</div>
<script>
(function(){{
  var search=document.getElementById("search");
  var filter=document.getElementById("filter");
  var tbody=document.getElementById("listing");
  var noRes=document.getElementById("no-results");
  function applyFilter(){{
    var q=search.value.toLowerCase();
    var cat=filter.value;
    var rows=tbody.querySelectorAll("tr");
    var visible=0;
    rows.forEach(function(r){{
      var name=r.getAttribute("data-name")||"";
      var rCat=r.getAttribute("data-cat")||"";
      var show=(name.indexOf(q)!==-1)&&(!cat||rCat===cat);
      r.style.display=show?"":"none";
      if(show) visible++;
    }});
    noRes.hidden=visible>0;
  }}
  search.addEventListener("input",applyFilter);
  filter.addEventListener("change",applyFilter);

  /* Column sorting */
  var sortCol="name",sortAsc=true;
  document.querySelectorAll("th[data-sort]").forEach(function(th){{
    th.addEventListener("click",function(){{
      var col=th.getAttribute("data-sort");
      if(sortCol===col){{sortAsc=!sortAsc}}else{{sortCol=col;sortAsc=true}}
      var rows=Array.from(tbody.querySelectorAll("tr"));
      rows.sort(function(a,b){{
        var va,vb;
        if(col==="name"){{va=a.getAttribute("data-name");vb=b.getAttribute("data-name")}}
        else if(col==="size"){{va=a.querySelector(".size").textContent;vb=b.querySelector(".size").textContent;
          va=parseSz(va);vb=parseSz(vb)}}
        else{{va=a.getAttribute("data-cat");vb=b.getAttribute("data-cat")}}
        if(va<vb)return sortAsc?-1:1;
        if(va>vb)return sortAsc?1:-1;
        return 0;
      }});
      rows.forEach(function(r){{tbody.appendChild(r)}});
      document.querySelectorAll("th[data-sort]").forEach(function(h){{
        var t=h.textContent.replace(/ [▲▼]/,"");
        h.textContent=h===th?t+(sortAsc?" ▲":" ▼"):t;
      }});
    }});
  }});
  function parseSz(s){{
    if(!s||s==="—")return -1;
    var m=s.match(/([\\.\\d]+)\\s*(B|KB|MB|GB|TB|PB)/);
    if(!m)return 0;
    var n=parseFloat(m[1]),u=m[2];
    var mult={{"B":1,"KB":1024,"MB":1048576,"GB":1073741824,"TB":1099511627776,"PB":1125899906842624}};
    return n*(mult[u]||1);
  }}
}})();
</script>
</body>
</html>
"""


# ── Public API ──────────────────────────────────────────────────────────────

def generate_index(output_dir: Path, site_name: str = "") -> Path:
    """Generate ``_index.html`` inside *output_dir*.

    We use ``_index.html`` (underscore prefix) so we never overwrite a
    crawled ``index.html`` that came from the remote site.

    Returns the path to the generated file.
    """
    output_dir = Path(output_dir)
    if not output_dir.is_dir():
        raise FileNotFoundError(f"Output directory does not exist: {output_dir}")

    if not site_name:
        site_name = output_dir.name

    stats = _compute_stats(output_dir)
    entries = _list_entries(output_dir)
    content = _render_html(site_name, stats, entries)

    index_path = output_dir / "_index.html"
    index_path.write_text(content, encoding="utf-8")
    log.info("Generated file index: %s (%d entries)", index_path, len(entries))
    return index_path
