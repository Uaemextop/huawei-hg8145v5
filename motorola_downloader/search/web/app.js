/* Motorola Firmware Explorer — Client-side logic
 * Handles search, filtering, sorting, grid/list toggle.
 * DATA is injected by Python as a global array at page load.
 * Each row: [filename, type, model, region, server, download_url]
 */

/* globals injected by the HTML template: DATA (array of arrays) */

let currentFilter = 'all';
let sortCol = -1;
let sortAsc = true;
let currentView = 'list';

const tbody = document.getElementById('tbody');
const gridView = document.getElementById('grid-view');
const searchBox = document.getElementById('search');
const countEl = document.getElementById('count');
const crumbEl = document.getElementById('crumb-filter');

/* ── Helper functions ──────────────────────────────────── */

function iconClass(t) {
  const l = t.toLowerCase();
  if (l.includes('flashtool')) return 'ficon-flashtool';
  if (l.includes('flashflow')) return 'ficon-flashflow';
  if (l === 'rom') return 'ficon-rom';
  if (l === 'firmware') return 'ficon-firmware';
  if (l.includes('tool')) return 'ficon-tools';
  return 'ficon-firmware';
}

function badgeClass(t) {
  const l = t.toLowerCase();
  if (l.includes('flashtool')) return 'badge-flashtool';
  if (l.includes('flashflow')) return 'badge-flashflow';
  if (l === 'rom') return 'badge-rom';
  if (l === 'firmware') return 'badge-firmware';
  if (l.includes('tool')) return 'badge-tools';
  return 'badge-firmware';
}

function iconLetter(t) {
  const l = t.toLowerCase();
  if (l.includes('flashtool')) return '\u26A1';
  if (l.includes('flashflow')) return '\uD83D\uDCCB';
  if (l === 'rom') return '\uD83D\uDCBF';
  if (l === 'firmware') return '\uD83D\uDCE6';
  if (l.includes('tool')) return '\uD83D\uDEE0';
  return '\uD83D\uDCC4';
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

/* ── Filtering ─────────────────────────────────────────── */

function getFiltered() {
  const q = searchBox.value.toLowerCase().trim();
  let rows = DATA;
  if (currentFilter === 'server-prod')
    rows = rows.filter(r => !r[4].toLowerCase().includes('test'));
  else if (currentFilter === 'server-test')
    rows = rows.filter(r => r[4].toLowerCase().includes('test'));
  else if (currentFilter !== 'all')
    rows = rows.filter(r => r[1].toLowerCase().includes(currentFilter));
  if (q) rows = rows.filter(r => r.slice(0, 5).some(c => c.toLowerCase().includes(q)));
  return rows;
}

/* ── Rendering ─────────────────────────────────────────── */

function renderList(rows) {
  tbody.innerHTML = rows.map(r => {
    const sclass = r[4].includes('test') ? 'badge-test' : 'badge-prod';
    return '<tr class="file-row" ondblclick="window.open(\'' + esc(r[5]) + '\')">' +
      '<td><div class="file-name">' +
        '<div class="ficon ' + iconClass(r[1]) + '">' + iconLetter(r[1]) + '</div>' +
        '<a href="' + esc(r[5]) + '" title="' + esc(r[0]) + '">' + esc(r[0]) + '</a>' +
      '</div></td>' +
      '<td><span class="badge ' + badgeClass(r[1]) + '">' + esc(r[1]) + '</span></td>' +
      '<td title="' + esc(r[2]) + '">' + esc(r[2]) + '</td>' +
      '<td>' + esc(r[3]) + '</td>' +
      '<td><span class="badge ' + sclass + '">' + esc(r[4]) + '</span></td>' +
      '<td><a href="' + esc(r[5]) + '" style="color:var(--accent);text-decoration:none;font-size:.82rem">\u2B07 Download</a></td>' +
    '</tr>';
  }).join('');
}

function renderGrid(rows) {
  gridView.innerHTML = rows.map(r => {
    const sclass = r[4].includes('test') ? 'badge-test' : 'badge-prod';
    return '<div class="file-card" onclick="window.open(\'' + esc(r[5]) + '\')">' +
      '<div class="card-icon ' + iconClass(r[1]) + '">' + iconLetter(r[1]) + '</div>' +
      '<div class="card-name"><a href="' + esc(r[5]) + '" onclick="event.stopPropagation()">' + esc(r[0]) + '</a></div>' +
      '<div class="card-meta">' +
        '<span class="badge ' + badgeClass(r[1]) + '">' + esc(r[1]) + '</span>' +
        '<span class="badge ' + sclass + '">' + esc(r[4]) + '</span>' +
      '</div>' +
      '<div class="card-meta">' + esc(r[2]) + (r[3] ? ' \u00B7 ' + esc(r[3]) : '') + '</div>' +
    '</div>';
  }).join('');
}

function render() {
  const rows = getFiltered();
  countEl.textContent = rows.length + ' of ' + DATA.length + ' files';
  renderList(rows);
  renderGrid(rows);
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty"><div class="icon">\uD83D\uDCC2</div>No files match your search</div></td></tr>';
    gridView.innerHTML = '<div class="empty"><div class="icon">\uD83D\uDCC2</div>No files match your search</div>';
  }
}

/* ── Sorting ───────────────────────────────────────────── */

function sortBy(col) {
  if (sortCol === col) sortAsc = !sortAsc;
  else { sortCol = col; sortAsc = true; }
  DATA.sort(function (a, b) { var v = a[col].localeCompare(b[col]); return sortAsc ? v : -v; });
  render();
}

/* ── View toggle ───────────────────────────────────────── */

function setView(v) {
  currentView = v;
  document.getElementById('list-view').style.display = v === 'list' ? 'block' : 'none';
  document.getElementById('grid-view').classList.toggle('active', v === 'grid');
  document.getElementById('btn-list').classList.toggle('active', v === 'list');
  document.getElementById('btn-grid').classList.toggle('active', v === 'grid');
}

/* ── Sidebar navigation ────────────────────────────────── */

function setFilter(f) {
  currentFilter = f;
  document.querySelectorAll('.nav-item').forEach(function (el) {
    el.classList.toggle('active', el.dataset.filter === f);
  });
  var labels = {
    all: 'Showing all', rom: 'ROMs', firmware: 'Firmware',
    flashtool: 'Flash Tools', flashflow: 'Flash Flows', tools: 'Tools',
    'server-prod': 'Production server', 'server-test': 'Test server'
  };
  crumbEl.textContent = labels[f] || f;
  render();
}

function resetFilter() { setFilter('all'); }

/* ── Sidebar badge counts ──────────────────────────────── */

function updateCounts() {
  var c = { all: DATA.length, rom: 0, firmware: 0, flashtool: 0, flashflow: 0, tools: 0 };
  DATA.forEach(function (r) {
    var l = r[1].toLowerCase();
    if (l === 'rom') c.rom++;
    else if (l === 'firmware') c.firmware++;
    else if (l.includes('flashtool')) c.flashtool++;
    else if (l.includes('flashflow')) c.flashflow++;
    else if (l.includes('tool')) c.tools++;
  });
  for (var k in c) {
    var el = document.getElementById('nav-' + k);
    if (el) el.textContent = c[k];
  }
}

/* ── Initialisation ────────────────────────────────────── */

document.querySelectorAll('.nav-item').forEach(function (el) {
  el.addEventListener('click', function () { setFilter(el.dataset.filter); });
});
searchBox.addEventListener('input', render);

updateCounts();
render();
