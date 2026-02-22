# huawei-hg8145v5

Huawei HG8145V5 router web crawler written in Python.

Logs in to the router admin interface and crawls all reachable pages and
static assets (HTML, JS, CSS, images, etc.), saving them to disk using the
**same directory structure** as the original web server.  The result is an
offline copy that can be browsed locally for code analysis.

---

## Requirements

- Python 3.7 or newer
- pip packages listed in `requirements.txt`

```
pip install -r requirements.txt
```

---

## Quick start

```bash
# Default settings (host 192.168.100.1, user Mega_gpon) – prompts for password
python crawler.py

# Supply password via environment variable (recommended)
set ROUTER_PASSWORD=your_password   # Windows
python crawler.py

# Or pass it directly on the command line
python crawler.py --host 192.168.100.1 --user Mega_gpon --password your_password

# Save to a specific folder
python crawler.py --output ./offline_site

# Verbose / debug output
python crawler.py --verbose
```

---

## Options

| Flag | Default | Description |
|---|---|---|
| `--host` | `192.168.100.1` | Router IP or hostname |
| `--user` | `Mega_gpon` | Admin username |
| `--password` | *(prompted)* | Admin password (or set `ROUTER_PASSWORD` env var) |
| `--output` | `router_site` | Output directory |
| `--timeout` | `15` | Request timeout in seconds |
| `--delay` | `0.3` | Delay between requests (seconds) |
| `--verbose` / `-v` | off | Enable debug logging |

---

## How it works

1. **Login** – fetches `/index.asp` to obtain session cookies, then gets an
   anti-CSRF token from `/asp/GetRandCount.asp`, and finally POSTs the
   credentials (password Base64-encoded) to `/login.cgi`.
2. **Crawl** – performs a breadth-first crawl starting from the router root,
   following links found in HTML, JS `src` attributes, CSS `href` attributes,
   inline script strings, and more.
3. **Save** – each resource is saved under `--output` preserving the original
   URL path (e.g. `/resource/common/util.js` →
   `router_site/resource/common/util.js`).

---

## Output structure (example)

```
router_site/
├── index.html          ← router root
├── index.asp           ← login page
├── Cuscss/
│   ├── login.css
│   └── english/
│       └── frame.css
├── resource/
│   └── common/
│       ├── md5.js
│       ├── util.js
│       └── jquery.min.js
├── frameaspdes/
│   └── english/
│       └── ssmpdes.js
└── ...
```
