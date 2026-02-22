# huawei-hg8145v5

Python web crawler for the Huawei HG8145V5 router administration interface.

Authenticates to the router web UI, crawls **all** accessible admin pages
dynamically and recursively, and downloads **every** resource (HTML/ASP
pages, JavaScript, CSS, images, etc.) preserving the original directory
structure so the site can be browsed offline for code analysis.

The crawler analyses the content of every downloaded file — HTML, ASP, JS
and CSS — to discover new routes, and keeps crawling until no new resources
are found.

## Requirements

- Python 3.8+
- `requests`
- `beautifulsoup4`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage (defaults: host=192.168.100.1, user=Mega_gpon)
python crawler.py

# Custom options
python crawler.py --host 192.168.100.1 --user Mega_gpon --password 796cce597901a5cf --output router_dump
```

### CLI options

| Option | Default | Description |
|---|---|---|
| `--host` | `192.168.100.1` | Router IP address |
| `--user` | `Mega_gpon` | Login username |
| `--password` | `796cce597901a5cf` | Login password |
| `--output` | `router_dump` | Output directory for downloaded files |
| `--max-depth` | `0` (unlimited) | Maximum link-following depth (0 = crawl everything) |
| `--delay` | `0.5` | Delay between HTTP requests (seconds) |

## How it works

1. **Login** – The crawler replicates the authentication flow found in
   `index.asp`:
   - Loads `/index.asp` to initialise the HTTP session and capture cookies.
   - POSTs to `/asp/GetRandCount.asp` to obtain a CSRF token.
   - POSTs credentials (password is Base64-encoded) to `/login.cgi`.
   - All cookies are captured and maintained automatically throughout the
     crawl.
   - **Session keep-alive**: every 20 requests the session is verified
     with a lightweight check.  If the session expires the crawler
     automatically re-authenticates (up to 3 retries) and continues.
2. **Crawl** – Starting from a set of known router pages, it **dynamically
   and recursively** discovers new URLs by parsing **every** downloaded file
   (HTML, ASP, JS, CSS) for:
   - HTML tags: `<a>`, `<script>`, `<link>`, `<img>`, `<frame>`,
     `<iframe>`, `<form>`, `<embed>`, `<object>`, `<input>`
   - CSS `url()` references
   - JavaScript patterns: `setAction()`, `$.ajax url:`,
     `window.location`, `.href =`, `.src =`, `document.write`
   - Huawei-specific patterns: `RequestFile=`, `loadLanguage()`,
     `getCheckCode.cgi`, `GetRandCount.asp`, `GetRandInfo.asp`
   - String literals that look like router paths (e.g.
     `'/html/status/deviceinformation.asp'`)
   - Bare `.cgi` and `.asp` endpoint references
   The crawler keeps going until the queue is empty — nothing new to find.
3. **Save** – Every downloaded file is written under the output directory
   using the same path structure as the router web server, producing an
   offline mirror suitable for static analysis.
4. **Resume** – On startup the crawler scans the output directory.  Files
   that already exist are **skipped** (not re-downloaded), but their
   content is still parsed for links so newly discovered pages can be
   crawled.  This makes it safe to stop and restart the crawler at any
   time.

## Output structure

```
router_dump/
├── index.asp
├── login.asp
├── Cuscss/
│   ├── login.css
│   └── english/
│       └── frame.css
├── resource/
│   └── common/
│       ├── jquery.min.js
│       ├── md5.js
│       ├── util.js
│       └── ...
├── html/
│   ├── status/
│   ├── network/
│   └── advance/
└── ...
```
