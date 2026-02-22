# huawei-hg8145v5

Python web crawler for the Huawei HG8145V5 router administration interface.

Authenticates to the router web UI, crawls all accessible admin pages, and
downloads every resource (HTML/ASP pages, JavaScript, CSS, images, etc.)
preserving the original directory structure so the site can be browsed offline
for code analysis.

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
| `--max-depth` | `10` | Maximum link-following depth |
| `--delay` | `0.5` | Delay between HTTP requests (seconds) |

## How it works

1. **Login** – The crawler replicates the authentication flow found in
   `index.asp`:
   - Loads `/index.asp` to initialise the HTTP session.
   - POSTs to `/asp/GetRandCount.asp` to obtain a CSRF token.
   - POSTs credentials (password is Base64-encoded) to `/login.cgi`.
2. **Crawl** – Starting from a set of known router pages, it recursively
   discovers new URLs by parsing HTML/ASP content for `<a>`, `<script>`,
   `<link>`, `<img>`, `<frame>` tags, inline `url()` references, and
   JavaScript patterns such as `setAction()`, `$.ajax`, and
   `window.location`.
3. **Save** – Every downloaded file is written under the output directory
   using the same path structure as the router web server, producing an
   offline mirror suitable for static analysis.

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
