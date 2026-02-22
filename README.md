# huawei-hg8145v5

Python crawler for the Huawei HG8145V5 router admin web interface.

Logs into the router at `http://192.168.100.1`, then **exhaustively crawls
every reachable admin page and static asset** (HTML/ASP, JavaScript, CSS,
images, fonts, JSON, XML, …) until no new URLs remain.  Preserves the
original server directory structure on disk for fully-offline code analysis.

## Features

* **Two-step authenticated login** – replicates the router's anti-CSRF token
  flow (POST to `/asp/GetRandCount.asp`, then POST to `/login.cgi` with a
  Base64-encoded password)
* **Dynamic cookie management** – session cookies are automatically tracked;
  pre-login cookies are cleared before authentication (mirroring the browser's
  `LoginSubmit()` behaviour) to prevent duplicate cookie entries that cause
  session-expiry loops
* **Post-login session validation** – the follow-up redirect after login is
  checked to ensure the session is genuinely active before crawling begins
* **Defensive token refresh** – the `X_HW_Token` refresh endpoint is guarded
  against responses that would invalidate the session cookie
* **Exhaustive recursive BFS** – continues until the queue is completely empty
* **Deep link extraction** from every content type:

  | Source | Patterns extracted |
  |--------|--------------------|
  | HTML / ASP | `href`, `src`, `action`, `data-src`, `srcset`, inline `<style>`, inline `<script>` |
  | CSS | `url()`, `@import` |
  | JavaScript | `Form.setAction()`, `$.ajax({url:})`, `window.location`, `location.href`, all root-relative `'/...'` string literals, `RequestFile=` in CGI query strings, `document.write(...)` |

* **ASP responses treated as HTML** regardless of the `Content-Type` header
* **Resume / skip already-downloaded files** – existing files are loaded from
  disk and parsed for undiscovered links so the crawl continues without
  re-fetching

## Project structure

```
huawei_crawler/           # Main Python package
├── __init__.py           # Package version
├── __main__.py           # Entry point: python -m huawei_crawler
├── cli.py                # CLI argument parsing
├── config.py             # Configuration constants
├── auth/                 # Authentication submodule
│   ├── __init__.py
│   ├── login.py          # Login flow, password encoding, cookie management
│   └── session.py        # Session creation and expiry detection
├── extraction/           # Link extraction submodule
│   ├── __init__.py
│   ├── css.py            # CSS url() and @import extraction
│   ├── html_parser.py    # HTML/ASP attribute extraction (BeautifulSoup)
│   ├── javascript.py     # Deep JS path extraction (10+ regex patterns)
│   ├── json_extract.py   # JSON value path extraction
│   └── links.py          # Master dispatcher
├── core/                 # Core crawler submodule
│   ├── __init__.py
│   ├── crawler.py        # BFS Crawler class with session management
│   └── storage.py        # File I/O and local path mapping
└── utils/                # Utility submodule
    ├── __init__.py
    ├── log.py            # Coloured logging setup
    └── url.py            # URL normalisation and deduplication
tests/                    # Unit tests
├── test_auth.py          # Authentication and session tests
├── test_extraction.py    # Link extraction tests
└── test_url.py           # URL normalisation tests
crawler.py                # Original single-file crawler (reference)
```

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt

# Or install as a package (includes optional tqdm and colorlog):
pip install -e ".[ui]"
```

## Usage

```bash
# Using the package (recommended)
python -m huawei_crawler --password YOUR_PASSWORD

# Using the original single-file crawler
python crawler.py --password YOUR_PASSWORD

# Password via environment variable (recommended – avoids shell history)
set ROUTER_PASSWORD=your_password_here   # Windows
export ROUTER_PASSWORD=your_password_here  # Linux / macOS
python -m huawei_crawler

# All options explicit
python -m huawei_crawler --host 192.168.100.1 --user Mega_gpon \
    --password your_password_here --output downloaded_site

# Verbose debug output (shows every cookie, every new URL enqueued)
python -m huawei_crawler --debug

# Force re-download even if files already exist
python -m huawei_crawler --force
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `192.168.100.1` | Router IP address |
| `--user` | `Mega_gpon` | Admin username |
| `--password` | *(env / prompt)* | Admin password |
| `--output` | `downloaded_site` | Local output directory |
| `--no-verify-ssl` | off | Disable TLS verification (for self-signed certs) |
| `--force` | off | Re-download files even if they exist on disk |
| `--debug` | off | Verbose logging (cookies, queued URLs, byte counts) |

## Running tests

```bash
python -m unittest discover -s tests -v
```

## How the login works

The router login page (`index.asp`) uses a two-step flow:

1. `GET /index.asp` – router sets initial session cookies
2. `POST /asp/GetRandCount.asp` – returns a one-time anti-CSRF token
3. `POST /login.cgi` with:
   - `UserName` = your username
   - `PassWord` = `Base64(UTF-8(password))`  *(replicated from `util.js`)*
   - `Language` = `english`
   - `x.X_HW_Token` = token from step 2
   - Cookie `Cookie=body:Language:english:id=-1;path=/`  *(replicated from login page JS)*

### Session fix details

The original crawler suffered from an infinite session-expiry / re-login loop
because:

1. **Duplicate cookies** – the `requests` library accumulated multiple `Cookie`
   entries (one manually set, one from the server response) with different
   internal domain representations, confusing the router.
2. **Immediate token refresh** – calling `GetRandToken.asp` right after login
   could reset the session cookie before any page was crawled.
3. **No post-login validation** – the crawler assumed login succeeded without
   checking whether the follow-up request actually returned an admin page.

These issues are fixed by:
- Clearing all cookies before setting the pre-login cookie (mirroring the
  browser's `LoginSubmit()` behaviour)
- Deduplicating `Cookie` entries after the login response
- Validating the follow-up redirect target
- Deferring token refresh to the heartbeat mechanism
- Saving and restoring cookies around token refresh calls

## Output structure (example)

```
downloaded_site/
├── index.asp
├── login.asp
├── main.asp
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
├── frameaspdes/
│   └── english/
│       └── ssmpdes.js
├── html/
│   └── ssmp/
│       ├── home.asp
│       ├── wlan.asp
│       ├── lan.asp
│       └── ...
└── images/
    └── hwlogo.ico
```

## Default credentials (from router label)

| Field | Value |
|-------|-------|
| User  | `Mega_gpon` |
| Password | *(see router label)* |

> **Security notice:** The router ships with a default password printed on its
> label.  Change both the admin password and the Wi-Fi passphrase before
> connecting the device to untrusted networks.  Never commit real passwords to
> public repositories.
>
> You can supply the password securely via the `ROUTER_PASSWORD` environment
> variable or the `--password` flag (which will prompt if omitted).
