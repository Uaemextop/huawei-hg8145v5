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
  if the session expires mid-crawl the script re-authenticates and retries
* **Exhaustive recursive BFS** – continues until the queue is completely empty
* **Deep link extraction** from every content type:

  | Source | Patterns extracted |
  |--------|--------------------|
  | HTML / ASP | `href`, `src`, `action`, `data-src`, `srcset`, inline `<style>`, inline `<script>` |
  | CSS | `url()`, `@import` |
  | JavaScript | `Form.setAction()`, `$.ajax({url:})`, `window.location`, `location.href`, all root-relative `'/...'` string literals, `RequestFile=` in CGI query strings, `document.write(...)` |

* **Seed list of 60+ known HG8145V5 paths** (admin menus, status pages, WAN,
  WLAN, LAN, security, QoS, voice, TR-069, system, …)
* **ASP responses treated as HTML** regardless of the `Content-Type` header

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Prompts for password if not set in environment
python crawler.py

# Password via environment variable (recommended – avoids shell history)
set ROUTER_PASSWORD=your_password_here   # Windows
export ROUTER_PASSWORD=your_password_here  # Linux / macOS
python crawler.py

# All options explicit
python crawler.py --host 192.168.100.1 --user Mega_gpon \
    --password your_password_here --output downloaded_site

# Verbose debug output (shows every cookie, every new URL enqueued)
python crawler.py --debug
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `192.168.100.1` | Router IP address |
| `--user` | `Mega_gpon` | Admin username |
| `--password` | *(env / prompt)* | Admin password |
| `--output` | `downloaded_site` | Local output directory |
| `--no-verify-ssl` | off | Disable TLS verification (for self-signed certs) |
| `--debug` | off | Verbose logging (cookies, queued URLs, byte counts) |

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

A successful login redirects to the main admin frame; if the login form is
returned again the credentials are incorrect.

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
