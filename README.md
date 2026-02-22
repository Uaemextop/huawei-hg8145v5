# huawei-hg8145v5

Python crawler for the Huawei HG8145V5 router admin web interface.

Logs into the router at `http://192.168.100.1`, crawls all admin pages and
downloads every reachable file (HTML/ASP, JavaScript, CSS, images, fonts, …)
preserving the original server directory structure.  The result is a local
offline copy of the interface suitable for static code analysis.

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Default settings (host 192.168.100.1, user Mega_gpon, prompts for password)
python crawler.py

# Supply password via environment variable (recommended)
ROUTER_PASSWORD=your_password_here python crawler.py

# Explicit flags
python crawler.py --host 192.168.100.1 --user Mega_gpon --password your_password_here --output downloaded_site

# Verbose debug output
python crawler.py --debug
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `192.168.100.1` | Router IP address |
| `--user` | `Mega_gpon` | Admin username |
| `--password` | `796cce597901a5cf` | Admin password |
| `--output` | `downloaded_site` | Local output directory |
| `--debug` | off | Enable verbose logging |

## How it works

1. **Login** – replicates the two-step authentication used by the router:
   - POST to `/asp/GetRandCount.asp` to obtain an anti-CSRF token (`x.X_HW_Token`).
   - POST to `/login.cgi` with the username, Base64-encoded password, and the token.
2. **Crawl** – starts from a seed list of known admin pages (`/index.asp`,
   `/main.asp`, `/frame.asp`, …) and follows every link found in HTML, CSS,
   and JavaScript responses.
3. **Save** – writes each downloaded resource to a local path that mirrors the
   server's directory structure (e.g. `/Cuscss/login.css` →
   `downloaded_site/Cuscss/login.css`).

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
└── frameaspdes/
    └── english/
        └── ssmpdes.js
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
