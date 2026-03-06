# web-crawler

Generic Python web crawler that downloads all reachable pages and static assets
from any website.

Starting from a seed URL, the crawler performs an **exhaustive BFS** (breadth-first
search), downloading every linked page and asset (HTML, JavaScript, CSS, images,
fonts, JSON, XML, …) until no new URLs remain.  Preserves the original server
directory structure on disk for fully-offline browsing and analysis.

## Features

* **Generic** – works with any website (no site-specific authentication)
* **Exhaustive recursive BFS** – continues until the queue is completely empty
* **robots.txt respect** – checks `/robots.txt` before crawling (disable with `--no-robots`)
* **Configurable depth limit** – limit crawl depth with `--depth N`
* **Configurable page limit** – limit total pages with `--max-pages N`
* **Configurable delay** – set delay between requests with `--delay N`
* **AI-powered CAPTCHA solver** – solves CAPTCHAs using GitHub Models vision API (GPT-4o)
* **Lenovo LMSA authentication** – full OAuth flow with automatic CAPTCHA solving
* **Deep link extraction** from every content type:

  | Source | Patterns extracted |
  |--------|--------------------|
  | HTML | `href`, `src`, `action`, `data-src`, `srcset`, inline `<style>`, inline `<script>` |
  | CSS | `url()`, `@import` |
  | JavaScript | `window.location`, `location.href`, `fetch()`, `$.ajax({url:})`, all root-relative `'/...'` string literals, `document.write(...)` |
  | JSON | String values starting with `/` |

* **Resume / skip already-downloaded files** – existing files are loaded from
  disk and parsed for undiscovered links so the crawl continues without
  re-fetching
* **Content deduplication** – identical content is saved only once

## Project structure

```
web_crawler/              # Main Python package
├── __init__.py           # Package version
├── __main__.py           # Entry point: python -m web_crawler
├── cli.py                # CLI argument parsing
├── config.py             # Configuration constants
├── session.py            # HTTP session creation (requests + retry)
├── ai/                   # AI module (GitHub Models + CAPTCHA solver)
│   ├── __init__.py
│   ├── github_models.py  # GitHub Models API client (OpenAI SDK, vision)
│   └── captcha_solver.py # Playwright-based CAPTCHA solver
├── auth/                 # Authentication submodule
│   ├── lenovo_id.py      # Lenovo ID OAuth (WUST → JWT) with AI CAPTCHA
│   └── lmsa.py           # LMSA session management
├── extraction/           # Link extraction submodule
│   ├── __init__.py
│   ├── css.py            # CSS url() and @import extraction
│   ├── html_parser.py    # HTML attribute extraction (BeautifulSoup)
│   ├── javascript.py     # Deep JS path extraction
│   ├── json_extract.py   # JSON value path extraction
│   └── links.py          # Master dispatcher
├── core/                 # Core crawler submodule
│   ├── __init__.py
│   ├── crawler.py        # BFS Crawler class
│   └── storage.py        # File I/O and local path mapping
└── utils/                # Utility submodule
    ├── __init__.py
    ├── log.py            # Coloured logging setup
    └── url.py            # URL normalisation and deduplication
tests/                    # Unit tests
├── test_ai.py            # AI module + CAPTCHA integration tests
├── test_crawler.py       # Crawler tests
├── test_extraction.py    # Link extraction tests
└── test_url.py           # URL normalisation tests
```

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt

# Or install as a package (includes optional tqdm and colorlog):
pip install -e ".[ui]"

# For AI CAPTCHA solving (optional):
pip install -e ".[ai]"
playwright install chromium
```

## Usage

```bash
# Basic crawl
python -m web_crawler https://example.com

# With depth limit
python -m web_crawler https://example.com --depth 3

# Custom output directory
python -m web_crawler https://example.com --output my_site

# Limit number of pages
python -m web_crawler https://example.com --max-pages 100

# Custom delay between requests (be polite!)
python -m web_crawler https://example.com --delay 1.0

# Ignore robots.txt
python -m web_crawler https://example.com --no-robots

# Force re-download even if files already exist
python -m web_crawler https://example.com --force

# Verbose debug output
python -m web_crawler https://example.com --debug

# Disable SSL verification (for self-signed certs)
python -m web_crawler https://example.com --no-verify-ssl
```

### AI CAPTCHA Solving + Lenovo LMSA Authentication

The crawler can authenticate with Lenovo's LMSA service using **Ulixee Hero** browser automation (superior Akamai bypass) and automatically solve CAPTCHAs using the **GitHub Models** vision API (GPT-4o). This is required for crawling `rsddownload-secure.lenovo.com` (private S3 bucket).

**Prerequisites:**
1. **Node.js** (v16+) and **npm** — required for Ulixee Hero browser
   - Install from https://nodejs.org/ or via package manager
   - Run `npm install` to install Hero dependencies
2. A **GitHub Personal Access Token** (optional, for AI CAPTCHA solving) — create at
   https://github.com/settings/tokens (enable the **Models** permission if prompted)
3. **Playwright** + Chromium (optional fallback) — `pip install playwright && playwright install chromium`

**⚠️ NEVER hardcode credentials in source code or command-line history.**
Use environment variables or source from a secure `.env` file instead:

```bash
# Step 1: Install Hero browser dependencies
npm install

# Step 2: Create a .env file (make sure it's in .gitignore!)
cat > .env << 'EOF'
export GITHUB_TOKEN="ghp_your_token_here"
export LMSA_EMAIL="your_email@example.com"
export LMSA_PASSWORD="your_password_here"
EOF
chmod 600 .env

# Step 3: Source the env file and run
source .env
python -m web_crawler "https://rsddownload-secure.lenovo.com/" \
  --lmsa-email "$LMSA_EMAIL" \
  --lmsa-password "$LMSA_PASSWORD" \
  --ai-captcha \
  --ai-model "openai/gpt-4o" \
  --debug \
  --output ./lenovo_firmware

# Or even shorter (reads from env vars automatically):
python -m web_crawler "https://rsddownload-secure.lenovo.com/" \
  --ai-captcha --debug --output ./lenovo_firmware
```

**What happens:**
1. The crawler fetches the OAuth login URL from `lsa.lenovo.com`
2. Launches **Ulixee Hero** browser (Node.js-based, advanced Akamai bypass)
3. Hero navigates to `passport.lenovo.com` with full TLS and browser fingerprinting evasion
4. Fills in your Lenovo ID credentials using realistic timing patterns
5. If a CAPTCHA appears → screenshots it → sends to GitHub Models GPT-4o vision API → fills in the solution
6. Captures the WUST token from the redirect
7. Exchanges WUST for a JWT at `lsa.lenovo.com`
8. Uses the JWT to generate pre-signed S3 URLs for firmware downloads
9. Crawls and downloads all discovered files

**Fallback chain:** Hero → zendriver → Playwright → plain HTTP (automatic)

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `url` | *(required)* | Target URL to crawl |
| `--output` | `downloaded_site` | Local output directory |
| `--depth` | `0` (unlimited) | Maximum crawl depth |
| `--max-pages` | `0` (unlimited) | Maximum number of pages to download |
| `--delay` | `0.25` | Delay between requests in seconds |
| `--no-verify-ssl` | off | Disable TLS certificate verification |
| `--no-robots` | off | Ignore robots.txt restrictions |
| `--force` | off | Re-download files even if they exist on disk |
| `--debug` | off | Verbose logging |
| `--ai-captcha` | off | Enable AI CAPTCHA solving (requires `GITHUB_TOKEN`) |
| `--ai-model` | `openai/gpt-4o` | GitHub Models vision model to use |
| `--ai-captcha-type` | `auto` | CAPTCHA type: `auto`, `numbersOnly`, `lettersOnly` |
| `--ai-captcha-url` | *(target URL)* | Override CAPTCHA page URL |
| `--ai-login-user` | | Username for standalone CAPTCHA login |
| `--ai-login-pass` | | Password for standalone CAPTCHA login |
| `--lmsa-email` | `$LMSA_EMAIL` | Lenovo ID email |
| `--lmsa-password` | `$LMSA_PASSWORD` | Lenovo ID password |
| `--lmsa-wust` | | Pre-obtained WUST token (skip OAuth) |
| `--lmsa-jwt` | | Pre-obtained JWT as `GUID:TOKEN` (skip all auth) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub PAT with `models` scope (for AI CAPTCHA) |
| `LMSA_EMAIL` | Lenovo ID email (alternative to `--lmsa-email`) |
| `LMSA_PASSWORD` | Lenovo ID password (alternative to `--lmsa-password`) |
| `AI_MODEL` | Override default AI model (alternative to `--ai-model`) |

## Running tests

```bash
# All tests
python -m unittest discover -s tests -v

# AI module tests only
python -m unittest tests.test_ai -v
```

## Output structure (example)

```
downloaded_site/
├── index.html
├── about.html
├── css/
│   └── style.css
├── js/
│   └── main.js
├── images/
│   ├── logo.png
│   └── banner.jpg
└── blog/
    ├── index.html
    └── post-1.html
```

> **Note:** Please be respectful when crawling websites. Always check
> `robots.txt`, use appropriate delays between requests, and avoid
> overwhelming servers. The `--delay` flag (default 0.25s) helps prevent
> excessive load on the target server.
