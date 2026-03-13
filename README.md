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
* **Configurable delay** – set delay between requests with `--delay N`
* **Concurrent downloads** – parallel workers auto-tuned by CPU/RAM or set with `--concurrency N`
* **Cloudflare bypass** – supports `cf_clearance` cookies and `curl_cffi` TLS fingerprinting
* **WAF/CAPTCHA detection** – detects Cloudflare, SiteGround, and generic WAF signatures
* **Technology detection** – identifies CMS, frameworks, CDNs, and protection systems
* **Plugin architecture** – extensible via auto-discovered plugins
* **Deep link extraction** from every content type:

  | Source | Patterns extracted |
  |--------|--------------------|
  | HTML | `href`, `src`, `action`, `data-src`, `srcset`, inline `<style>`, inline `<script>` |
  | CSS | `url()`, `@import` |
  | JavaScript | `window.location`, `location.href`, `fetch()`, `$.ajax({url:})`, root-relative `'/...'` literals, `document.write(...)` |
  | JSON | String values starting with `/` |

* **Cloud storage link detection** – Google Drive, Mega, OneDrive, and other platforms
* **Resume / skip already-downloaded files** – existing files are loaded from
  disk and parsed for undiscovered links so the crawl continues without
  re-fetching
* **Content deduplication** – identical content is saved only once
* **HTML index generator** – generates a browsable file index for GitHub Pages

## Project structure

```
web_crawler/                # Main Python package
├── __init__.py             # Package version (3.0.0)
├── __main__.py             # Entry point: python -m web_crawler
├── cli.py                  # CLI argument parsing
├── config/
│   └── settings.py         # Configuration constants
├── core/
│   ├── engine.py           # BFS Crawler class (main crawling engine)
│   └── storage.py          # File I/O and local path mapping
├── detection/              # Technology & protection detection
│   ├── cloudflare.py       # Cloudflare detection
│   ├── siteground.py       # SiteGround detection
│   ├── waf.py              # Generic WAF signature detection
│   ├── soft404.py          # Soft-404 detection
│   └── wordpress.py        # WordPress detection
├── extraction/             # Link extraction from multiple content types
│   ├── css.py              # CSS url() and @import extraction
│   ├── html.py             # HTML attribute extraction (BeautifulSoup)
│   ├── javascript.py       # Deep JS path extraction
│   ├── json_extract.py     # JSON value path extraction
│   └── google_drive.py     # Cloud storage link detection
├── session/
│   └── http.py             # HTTP session (retry, UA rotation, CF/SG bypass)
└── utils/
    ├── log.py              # Coloured logging setup
    ├── url.py              # URL normalisation and deduplication
    └── index_generator.py  # HTML file index page generator
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
# Basic crawl
python -m web_crawler https://example.com

# With depth limit
python -m web_crawler https://example.com --depth 3

# Custom output directory
python -m web_crawler https://example.com --output my_site

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

# Download only specific file types
python -m web_crawler https://example.com --download-extensions zip,exe,bin

# Auto-push crawled files to a git repo every 100 files
python -m web_crawler https://example.com --git-push-every 100

# Skip downloading large binaries, record curl commands instead
python -m web_crawler https://example.com --skip-download-exts zip,exe,rar
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `url` | *(required)* | Target URL to crawl |
| `--output` | `downloaded_site` | Local output directory |
| `--depth` | `0` (unlimited) | Maximum crawl depth |
| `--delay` | `0.25` | Delay between requests in seconds |
| `--concurrency` | `auto` | Parallel download workers (`auto` = CPU/RAM-based) |
| `--no-verify-ssl` | off | Disable TLS certificate verification |
| `--no-robots` | off | Ignore robots.txt restrictions |
| `--force` | off | Re-download files even if they exist on disk |
| `--debug` | off | Verbose logging + save `.headers` files |
| `--log-file` | | Write detailed logs to a file |
| `--download-extensions` | `all` | Comma-separated extensions to seek, or `all` |
| `--skip-download-exts` | | Extensions to skip (record curl commands instead) |
| `--skip-media-files` | off | Skip video/audio but record URLs in `video_urls.txt` |
| `--no-external` | off | Don't download media from external CDN hosts |
| `--no-check-captcha` | off | Disable WAF/CAPTCHA detection |
| `--cf-clearance` | | Cloudflare `cf_clearance` cookie for bypass |
| `--git-push-every` | `0` | Push crawled files every N saves (0 = end only) |
| `--upload-extensions` | `all` | Extensions to include in git pushes |

## Output structure (example)

```
downloaded_site/
├── index.html            # Browsable file index (auto-generated)
├── about.html
├── css/
│   └── style.css
├── js/
│   └── main.js
├── images/
│   ├── logo.png
│   └── banner.jpg
├── download_links.txt    # curl/wget commands for skipped files
├── video_urls.txt        # Discovered video/audio URLs
└── blog/
    ├── index.html
    └── post-1.html
```

> **Note:** Please be respectful when crawling websites. Always check
> `robots.txt`, use appropriate delays between requests, and avoid
> overwhelming servers. The `--delay` flag (default 0.25s) helps prevent
> excessive load on the target server.
