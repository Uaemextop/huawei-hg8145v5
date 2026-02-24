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

## Running tests

```bash
python -m unittest discover -s tests -v
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
