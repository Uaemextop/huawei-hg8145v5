# crawl4ai

Unified Python web crawling engine combining an async browser-based crawler
with a general-purpose BFS site downloader and specialised site modules
(HP Support, AMI BIOS, Lenovo RSD, etc.).

## Features

* **Async browser crawler** – Playwright/headless crawling with LLM extraction
* **BFS site downloader** – exhaustive breadth-first file discovery and download
* **50+ technology detectors** – Cloudflare, SiteGround, WordPress, React, Angular, Django, and more
* **Deep link extraction** from HTML, CSS, JavaScript, JSON, and cloud storage
* **WAF/CAPTCHA bypass** – Cloudflare Managed Challenge, SiteGround PoW, header rotation
* **Site-specific modules** – HP Support, AMI BIOS, Lenovo RSD firmware crawlers
* **Content deduplication** by SHA-256 hash
* **Git integration** – periodic commit/push of downloaded files
* **robots.txt respect** with configurable depth and delay

## Project structure

```
crawl4ai/                         # Main Python package
├── __init__.py                   # Async crawler exports
├── async_webcrawler.py           # Core AsyncWebCrawler
├── extensions/                   # Extension modules
│   ├── __init__.py               # Unified exports
│   ├── settings.py               # Configuration constants
│   ├── extraction.py             # Link extraction (HTML, CSS, JS, JSON)
│   ├── storage.py                # File I/O and content hashing
│   ├── downloader.py             # SiteDownloader for site modules
│   ├── url_utils.py              # URL normalisation
│   ├── log_utils.py              # Coloured logging
│   ├── bypass/                   # Session & bypass helpers
│   │   ├── session.py            # HTTP session builder
│   │   ├── cloudflare.py         # CF challenge solver
│   │   └── siteground.py         # SG CAPTCHA solver
│   ├── detection/                # 50+ technology detectors
│   │   ├── base.py               # BaseDetector ABC
│   │   ├── cloudflare.py, waf.py, wordpress.py, ...
│   │   └── react.py, angular.py, django.py, ...
│   ├── handlers/                 # Response handlers
│   │   ├── base.py               # BaseHandler ABC
│   │   ├── spa_renderer.py, cdn_optimizer.py, ...
│   │   └── protection_bypass.py, rate_limiter.py, ...
│   ├── crawler/                  # BFS web crawler engine
│   │   ├── __init__.py           # Exports: Crawler
│   │   ├── engine.py             # Main BFS Crawler class
│   │   ├── cli.py                # CLI entry point
│   │   ├── wordpress.py          # WordPress discovery
│   │   ├── protection.py         # WAF/protection detection
│   │   ├── media.py              # Video/CDN/media handling
│   │   ├── git_ops.py            # Git integration
│   │   ├── models.py             # Data models
│   │   ├── configs.py            # Config dataclasses
│   │   └── handlers.py           # Handler base class
│   └── sites/                    # Site-specific modules
│       ├── base.py               # BaseSiteModule ABC
│       ├── hp_support.py         # HP Support crawler
│       ├── ami_bios.py           # AMI BIOS crawler
│       └── lenovo_rsd.py         # Lenovo RSD crawler
tests/                            # Unit tests
```

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt

# Or install as a package:
pip install -e ".[ui]"
```

## Usage

```bash
# BFS crawler
python -m crawl4ai.extensions.crawler https://example.com

# With depth limit
python -m crawl4ai.extensions.crawler https://example.com --depth 3

# Custom output directory
python -m crawl4ai.extensions.crawler https://example.com --output my_site

# Verbose debug output
python -m crawl4ai.extensions.crawler https://example.com --debug

# Disable SSL verification
python -m crawl4ai.extensions.crawler https://example.com --no-verify-ssl
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `url` | *(required)* | Target URL to crawl |
| `--output` | `downloaded_site` | Local output directory |
| `--depth` | `0` (unlimited) | Maximum crawl depth |
| `--delay` | `0.25` | Delay between requests in seconds |
| `--concurrency` | `auto` | Number of parallel workers |
| `--no-verify-ssl` | off | Disable TLS certificate verification |
| `--no-robots` | off | Ignore robots.txt restrictions |
| `--force` | off | Re-download files even if they exist |
| `--debug` | off | Verbose logging |
| `--git-push-every N` | `0` | Commit/push every N files |
| `--cf-clearance` | | Cloudflare bypass cookie |
| `--extra-hosts` | | Additional download hosts |

## Running tests

```bash
python -m pytest tests/ -v
```

> **Note:** Please be respectful when crawling websites. Always check
> `robots.txt`, use appropriate delays, and avoid overwhelming servers.
