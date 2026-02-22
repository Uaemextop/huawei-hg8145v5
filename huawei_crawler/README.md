# Huawei Crawler Package

A modular Python package for crawling Huawei HG8145V5 router admin interfaces.

## Package Structure

```
huawei_crawler/
├── __init__.py          # Package initialization
├── __main__.py          # Entry point for python -m huawei_crawler
├── cli.py               # Command-line interface
├── auth/                # Authentication module
│   ├── __init__.py
│   ├── login.py         # Login functions (base64, PBKDF2+SHA256)
│   └── session.py       # Session validation and expiry detection
├── network/             # Network operations module
│   ├── __init__.py
│   └── client.py        # HTTP session setup with retry logic
├── parser/              # Content parsing module
│   ├── __init__.py
│   └── extractor.py     # Link extraction from HTML/JS/CSS/JSON
└── crawler/             # Core crawler module
    ├── __init__.py
    ├── core.py          # Main Crawler class with BFS logic
    └── utils.py         # URL normalization and file operations
```

## Usage

### As a Package

```python
from huawei_crawler import Crawler
from pathlib import Path

crawler = Crawler(
    host="192.168.100.1",
    username="Mega_gpon",
    password="your_password",
    output_dir=Path("downloaded_site"),
    verify_ssl=True,
    force=False
)
crawler.run()
```

### As a Command-Line Tool

```bash
# Using the module
python -m huawei_crawler --password your_password

# Using the legacy script (backward compatible)
python crawler.py --password your_password

# With all options
python -m huawei_crawler \\
    --host 192.168.100.1 \\
    --user Mega_gpon \\
    --password your_password \\
    --output downloaded_site \\
    --debug
```

## Modules

### `auth` - Authentication

- **login.py**: Handles router authentication with auto-detection of login method (base64 or PBKDF2+SHA256)
- **session.py**: Validates session state and detects session expiry

### `network` - Network Operations

- **client.py**: Configures HTTP sessions with retry logic, keep-alive, and browser-like headers

### `parser` - Content Parsing

- **extractor.py**: Extracts URLs from HTML, JavaScript, CSS, and JSON content

### `crawler` - Core Crawler

- **core.py**: Main Crawler class implementing BFS-based recursive crawling
- **utils.py**: URL normalization, file path mapping, and content deduplication

### `cli` - Command-Line Interface

- **cli.py**: Argument parsing and logging configuration

## Features

- **Modular Design**: Clean separation of concerns across authentication, networking, parsing, and crawling
- **Auto Re-authentication**: Detects session expiry and automatically re-logs in
- **Resume Support**: Skips already-downloaded files and continues from where it left off
- **Deep Link Extraction**: Comprehensive URL extraction from all content types
- **Session Keep-Alive**: Maintains long-running sessions with heartbeat mechanism
- **Progress Tracking**: Optional tqdm progress bar with live statistics

## Development

The package is designed for easy extension:

1. **Add new authentication methods**: Extend `auth/login.py`
2. **Add new content parsers**: Extend `parser/extractor.py`
3. **Customize crawling behavior**: Modify `crawler/core.py`
4. **Add new CLI options**: Update `cli.py`
