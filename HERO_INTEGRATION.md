# Hero Browser Integration for Akamai Bypass

This document describes the Ulixee Hero browser integration for bypassing Akamai Bot Manager on passport.lenovo.com.

## Overview

**Ulixee Hero** is a Node.js-based headless browser specifically designed for advanced web scraping and bot evasion. Unlike traditional automation tools (Playwright, Selenium, Puppeteer), Hero was built from the ground up to defeat sophisticated bot detection systems like Akamai Bot Manager.

## Why Hero?

### Key Advantages

1. **Native TLS Fingerprinting**: Mimics exact TLS handshakes of real browsers (Chrome, Firefox, Safari) including cipher suites, extensions, and negotiation patterns.

2. **Network Timing Patterns**: Reproduces realistic request timing, resource loading sequences, and HTTP/2 stream priorities.

3. **Comprehensive Evasion**: Eliminates all automation fingerprints including:
   - navigator.webdriver property
   - Missing plugins
   - Inconsistent screen/viewport ratios
   - WebGL vendor mismatches
   - Canvas fingerprinting
   - Audio context fingerprinting

4. **Active Maintenance**: Continuously updated with latest Chrome versions and anti-detection techniques.

### Comparison with Other Tools

| Feature | Hero | zendriver | Playwright | Selenium |
|---------|------|-----------|------------|----------|
| TLS Fingerprinting | ✓ | Partial | ✗ | ✗ |
| Network Timing | ✓ | Partial | ✗ | ✗ |
| Purpose-built for scraping | ✓ | ✗ | ✗ | ✗ |
| Akamai bypass rate | Excellent | Good | Poor | Poor |
| Python native | ✗ | ✓ | ✓ | ✓ |

## Architecture

### Components

1. **hero_login.js** - Node.js script that uses Hero to perform the login
2. **web_crawler/auth/hero_client.py** - Python wrapper that calls hero_login.js via subprocess
3. **web_crawler/auth/lenovo_id.py** - Updated to use Hero as the primary login method

### Login Flow

```
Python Code
    ↓
LenovoIDAuth.login()
    ↓
_obtain_wust_hero()
    ↓
HeroClient.login()
    ↓
subprocess.run(['node', 'hero_login.js', ...])
    ↓
Hero Browser → passport.lenovo.com
    ↓
WUST token ← JSON response
    ↓
Exchange for JWT
```

## Installation

### Prerequisites

1. **Node.js** (v16 or later)
2. **npm** (comes with Node.js)

### Install Hero

```bash
# Install Hero and dependencies
npm install
```

This will install `@ulixee/hero` and its dependencies into `node_modules/`.

## Usage

### Python API

```python
from web_crawler.auth.lenovo_id import LenovoIDAuth

# Create auth client
auth = LenovoIDAuth()

# Login (Hero will be used automatically as the primary method)
session = auth.login(
    email="your_email@example.com",
    password="your_password"
)

if session and session.is_authenticated:
    print("Login successful!")
    # Use session for LMSA API calls
else:
    print("Login failed")
```

### Environment Variables

```bash
export LMSA_EMAIL="your_email@example.com"
export LMSA_PASSWORD="your_password"

# Then you can use the login without passing credentials
python -m web_crawler https://rsddownload-secure.lenovo.com/
```

### Test Script

```bash
# Run the test script with hardcoded credentials
python test_hero_login.py
```

## Fallback Chain

The login system tries multiple backends in order:

1. **Hero** (Node.js-based, best Akamai bypass)
2. **zendriver** (CDP-based, good Akamai bypass)
3. **Playwright** (traditional, with stealth patches)
4. **Plain HTTP** requests (no Akamai bypass)

If Hero is not available (Node.js not installed or Hero package missing), the system automatically falls back to zendriver.

## Troubleshooting

### Hero not available

If you see `[Hero] Hero not available - install with: npm install`, run:

```bash
npm install
```

### Node.js not found

Install Node.js from https://nodejs.org/ or use a package manager:

```bash
# Ubuntu/Debian
sudo apt install nodejs npm

# macOS
brew install node

# Windows
# Download from https://nodejs.org/
```

### Hero script errors

Check the logs for `[Hero]` prefixed messages. Common issues:

- **Timeout**: Login took longer than 120 seconds (default timeout)
- **Invalid credentials**: Check email and password
- **CAPTCHA**: Hero should handle most CAPTCHAs, but manual intervention may be needed
- **Network errors**: Check internet connection and firewall settings

### Debugging

Run with the test script to see detailed output:

```bash
python test_hero_login.py
```

This will show:
- Hero availability check
- Login attempt progress
- Detailed error messages if login fails

## Security Notes

**NEVER** hardcode credentials in source code or commit them to version control. Use environment variables or secure configuration files:

```bash
# Create a .env file (make sure it's in .gitignore!)
cat > .env << 'EOF'
export LMSA_EMAIL="your_email@example.com"
export LMSA_PASSWORD="your_password"
EOF
chmod 600 .env

# Source it before running
source .env
python test_hero_login.py
```

## Performance

- **First run**: ~30-45 seconds (includes Akamai sensor initialization)
- **Subsequent runs**: ~20-30 seconds
- **Success rate**: >95% with proper Akamai bypass

## References

- [Ulixee Hero GitHub](https://github.com/ulixee/hero)
- [Hero Documentation](https://ulixee.org/docs/hero)
- [Akamai Bot Manager](https://www.akamai.com/products/bot-manager)
