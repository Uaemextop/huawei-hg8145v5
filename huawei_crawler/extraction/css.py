"""
CSS URL extraction helpers.
"""

import re

from huawei_crawler.utils.url import normalise_url

_CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^)'">\s]+)['"]?\s*\)""", re.I)
_CSS_IMPORT_RE = re.compile(r"""@import\s+['"]([^'"]+)['"]""", re.I)


def extract_css_urls(css: str, page_url: str, base: str) -> set[str]:
    """Extract all URLs from CSS ``url()`` and ``@import`` statements."""
    found: set[str] = set()
    for pat in (_CSS_URL_RE, _CSS_IMPORT_RE):
        for m in pat.finditer(css):
            n = normalise_url(m.group(1), page_url, base)
            if n:
                found.add(n)
    return found
