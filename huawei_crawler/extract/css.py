"""
huawei_crawler.extract.css
===========================
Extracts URLs from CSS content (``url()`` references and ``@import`` rules).
"""

import re

_CSS_URL_RE    = re.compile(r"""url\(\s*['"]?([^)'">\s]+)['"]?\s*\)""", re.I)
_CSS_IMPORT_RE = re.compile(r"""@import\s+['"]([^'"]+)['"]""", re.I)


def extract_css_urls(css: str, page_url: str, base: str, normalise) -> set:
    """
    Return a set of absolute URLs found in *css* text.

    Parameters
    ----------
    css       : Raw CSS text.
    page_url  : Absolute URL of the CSS file (used for relative resolution).
    base      : Base URL of the router (e.g. ``http://192.168.100.1``).
    normalise : Callable ``(raw, page_url, base) -> str | None`` that converts
                a raw URL string to an absolute, normalised URL.
    """
    found: set = set()
    for pat in (_CSS_URL_RE, _CSS_IMPORT_RE):
        for m in pat.finditer(css):
            n = normalise(m.group(1), page_url, base)
            if n:
                found.add(n)
    return found
