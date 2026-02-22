"""
huawei_crawler.extract.js
==========================
Extracts resource URLs from JavaScript source code.

Covers:
* Explicit navigation (window.location, Form.setAction, fetch, $.ajax)
* All root-relative quoted strings
* Relative paths with known web extensions
* Template literals (static prefix)
* Object / array literals containing paths
* Variable assignments
* Huawei-specific concatenation prefixes (``'/html/ssmp/' + pageName``)
* ``RequestFile=`` CGI parameter values
* ``document.write()`` nested markup (recursed through HTML extractor)
"""

import re

# window.location / location.href
_WIN_LOC_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href|location\.replace)\s*[=(]\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# Form.setAction('/path')
_FORM_ACTION_RE = re.compile(
    r"""\.setAction\s*\(\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# $.ajax({ url: '...' }) / fetch('...') / axios.get('...')
_AJAX_URL_RE = re.compile(
    r"""(?:['"]url['"]\s*:|url\s*:|fetch\s*\(|axios\.(?:get|post)\s*\()\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# document.write(...)
_DOC_WRITE_RE = re.compile(
    r"""document\.write\s*\(\s*['"`](.+?)['"`]""",
    re.I | re.DOTALL,
)

# RequestFile=login.asp embedded in CGI query strings
_REQUEST_FILE_RE = re.compile(
    r"""RequestFile=([^&'">\s\n]+)""",
    re.I,
)

# All root-relative quoted path strings: '/anything/here'
_ABS_QUOTED_PATH_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Relative paths with a known web extension
_REL_EXT_PATH_RE = re.compile(
    r"""['"`]([.]{0,2}/[a-zA-Z0-9_\-./]+\.(?:asp|html|htm|cgi|js|css|png|jpg|jpeg|gif|ico|svg|json|xml|woff2?|ttf|eot|otf|bmp|webp))['"`]""",
    re.I,
)

# Template literals: `/html/ssmp/${name}.asp`
_TEMPLATE_PATH_RE = re.compile(
    r"""`(/[a-zA-Z0-9_/.-]+(?:\$\{[^}]+\}[a-zA-Z0-9_/.-]*)*)`""",
    re.I,
)

# Object / array literal paths: { url: '/path' } or ['/path1', '/path2']
_OBJ_PROP_PATH_RE = re.compile(
    r"""[\[,{]\s*['"`](/[a-zA-Z0-9_./%?&=+\-][^'"`\n]{0,150})['"`]\s*[,\]}]""",
    re.I,
)

# var/let/const  varName = '/path'
_VAR_ASSIGN_RE = re.compile(
    r"""(?:var|let|const)\s+\w+\s*=\s*['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Huawei-specific: '/html/ssmp/' + pageName + '.asp'
_CONCAT_PREFIX_RE = re.compile(
    r"""['"`](/html/[a-zA-Z0-9_/]+/)['"`]\s*\+""",
    re.I,
)


def extract_js_paths(js: str, page_url: str, base: str, normalise, extract_html_attrs) -> set:
    """
    Exhaustively extract every URL/path reference from JavaScript source.

    Parameters
    ----------
    js               : Raw JavaScript text.
    page_url         : Absolute URL of the JS file (for relative resolution).
    base             : Router base URL.
    normalise        : URL normalisation callable.
    extract_html_attrs : HTML attribute extraction callable (for document.write).
    """
    found: set = set()

    def _add(raw: str) -> None:
        # Skip strings containing template interpolation or embedded quotes.
        if "${" in raw or "'" in raw or '"' in raw:
            return
        n = normalise(raw.strip(), page_url, base)
        if n:
            found.add(n)

    for pat in (
        _WIN_LOC_RE,
        _FORM_ACTION_RE,
        _AJAX_URL_RE,
        _ABS_QUOTED_PATH_RE,
        _REL_EXT_PATH_RE,
        _OBJ_PROP_PATH_RE,
        _VAR_ASSIGN_RE,
        _CONCAT_PREFIX_RE,
    ):
        for m in pat.finditer(js):
            _add(m.group(1))

    # Template literals – queue the static prefix
    for m in _TEMPLATE_PATH_RE.finditer(js):
        raw = re.sub(r"\$\{[^}]+\}", "", m.group(1))
        _add(raw)

    # document.write – treat written markup as HTML
    for m in _DOC_WRITE_RE.finditer(js):
        snippet = m.group(1).replace("\\'", "'").replace('\\"', '"')
        found |= extract_html_attrs(snippet, page_url, base)

    # RequestFile= in any CGI action string
    for m in _REQUEST_FILE_RE.finditer(js):
        val = m.group(1)
        if not val.startswith("/"):
            val = "/" + val
        _add(val)

    return found
