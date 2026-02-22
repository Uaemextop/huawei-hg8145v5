"""
JavaScript deep URL/path extraction.
"""

import re

from huawei_crawler.utils.url import normalise_url

# window.location = "..." or window.location.href = "..."
_WIN_LOC_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href|location\.replace)\s*[=(]\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# Form.setAction('/some/path.cgi?params')
_FORM_ACTION_RE = re.compile(
    r"""\.setAction\s*\(\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# $.ajax({ url: '/path', ... }) / fetch('/path') / axios.get('/path')
_AJAX_URL_RE = re.compile(
    r"""(?:['"]url['"]\s*:|url\s*:|fetch\s*\(|axios\.(?:get|post)\s*\()\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# document.write('<tag src="/path/to/file.js">')
_DOC_WRITE_RE = re.compile(
    r"""document\.write\s*\(\s*['"`](.+?)['"`]""",
    re.I | re.DOTALL,
)

# RequestFile=login.asp
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

# Template literals with simple paths
_TEMPLATE_PATH_RE = re.compile(
    r"""`(/[a-zA-Z0-9_/.-]+(?:\$\{[^}]+\}[a-zA-Z0-9_/.-]*)*)` """,
    re.I,
)

# JS object / array literal paths
_OBJ_PROP_PATH_RE = re.compile(
    r"""[\[,{]\s*['"`](/[a-zA-Z0-9_./%?&=+\-][^'"`\n]{0,150})['"`]\s*[,\]}]""",
    re.I,
)

# var/let/const  varName = '/path'
_VAR_ASSIGN_RE = re.compile(
    r"""(?:var|let|const)\s+\w+\s*=\s*['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Huawei-specific: string concatenation   '/html/ssmp/' + pageName + '.asp'
_CONCAT_PREFIX_RE = re.compile(
    r"""['"`](/html/[a-zA-Z0-9_/]+/)['"`]\s*\+""",
    re.I,
)


def extract_js_paths(js: str, page_url: str, base: str) -> set[str]:
    """
    Exhaustively extract every URL/path reference from JavaScript source.
    """
    found: set[str] = set()

    def _add(raw: str) -> None:
        if "${" in raw or "'" in raw or '"' in raw:
            return
        n = normalise_url(raw.strip(), page_url, base)
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

    for m in _TEMPLATE_PATH_RE.finditer(js):
        raw = re.sub(r"\$\{[^}]+\}", "", m.group(1))
        _add(raw)

    for m in _DOC_WRITE_RE.finditer(js):
        snippet = m.group(1).replace("\\'", "'").replace('\\"', '"')
        from huawei_crawler.extraction.html_parser import extract_html_attrs
        found |= extract_html_attrs(snippet, page_url, base)

    for m in _REQUEST_FILE_RE.finditer(js):
        val = m.group(1)
        if not val.startswith("/"):
            val = "/" + val
        _add(val)

    return found
