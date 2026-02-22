"""JavaScript path extraction from JS source code."""

import re

from ..utils.url import normalise_url

# window.location = "..." or window.location.href = "..."
_WIN_LOC_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href|location\.replace)\s*[=(]\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# Form.setAction('/some/path.cgi?params')  –  router-specific helper
_FORM_ACTION_RE = re.compile(
    r"""\.setAction\s*\(\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# $.ajax({ url: '/path', ... }) / fetch('/path') / axios.get('/path')
_AJAX_URL_RE = re.compile(
    r"""(?:['"]url['"]\s*:|url\s*:|fetch\s*\(|axios\.(?:get|post)\s*\()\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# document.write('<tag src="/path/to/file.js">') — extract nested markup
_DOC_WRITE_RE = re.compile(
    r"""document\.write\s*\(\s*['"`](.+?)['"`]""",
    re.I | re.DOTALL,
)

# RequestFile=login.asp embedded in CGI query strings (Huawei-specific)
_REQUEST_FILE_RE = re.compile(
    r"""RequestFile=([^&'">\s\n]+)""",
    re.I,
)

# All root-relative quoted path strings: '/anything/here'
_ABS_QUOTED_PATH_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Relative paths with a known web extension (catches 'wlan.asp', '../images/x.jpg', etc.)
_REL_EXT_PATH_RE = re.compile(
    r"""['"`]([.]{0,2}/[a-zA-Z0-9_\-./]+\.(?:asp|html|htm|cgi|js|css|png|jpg|jpeg|gif|ico|svg|json|xml|woff2?|ttf|eot|otf|bmp|webp))['"`]""",
    re.I,
)

# Template literals that contain only a simple path: `/html/ssmp/${name}.asp`
# Extracts the static prefix up to the first interpolation marker.
_TEMPLATE_PATH_RE = re.compile(
    r"""`(/[a-zA-Z0-9_/.-]+(?:\$\{[^}]+\}[a-zA-Z0-9_/.-]*)*)` """,
    re.I,
)

# JS object / array literal paths:  { url: '/path' }  or  ['/path1', '/path2']
_OBJ_PROP_PATH_RE = re.compile(
    r"""[\[,{]\s*['"`](/[a-zA-Z0-9_./%?&=+\-][^'"`\n]{0,150})['"`]\s*[,\]}]""",
    re.I,
)

# var/let/const  varName = '/path'  assignments
_VAR_ASSIGN_RE = re.compile(
    r"""(?:var|let|const)\s+\w+\s*=\s*['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Huawei-specific: string concatenation   '/html/ssmp/' + pageName + '.asp'
# Extracts the static prefix to queue as a candidate
_CONCAT_PREFIX_RE = re.compile(
    r"""['"`](/html/[a-zA-Z0-9_/]+/)['"`]\s*\+""",
    re.I,
)


def _extract_js_paths(js: str, page_url: str, base: str) -> set[str]:
    """
    Exhaustively extract every URL/path reference from JavaScript source.

    Uses many overlapping patterns to maximise discovery:
      • Explicit navigation (window.location, Form.setAction, fetch, $.ajax)
      • All root-relative quoted strings
      • Relative paths with known web extensions
      • Template literals
      • Object/array literals containing paths
      • Variable assignments
      • Huawei-specific concatenation prefixes
      • RequestFile= CGI parameter values
      • document.write() nested markup
    """
    # Import here to avoid circular dependency at module level
    from .html_parser import _extract_html_attrs

    found: set[str] = set()

    def _add(raw: str) -> None:
        # Skip strings that still contain template-literal interpolation markers
        # or embedded quote characters – these are not valid URL paths but
        # fragments of JS expressions captured by the broader regexes.
        # (Legitimate URL query strings use percent-encoding, not raw quotes.)
        if "${" in raw or "'" in raw or '"' in raw:
            return
        n = normalise_url(raw.strip(), page_url, base)
        if n:
            found.add(n)

    # All targeted patterns
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

    # Template literal – queue the static prefix as a directory hint
    for m in _TEMPLATE_PATH_RE.finditer(js):
        raw = re.sub(r"\$\{[^}]+\}", "", m.group(1))  # strip interpolations
        _add(raw)

    # document.write – treat written markup as HTML to extract src/href
    for m in _DOC_WRITE_RE.finditer(js):
        snippet = m.group(1).replace("\\'", "'").replace('\\"', '"')
        found |= _extract_html_attrs(snippet, page_url, base)

    # RequestFile= in any CGI action string
    for m in _REQUEST_FILE_RE.finditer(js):
        val = m.group(1)
        if not val.startswith("/"):
            val = "/" + val
        _add(val)

    return found
