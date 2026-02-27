"""
JavaScript deep URL/path extraction.
"""

import re

from web_crawler.utils.url import normalise_url

# window.location = "..." or window.location.href = "..."
_WIN_LOC_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href|location\.replace)\s*[=(]\s*['"`]([^'"`\n]+)['"`]""",
    re.I,
)

# Form action patterns
_FORM_ACTION_RE = re.compile(
    r"""\.(?:setAction|setAttribute\s*\(\s*['"]action['"])\s*[,(]\s*['"`]([^'"`\n]+)['"`]""",
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

# All root-relative quoted path strings: '/anything/here'
_ABS_QUOTED_PATH_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# Relative paths with a known web extension
_REL_EXT_PATH_RE = re.compile(
    r"""['"`]([.]{0,2}/[a-zA-Z0-9_\-./]+\.(?:"""
    r"html|htm|php|asp|aspx|cgi|jsp|do|action|"
    r"js|mjs|cjs|ts|jsx|tsx|vue|svelte|"
    r"css|scss|sass|less|styl|"
    r"png|jpg|jpeg|gif|ico|svg|bmp|webp|avif|tiff|"
    r"json|xml|yml|yaml|toml|ini|cfg|conf|config|hst|"
    r"woff2?|ttf|eot|otf|"
    r"pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods|"
    r"zip|tar|gz|tgz|bz2|rar|7z|"
    r"mp3|mp4|ogg|wav|webm|avi|mov|flv|"
    r"env|log|sql|md|rst|txt|csv|tsv|"
    r"swf|swp|bak|old|orig|save|tmp|"
    r"py|rb|pl|sh|bat|ps1|lua|go|rs|java|c|cpp|h|"
    r"htaccess|htpasswd|gitignore|dockerignore|editorconfig"
    r"""))['"`]""",
    re.I,
)

# Hidden/dot-files referenced in source: ".env", ".htaccess", etc.
_HIDDEN_FILE_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_\-./]*\.(?:"""
    r"htaccess|htpasswd|htgroups|htdigest|"
    r"env(?:\.\w+)?|"
    r"config|cfg|conf|hst|ini|toml|"
    r"gitignore|gitattributes|gitmodules|"
    r"dockerignore|editorconfig|"
    r"babelrc(?:\.json)?|eslintrc(?:\.(?:json|js|yml))?|"
    r"prettierrc(?:\.json)?|stylelintrc(?:\.json)?|"
    r"npmrc|npmignore|yarnrc(?:\.yml)?|nvmrc|"
    r"flake8|pylintrc|rubocop\.yml|coveragerc|"
    r"python-version|ruby-version|java-version|node-version|tool-versions|"
    r"browserslistrc|postcssrc|graphqlrc(?:\.yml)?|"
    r"travis\.yml|circleci|gitlab-ci\.yml|"
    r"DS_Store|vimrc|viminfo|"
    r"bash_history|bashrc|bash_profile|profile|zshrc|zsh_history|sh_history|"
    r"swp|swo|p12|pfx|pem|key|crt|cer"
    r"""))['"`]""",
    re.I,
)

# var/let/const  varName = '/path'
_VAR_ASSIGN_RE = re.compile(
    r"""(?:var|let|const)\s+\w+\s*=\s*['"`](/[a-zA-Z0-9_./%?&=+\-#][^'"`\n]{0,200})['"`]""",
    re.I,
)

# JS object / array literal paths
_OBJ_PROP_PATH_RE = re.compile(
    r"""[\[,{]\s*['"`](/[a-zA-Z0-9_./%?&=+\-][^'"`\n]{0,150})['"`]\s*[,\]}]""",
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
        _HIDDEN_FILE_RE,
        _OBJ_PROP_PATH_RE,
        _VAR_ASSIGN_RE,
    ):
        for m in pat.finditer(js):
            _add(m.group(1))

    for m in _DOC_WRITE_RE.finditer(js):
        snippet = m.group(1).replace("\\'", "'").replace('\\"', '"')
        from web_crawler.extraction.html_parser import extract_html_attrs
        found |= extract_html_attrs(snippet, page_url, base)

    return found
