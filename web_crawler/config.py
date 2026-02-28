"""
Configuration constants for the generic web crawler.
"""

import os
import re

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_OUTPUT = "downloaded_site"
DEFAULT_MAX_DEPTH = 0          # 0 = unlimited
DEFAULT_DELAY = 0.25           # seconds between requests
DEFAULT_CONCURRENCY = 0        # 0 = auto-detect from CPU/RAM
DEFAULT_DOWNLOAD_EXTENSIONS = "all"

# Limits for auto-concurrency calculation
_MIN_WORKERS = 2
_MAX_WORKERS = 32
_RAM_PER_WORKER_MB = 64        # estimated RSS per worker thread


def auto_concurrency() -> int:
    """Calculate the optimal number of concurrent workers based on
    available CPU cores and system RAM.

    Heuristic:
      * Start with ``cpu_count * 2`` (I/O-bound workload).
      * Cap by available RAM (``free_mb / _RAM_PER_WORKER_MB``).
      * Clamp between ``_MIN_WORKERS`` and ``_MAX_WORKERS``.
    """
    cpus = os.cpu_count() or 2
    workers = cpus * 2

    # Try to read available memory and cap accordingly
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    mem_kb = int(line.split()[1])
                    mem_mb = mem_kb // 1024
                    ram_cap = max(1, mem_mb // _RAM_PER_WORKER_MB)
                    workers = min(workers, ram_cap)
                    break
    except (OSError, ValueError):
        pass

    return max(_MIN_WORKERS, min(workers, _MAX_WORKERS))

# ---------------------------------------------------------------------------
# Crawler tuning
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
HEADER_RETRY_MAX = 3           # extra retries with rotated headers on 403/etc.
BACKOFF_429_BASE = 2.0         # base seconds for exponential backoff on 429
BACKOFF_429_MAX = 60.0         # cap for 429 backoff
PROBE_403_THRESHOLD = 10       # disable hidden-file probing after this many 403s
PROBE_404_THRESHOLD = 50       # disable hidden-file probing after this many 404s
PROBE_DIR_404_LIMIT = 10       # skip remaining probes for a directory after this many 404s

# Minimum response body size (in bytes) at which the crawler switches to
# streaming mode instead of buffering the entire response in RAM.
# 10 MiB – covers typical firmware / archive files without penalising small assets.
STREAM_SIZE_THRESHOLD = 10 * 1024 * 1024

# Content-Type values that indicate large binary files deserving streaming.
BINARY_CONTENT_TYPES = frozenset({
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-sh",
    "application/x-bat",
    "application/x-cmd",
    "application/x-powershell",
})

# ---------------------------------------------------------------------------
# User-Agent rotation pool
# ---------------------------------------------------------------------------
USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    # Safari (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    # Opera (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/114.0.0.0",
]

# ---------------------------------------------------------------------------
# HTTP status codes that trigger header-rotation retry
# ---------------------------------------------------------------------------
RETRY_STATUS_CODES = {403, 402}

# ---------------------------------------------------------------------------
# WAF / Cloudflare / CAPTCHA detection signatures
# ---------------------------------------------------------------------------
WAF_SIGNATURES = {
    "cloudflare": [
        "cf-ray",
        "cf-mitigated",
        "cloudflare",
        "attention required! | cloudflare",
        "cf-chl-bypass",
        "checking your browser",
        "ray id:",
        "_cf_chl_opt",
        "challenges.cloudflare.com",
    ],
    "wordfence": [
        "wordfence",
        "wfwaf-authcookie",
        "this site is protected by wordfence",
        "your access to this site has been limited",
        "generated by wordfence",
    ],
    "sucuri": [
        "sucuri",
        "x-sucuri-id",
        "sucuri-cloudproxy",
        "access denied - sucuri website firewall",
        "sucuri website firewall",
    ],
    "modsecurity": [
        "mod_security",
        "modsecurity",
        "not acceptable!",
        "noyb",
    ],
    "imperva": [
        "x-iinfo",
        "incapsula",
        "imperva",
        "visid_incap",
        "_incapsula_",
    ],
    "akamai": [
        "akamai",
        "akamaighost",
        "x-akamai-transformed",
        "ak_bmsc",
    ],
    "shield_security": [
        "icwp-wpsf",
        "shield security",
    ],
    "ithemes_security": [
        "itsec",
        "ithemes security",
        "solid security",
    ],
    "siteground": [
        "sg-captcha",
        "sgcaptcha",
        ".well-known/sgcaptcha",
    ],
    "captcha": [
        "captcha",
        "recaptcha",
        "hcaptcha",
        "g-recaptcha",
        "h-captcha",
        "cf-turnstile",
        "funcaptcha",
        "geetest",
        "please verify you are a human",
        "verificar que eres humano",
        "complete the security check",
    ],
}

# ---------------------------------------------------------------------------
# Soft-404 (false positive) detection
# ---------------------------------------------------------------------------

# Extensions blocked at the nginx/SiteGround WAF level.  Requests for
# files with these extensions always receive HTTP 403 regardless of
# whether the file exists, so probing them is futile.
SITEGROUND_BLOCKED_EXTENSIONS = frozenset({
    ".env", ".sql", ".log", ".conf", ".ini", ".cfg",
    ".yml", ".yaml", ".toml", ".pem", ".key", ".db",
})

SOFT_404_KEYWORDS = [
    "page not found",
    "página no encontrada",
    "pagina no encontrada",
    "no encontrado",
    "not found",
    "404",
    "error 404",
    "page doesn't exist",
    "page does not exist",
    "nothing found",
    "no existe",
    "no se encontró",
    "no se encontro",
    "the page you requested",
    "this page could not be found",
    "we couldn't find",
    "lo sentimos",
    "oops",
    "page you are looking for",
    "page you were looking for",
    "requested page was not found",
    "requested url was not found",
    "la página que buscas",
    "la pagina que buscas",
    "contenido no disponible",
    "recurso no encontrado",
    "enlace roto",
    "página no existe",
    "pagina no existe",
]

# Keywords that indicate a soft-404 when found in the <title> tag
SOFT_404_TITLE_KEYWORDS = [
    "404",
    "not found",
    "page not found",
    "error 404",
    "no encontrado",
    "no encontrada",
    "página no encontrada",
    "pagina no encontrada",
]

SOFT_404_SIZE_RATIO = 0.15
SOFT_404_MIN_KEYWORD_HITS = 1

# Minimum keyword hits for standalone detection (without baseline fingerprint)
SOFT_404_STANDALONE_MIN_HITS = 2

# ---------------------------------------------------------------------------
# WordPress discovery paths (auto-queued when WP is detected)
# ---------------------------------------------------------------------------
WP_DISCOVERY_PATHS = [
    # REST API
    "/wp-json/",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/categories",
    "/wp-json/wp/v2/tags",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/comments",
    # WooCommerce Store API (public, no auth needed)
    "/wp-json/wc/store/v1/products",
    "/wp-json/wc/store/v1/products/categories",
    "/wp-json/wc/store/v1/products/tags",
    "/wp-json/wc/store/v1/products/attributes",
    # Sitemaps
    "/wp-sitemap.xml",
    "/wp-sitemap-posts-post-1.xml",
    "/wp-sitemap-posts-page-1.xml",
    "/wp-sitemap-posts-product-1.xml",
    "/wp-sitemap-taxonomies-category-1.xml",
    "/wp-sitemap-taxonomies-product_cat-1.xml",
    "/wp-sitemap-taxonomies-product_tag-1.xml",
    "/wp-sitemap-users-1.xml",
    "/sitemap.xml",
    "/sitemap_index.xml",
    # Feeds
    "/feed/",
    "/comments/feed/",
    "/feed/atom/",
    # Root PHP files (accessible)
    "/wp-login.php",
    "/wp-cron.php",
    "/wp-links-opml.php",
    "/wp-signup.php",
    "/wp-activate.php",
    "/wp-comments-post.php",
    # wp-admin PHP (redirect to login if not authenticated, still saved)
    "/wp-admin/",
    "/wp-admin/install.php",
    "/wp-admin/about.php",
    "/wp-admin/admin.php",
    "/wp-admin/index.php",
    "/wp-admin/edit.php",
    "/wp-admin/upload.php",
    "/wp-admin/plugins.php",
    "/wp-admin/themes.php",
    "/wp-admin/users.php",
    "/wp-admin/tools.php",
    "/wp-admin/options-general.php",
    "/wp-admin/site-health.php",
    "/wp-admin/update-core.php",
    # Common files
    "/readme.html",
    "/license.txt",
    "/wp-includes/css/dist/block-library/style.min.css",
    "/wp-includes/js/jquery/jquery.min.js",
    # WP REST API alternate (bypasses /wp-json/ path if blocked)
    "/?rest_route=/wp/v2/posts",
    "/?rest_route=/wp/v2/pages",
    "/?rest_route=/wp/v2/media",
]

# ---------------------------------------------------------------------------
# WordPress plugin enumeration (top plugins by popularity)
# ---------------------------------------------------------------------------
WP_PLUGIN_PROBES = [
    "akismet",
    "contact-form-7",
    "woocommerce",
    "wordpress-seo",
    "elementor",
    "classic-editor",
    "wpforms-lite",
    "wordfence",
    "really-simple-ssl",
    "jetpack",
    "all-in-one-seo-pack",
    "updraftplus",
    "litespeed-cache",
    "duplicate-post",
    "wp-super-cache",
    "w3-total-cache",
    "redirection",
    "google-analytics-for-wordpress",
    "wp-mail-smtp",
    "tablepress",
    "regenerate-thumbnails",
    "all-in-one-wp-migration",
    "google-sitemap-generator",
    "sucuri-scanner",
    "ithemes-security-pro",
    "limit-login-attempts-reloaded",
    "wp-fastest-cache",
    "better-wp-security",
    "backwpup",
    "ninja-forms",
    "advanced-custom-fields",
    "query-monitor",
    "sg-cachepress",
    "autoptimize",
    "shortcodes-ultimate",
    "insert-headers-and-footers",
    "tinymce-advanced",
    "wp-optimize",
    "broken-link-checker",
    "wp-smushit",
    "imagify",
    "user-role-editor",
    "yoast-seo-premium",
    "wp-rocket",
    "mailchimp-for-wp",
    "instagram-feed",
    "custom-post-type-ui",
    "simple-custom-css",
    "disable-comments",
    "health-check",
]

# ---------------------------------------------------------------------------
# WordPress theme enumeration (popular themes)
# ---------------------------------------------------------------------------
WP_THEME_PROBES = [
    "twentytwentyfive",
    "twentytwentyfour",
    "twentytwentythree",
    "twentytwentytwo",
    "twentytwentyone",
    "twentytwenty",
    "astra",
    "flavor",
    "flavstarter",
    "flavor-starter",
    "oceanwp",
    "generatepress",
    "kadence",
    "hello-elementor",
    "storefront",
    "neve",
]

# ---------------------------------------------------------------------------
# Deep WP plugin/theme internal files to crawl once a slug is confirmed
# ---------------------------------------------------------------------------
WP_PLUGIN_FILES = [
    "readme.txt",
    "README.md",
    "changelog.txt",
    "CHANGELOG.md",
    "license.txt",
    "composer.json",
    "package.json",
    "uninstall.php",
    "includes/",
    "assets/",
    "css/",
    "js/",
    "languages/",
    "templates/",
    "admin/",
    "public/",
    "vendor/autoload.php",
    "config.php",
    "settings.php",
    "debug.log",
    ".htaccess",
]

WP_THEME_FILES = [
    "style.css",
    "screenshot.png",
    "screenshot.jpg",
    "functions.php",
    "header.php",
    "footer.php",
    "index.php",
    "single.php",
    "page.php",
    "sidebar.php",
    "archive.php",
    "search.php",
    "404.php",
    "comments.php",
    "front-page.php",
    "template-parts/",
    "inc/",
    "assets/",
    "css/",
    "js/",
    "images/",
    "fonts/",
    "readme.txt",
    "README.md",
    "changelog.txt",
    "rtl.css",
    "woocommerce.css",
    "editor-style.css",
    "theme.json",
]

# ---------------------------------------------------------------------------
# Cache-bypass query parameters (appended to force fresh responses)
# ---------------------------------------------------------------------------
CACHE_BYPASS_PARAMS = [
    "nocache=1",
    "cachebuster={rand}",
    "v={rand}",
    "_={rand}",
]

# ---------------------------------------------------------------------------
# Content types parsed for further links
# ---------------------------------------------------------------------------
CRAWLABLE_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "text/css",
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/x-httpd-php",
    "text/x-php",
    "application/php",
    "application/x-yaml",
    "text/yaml",
    "text/x-ini",
}

# ---------------------------------------------------------------------------
# Blocked URL patterns (dangerous / non-crawlable endpoints)
# ---------------------------------------------------------------------------
BLOCKED_PATH_RE = re.compile(
    r"(logout|signout|delete|remove|unsubscribe)\b"
    # WP REST API routes that require API-key / admin authentication
    # (always return 401 without WooCommerce API keys or WP app passwords).
    # Crawling them wastes requests and fills the queue with guaranteed errors.
    # NOTE: wp/v2/product*, product_cat, product_tag are PUBLIC (return 200)
    # and must NOT be blocked.
    r"|/wp-json/(?:"
    r"wc/(?:v[1-9]|gla|analytics)/|"      # WC REST v1–9, GLA, Analytics (401)
    r"wc-admin/|"                           # WC Admin (401)
    r"wc-analytics/|"                       # WC Analytics (401)
    r"jetpack/|my-jetpack/v\d+/(?!$)|"     # Jetpack (401), keep root index
    r"elementor(?:-pro)?/v\d+/(?!$)|"      # Elementor/Pro (401), keep root index
    r"siteground-optimizer/|"              # SiteGround Optimizer (404/401)
    r"code-snippets/|"                     # Code Snippets (401)
    r"flexible-checkout-fields/|"          # Flexible Checkout Fields (401)
    r"wp-site-health/|"                    # WP Site Health (401)
    r"oceanwp/v\d+/(?!$)"                  # OceanWP (401), keep root index
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Hidden / sensitive files to probe at every discovered directory
# ---------------------------------------------------------------------------
HIDDEN_FILE_PROBES = [
    # -- Apache / web server config --
    ".htaccess",
    ".htpasswd",
    ".htgroups",
    ".htdigest",
    "httpd.conf",
    "apache2.conf",
    "sites-enabled/default",
    "conf/httpd.conf",
    # -- Nginx --
    "nginx.conf",
    "conf.d/default.conf",
    "sites-available/default",
    # -- Environment / dotenv --
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
    ".env.example",
    ".env.sample",
    ".env.bak",
    ".env.old",
    ".env.save",
    ".env.dist",
    ".env.defaults",
    ".env.dev",
    ".env.prod",
    # -- General config --
    ".config",
    ".cfg",
    ".hst",                # history files (browser, shell)
    "config.php",
    "config.php.bak",
    "config.php.old",
    "config.php.save",
    "config.php.swp",
    "config.php~",
    "config.inc.php",
    "config.inc",
    "config.yml",
    "config.yaml",
    "config.json",
    "config.xml",
    "config.ini",
    "config.toml",
    "config.rb",
    "config.py",
    "config.js",
    "config.ts",
    "config.bak",
    "config.old",
    "conf.ini",
    "app.config",
    "app.yaml",
    "app.yml",
    "app.json",
    "appsettings.json",
    "appsettings.Development.json",
    "appsettings.Production.json",
    # -- Git --
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/COMMIT_EDITMSG",
    ".git/description",
    ".git/info/exclude",
    ".git/logs/HEAD",
    ".git/packed-refs",
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    # -- SVN / Mercurial --
    ".svn/entries",
    ".svn/wc.db",
    ".hg/hgrc",
    ".hgignore",
    # -- OS metadata --
    ".DS_Store",
    "Thumbs.db",
    "Desktop.ini",
    "._metadata",
    # -- Microsoft / IIS --
    "web.config",
    "web.config.bak",
    "Web.Debug.config",
    "Web.Release.config",
    "Global.asax",
    "iisstart.htm",
    # -- WordPress --
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.php.old",
    "wp-config.php.save",
    "wp-config.php.swp",
    "wp-config.php.txt",
    "wp-config-sample.php",
    "wp-login.php",
    "wp-cron.php",
    "wp-settings.php",
    "wp-includes/version.php",
    "wp-admin/install.php",
    "wp-content/debug.log",
    "xmlrpc.php",
    "wp-trackback.php",
    "wp-links-opml.php",
    "wp-content/uploads/",
    "wp-content/plugins/",
    "wp-content/themes/",
    "wp-json/",
    "readme.html",
    # -- Joomla --
    "configuration.php",
    "configuration.php.bak",
    "configuration.php~",
    # -- Drupal --
    "settings.php",
    "settings.local.php",
    "sites/default/settings.php",
    # -- Laravel --
    "storage/logs/laravel.log",
    "artisan",
    ".env.backup",
    "bootstrap/cache/config.php",
    # -- Django / Python --
    "settings.py",
    "local_settings.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "celeryconfig.py",
    # -- Ruby / Rails --
    "database.yml",
    "database.yml.example",
    "secrets.yml",
    "credentials.yml.enc",
    "master.key",
    "Rakefile",
    # -- Docker --
    ".dockerignore",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.override.yml",
    "docker-compose.prod.yml",
    "docker-compose.dev.yml",
    ".docker/config.json",
    # -- CI/CD --
    ".travis.yml",
    ".circleci/config.yml",
    ".github/workflows/main.yml",
    ".github/workflows/ci.yml",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "buildspec.yml",
    # -- Build / package managers --
    "Makefile",
    "CMakeLists.txt",
    "Gruntfile.js",
    "Gulpfile.js",
    "webpack.config.js",
    "rollup.config.js",
    "vite.config.js",
    "vite.config.ts",
    "nuxt.config.js",
    "nuxt.config.ts",
    "next.config.js",
    "next.config.mjs",
    "vue.config.js",
    "angular.json",
    "composer.json",
    "composer.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile",
    "Gemfile.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    "build.xml",
    "ivy.xml",
    "project.clj",
    "mix.exs",
    "rebar.config",
    "deno.json",
    "deno.lock",
    "bun.lockb",
    # -- Linting / formatting --
    ".babelrc",
    ".babelrc.json",
    "babel.config.js",
    "babel.config.json",
    ".eslintrc",
    ".eslintrc.json",
    ".eslintrc.js",
    ".eslintrc.yml",
    ".eslintignore",
    ".prettierrc",
    ".prettierrc.json",
    ".prettierignore",
    ".stylelintrc",
    ".stylelintrc.json",
    "tsconfig.json",
    "tsconfig.build.json",
    "jsconfig.json",
    ".browserslistrc",
    ".postcssrc",
    "postcss.config.js",
    "tailwind.config.js",
    "tailwind.config.ts",
    ".editorconfig",
    ".flake8",
    ".pylintrc",
    ".rubocop.yml",
    ".phpcs.xml",
    "phpunit.xml",
    "phpunit.xml.dist",
    "jest.config.js",
    "jest.config.ts",
    "vitest.config.ts",
    "karma.conf.js",
    ".mocharc.yml",
    "pytest.ini",
    "tox.ini",
    "mypy.ini",
    ".coveragerc",
    "codecov.yml",
    ".nycrc",
    # -- SEO / discovery --
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "sitemap.xml.gz",
    "sitemap1.xml",
    "sitemap2.xml",
    "rss.xml",
    "feed.xml",
    "atom.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "browserconfig.xml",
    "manifest.json",
    "site.webmanifest",
    "favicon.ico",
    "apple-touch-icon.png",
    "ads.txt",
    "app-ads.txt",
    "sellers.json",
    # -- Security / well-known --
    "security.txt",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    ".well-known/assetlinks.json",
    ".well-known/apple-app-site-association",
    ".well-known/change-password",
    ".well-known/jwks.json",
    ".well-known/acme-challenge",
    # -- PHP --
    "phpinfo.php",
    "info.php",
    "test.php",
    "i.php",
    "pi.php",
    "php.ini",
    ".user.ini",
    "php.ini.bak",
    # -- Database --
    "backup.sql",
    "dump.sql",
    "db.sql",
    "database.sql",
    "data.sql",
    "mysql.sql",
    "export.sql",
    "backup.sql.gz",
    "backup.sql.bz2",
    "db.sqlite",
    "db.sqlite3",
    "database.sqlite",
    "database.sqlite3",
    "data.db",
    # -- Shell / system --
    ".bash_history",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zsh_history",
    ".sh_history",
    ".vimrc",
    ".viminfo",
    "crontab",
    "passwd",
    "shadow",
    # -- SSH / TLS keys & certs --
    ".ssh/authorized_keys",
    ".ssh/known_hosts",
    ".ssh/id_rsa",
    ".ssh/id_rsa.pub",
    ".ssh/id_ed25519",
    ".ssh/id_ed25519.pub",
    "id_rsa",
    "id_rsa.pub",
    "id_dsa",
    "id_dsa.pub",
    "server.key",
    "server.crt",
    "server.pem",
    "private.key",
    "private.pem",
    "public.key",
    "public.pem",
    "certificate.crt",
    "certificate.pem",
    "ca-bundle.crt",
    "ssl-cert-snakeoil.key",
    "ssl-cert-snakeoil.pem",
    "keystore.jks",
    "truststore.jks",
    ".p12",
    ".pfx",
    # -- Logs --
    "error_log",
    "error.log",
    "access_log",
    "access.log",
    "debug.log",
    "app.log",
    "application.log",
    "server.log",
    "install.log",
    "migration.log",
    "cron.log",
    "mail.log",
    "syslog",
    "messages",
    "npm-debug.log",
    "yarn-error.log",
    "yarn-debug.log",
    # -- Documentation --
    "README.md",
    "README.txt",
    "README.rst",
    "README.html",
    "CHANGELOG.md",
    "CHANGELOG.txt",
    "CHANGES.md",
    "HISTORY.md",
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "COPYING",
    "NOTICE",
    "CONTRIBUTING.md",
    "AUTHORS",
    "AUTHORS.md",
    "TODO.md",
    "TODO.txt",
    "humans.txt",
    "VERSION",
    "VERSION.txt",
    # -- Backup / temp / swap --
    "backup.tar",
    "backup.tar.gz",
    "backup.tgz",
    "backup.zip",
    "backup.rar",
    "backup.7z",
    "site.tar.gz",
    "www.tar.gz",
    "www.zip",
    "public.tar.gz",
    "public.zip",
    "htdocs.tar.gz",
    "old.zip",
    "archive.zip",
    "archive.tar.gz",
    "temp.zip",
    "test.zip",
    ".swp",
    ".swo",
    "~",
    # -- Cloud / serverless --
    "firebase.json",
    ".firebaserc",
    "now.json",
    "vercel.json",
    "netlify.toml",
    "amplify.yml",
    "serverless.yml",
    "serverless.yaml",
    "sam-template.yaml",
    "template.yaml",
    "cloudformation.yaml",
    "terraform.tfvars",
    "terraform.tfstate",
    "main.tf",
    "variables.tf",
    "outputs.tf",
    "ansible.cfg",
    "playbook.yml",
    "inventory",
    "hosts",
    "Vagrantfile",
    # -- API docs --
    "swagger.json",
    "swagger.yaml",
    "openapi.json",
    "openapi.yaml",
    "api-docs.json",
    "graphql",
    "graphql/schema",
    ".graphqlrc",
    ".graphqlrc.yml",
    # -- Misc application --
    "elmah.axd",
    "trace.axd",
    ".idea/workspace.xml",
    ".vscode/settings.json",
    ".vscode/launch.json",
    "nbproject/project.properties",
    ".project",
    ".classpath",
    ".settings/org.eclipse.core.resources.prefs",
    "bower.json",
    ".bowerrc",
    "Procfile",
    "Procfile.dev",
    "runtime.txt",
    "nixpacks.toml",
    ".node-version",
    ".nvmrc",
    ".python-version",
    ".ruby-version",
    ".java-version",
    ".tool-versions",
    ".npmrc",
    ".npmignore",
    ".yarnrc",
    ".yarnrc.yml",
    "lerna.json",
    "nx.json",
    "turbo.json",
    "renovate.json",
    ".renovaterc",
    "dependabot.yml",
    ".github/dependabot.yml",
]
