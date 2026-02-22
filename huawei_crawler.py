#!/usr/bin/env python3
"""
Huawei HG8145V5 Router Web Crawler
Crawls and downloads all accessible content from the router's web interface
maintaining the original directory structure for offline analysis.
"""

import os
import re
import sys
import base64
import logging
import argparse
from urllib.parse import urljoin, urlparse, urlunparse
from pathlib import Path
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('crawler.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class HuaweiRouterCrawler:
    """Crawler for Huawei HG8145V5 router web interface."""

    def __init__(self, base_url, username, password, output_dir='router_backup'):
        """
        Initialize the crawler.

        Args:
            base_url: Router base URL (e.g., http://192.168.100.1)
            username: Login username
            password: Login password
            output_dir: Directory to save downloaded files
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Session management
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for local router

        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Track visited URLs to avoid duplicates
        self.visited_urls = set()
        self.downloaded_files = set()

        # Common resource extensions
        self.resource_extensions = {
            '.js', '.css', '.asp', '.cgi', '.html', '.htm',
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
            '.woff', '.woff2', '.ttf', '.eot',
            '.json', '.xml'
        }

        logger.info(f"Crawler initialized for {base_url}")
        logger.info(f"Output directory: {self.output_dir.absolute()}")

    def login(self):
        """
        Authenticate with the router.

        Returns:
            bool: True if login successful, False otherwise
        """
        try:
            logger.info("Attempting to login...")

            # First, get the CSRF token
            token_url = f"{self.base_url}/asp/GetRandCount.asp"
            token_response = self.session.post(token_url, timeout=10)
            token = token_response.text.strip()
            logger.info(f"Retrieved CSRF token: {token}")

            # Encode password in base64
            password_b64 = base64.b64encode(self.password.encode()).decode()

            # Set cookie
            cookie_value = f"Cookie=body:Language:english:id=-1;path=/"
            self.session.cookies.set('Cookie', cookie_value)

            # Prepare login data
            login_data = {
                'UserName': self.username,
                'PassWord': password_b64,
                'Language': 'english',
                'x.X_HW_Token': token
            }

            # Submit login
            login_url = f"{self.base_url}/login.cgi"
            response = self.session.post(
                login_url,
                data=login_data,
                allow_redirects=True,
                timeout=10
            )

            # Check if login was successful
            if response.status_code == 200:
                # Check if we're redirected to a logged-in page or if there's session cookie
                if 'sessionid' in self.session.cookies or 'SessionID' in self.session.cookies:
                    logger.info("Login successful!")
                    return True
                elif 'frame.asp' in response.url or 'main.asp' in response.url:
                    logger.info("Login successful! Redirected to main page")
                    return True
                else:
                    logger.warning("Login may have succeeded but confirmation unclear")
                    return True
            else:
                logger.error(f"Login failed with status code: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    def normalize_url(self, url):
        """
        Normalize URL to ensure consistency.

        Args:
            url: URL to normalize

        Returns:
            str: Normalized URL
        """
        # Parse URL
        parsed = urlparse(url)

        # Remove fragment
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            ''  # Remove fragment
        ))

        return normalized

    def get_file_path(self, url):
        """
        Convert URL to local file path maintaining directory structure.

        Args:
            url: URL to convert

        Returns:
            Path: Local file path
        """
        parsed = urlparse(url)
        path = parsed.path.lstrip('/')

        # Handle query parameters for versioned resources
        if parsed.query:
            # Remove version query parameters but keep the base filename
            path = path

        # Default to index.html for directory URLs
        if not path or path.endswith('/'):
            path = os.path.join(path, 'index.html')

        # Ensure proper extension
        if not any(path.endswith(ext) for ext in self.resource_extensions):
            # If no extension and no query, might be an ASP page
            if '?' not in url:
                path += '.html'

        return self.output_dir / path

    def download_file(self, url):
        """
        Download a file from the given URL.

        Args:
            url: URL to download

        Returns:
            bool: True if successful, False otherwise
        """
        if url in self.downloaded_files:
            return True

        try:
            # Normalize URL
            url = self.normalize_url(url)

            logger.info(f"Downloading: {url}")
            response = self.session.get(url, timeout=15)

            if response.status_code == 200:
                # Get local file path
                file_path = self.get_file_path(url)

                # Create directories
                file_path.parent.mkdir(parents=True, exist_ok=True)

                # Write file
                if 'text' in response.headers.get('Content-Type', '') or \
                   any(url.endswith(ext) for ext in ['.js', '.css', '.html', '.htm', '.asp', '.xml', '.json']):
                    # Text file
                    file_path.write_text(response.text, encoding='utf-8')
                else:
                    # Binary file
                    file_path.write_bytes(response.content)

                self.downloaded_files.add(url)
                logger.info(f"Saved to: {file_path}")
                return True
            else:
                logger.warning(f"Failed to download {url}: Status {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
            return False

    def extract_links(self, html, base_url):
        """
        Extract all links and resources from HTML content.

        Args:
            html: HTML content
            base_url: Base URL for resolving relative links

        Returns:
            set: Set of URLs found in the HTML
        """
        urls = set()

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Extract links from various tags
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'source']):
                url = None

                if tag.name == 'a':
                    url = tag.get('href')
                elif tag.name == 'link':
                    url = tag.get('href')
                elif tag.name == 'script':
                    url = tag.get('src')
                elif tag.name == 'img':
                    url = tag.get('src')
                elif tag.name == 'iframe':
                    url = tag.get('src')
                elif tag.name == 'source':
                    url = tag.get('src')

                if url:
                    # Resolve relative URLs
                    absolute_url = urljoin(base_url, url)

                    # Only include URLs from the same host
                    if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                        urls.add(absolute_url)

            # Extract URLs from CSS url() references
            css_pattern = r'url\([\'"]?([^\'")\s]+)[\'"]?\)'
            for match in re.finditer(css_pattern, html):
                url = match.group(1)
                absolute_url = urljoin(base_url, url)
                if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                    urls.add(absolute_url)

        except Exception as e:
            logger.error(f"Error extracting links: {e}")

        return urls

    def crawl_page(self, url):
        """
        Crawl a single page and extract resources.

        Args:
            url: URL to crawl

        Returns:
            set: Set of new URLs discovered
        """
        if url in self.visited_urls:
            return set()

        self.visited_urls.add(url)
        new_urls = set()

        try:
            logger.info(f"Crawling: {url}")
            response = self.session.get(url, timeout=15)

            if response.status_code == 200:
                # Save the page
                file_path = self.get_file_path(url)
                file_path.parent.mkdir(parents=True, exist_ok=True)

                # Save content
                if 'text' in response.headers.get('Content-Type', ''):
                    content = response.text
                    file_path.write_text(content, encoding='utf-8')

                    # Extract links from HTML
                    new_urls = self.extract_links(content, url)
                else:
                    file_path.write_bytes(response.content)

                logger.info(f"Saved: {file_path}")

        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")

        return new_urls

    def crawl(self, start_urls=None):
        """
        Start the crawling process.

        Args:
            start_urls: List of URLs to start crawling from
        """
        if start_urls is None:
            start_urls = [
                f"{self.base_url}/index.asp",
                f"{self.base_url}/frame.asp",
                f"{self.base_url}/main.asp"
            ]

        # Queue of URLs to visit
        to_visit = set(start_urls)

        logger.info(f"Starting crawl with {len(to_visit)} initial URLs")

        # Common admin pages to try
        common_pages = [
            '/status.asp', '/info.asp', '/config.asp',
            '/network.asp', '/wan.asp', '/lan.asp',
            '/wifi.asp', '/wireless.asp', '/wlan.asp',
            '/security.asp', '/firewall.asp',
            '/system.asp', '/admin.asp', '/management.asp',
            '/diagnostic.asp', '/tools.asp',
            '/backup.asp', '/update.asp', '/firmware.asp'
        ]

        for page in common_pages:
            to_visit.add(f"{self.base_url}{page}")

        # Crawl pages
        while to_visit:
            url = to_visit.pop()

            # Skip if already visited
            if url in self.visited_urls:
                continue

            # Crawl page and get new URLs
            new_urls = self.crawl_page(url)

            # Add new URLs to visit queue
            for new_url in new_urls:
                if new_url not in self.visited_urls:
                    to_visit.add(new_url)

        logger.info(f"Crawling complete. Visited {len(self.visited_urls)} URLs")
        logger.info(f"Downloaded {len(self.downloaded_files)} files")

    def create_index(self):
        """Create an index.html file listing all downloaded content."""
        try:
            index_path = self.output_dir / 'CRAWLER_INDEX.html'

            html = ['<!DOCTYPE html>', '<html>', '<head>',
                    '<meta charset="utf-8">',
                    '<title>Huawei Router Backup Index</title>',
                    '<style>',
                    'body { font-family: Arial, sans-serif; margin: 20px; }',
                    'h1 { color: #c00; }',
                    'ul { line-height: 1.6; }',
                    'a { color: #00c; text-decoration: none; }',
                    'a:hover { text-decoration: underline; }',
                    '</style>',
                    '</head>', '<body>',
                    '<h1>Huawei HG8145V5 Router Backup</h1>',
                    f'<p>Backup created from: {self.base_url}</p>',
                    f'<p>Total files: {len(self.downloaded_files)}</p>',
                    '<h2>Downloaded Files:</h2>', '<ul>']

            for url in sorted(self.visited_urls):
                path = self.get_file_path(url)
                if path.exists():
                    rel_path = path.relative_to(self.output_dir)
                    html.append(f'<li><a href="{rel_path}">{url}</a></li>')

            html.extend(['</ul>', '</body>', '</html>'])

            index_path.write_text('\n'.join(html), encoding='utf-8')
            logger.info(f"Created index file: {index_path}")

        except Exception as e:
            logger.error(f"Error creating index: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Huawei HG8145V5 Router Web Crawler'
    )
    parser.add_argument(
        '--url',
        default='http://192.168.100.1',
        help='Router base URL (default: http://192.168.100.1)'
    )
    parser.add_argument(
        '--username',
        default='Mega_gpon',
        help='Login username (default: Mega_gpon)'
    )
    parser.add_argument(
        '--password',
        default='796cce597901a5cf',
        help='Login password'
    )
    parser.add_argument(
        '--output',
        default='router_backup',
        help='Output directory (default: router_backup)'
    )

    args = parser.parse_args()

    # Disable SSL warnings for local router
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create crawler
    crawler = HuaweiRouterCrawler(
        args.url,
        args.username,
        args.password,
        args.output
    )

    # Login
    if not crawler.login():
        logger.error("Login failed. Exiting.")
        sys.exit(1)

    # Start crawling
    crawler.crawl()

    # Create index
    crawler.create_index()

    logger.info("Crawling complete!")
    logger.info(f"Files saved to: {crawler.output_dir.absolute()}")


if __name__ == '__main__':
    main()
