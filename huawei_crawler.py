#!/usr/bin/env python3
"""
Huawei HG8145V5 Router Web Crawler
Crawls and downloads all accessible content from the router's web interface
maintaining the original directory structure for offline analysis.
"""

import os
import re
import sys
import time
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

    def __init__(self, base_url, username, password, output_dir='router_backup', max_iterations=50):
        """
        Initialize the crawler.

        Args:
            base_url: Router base URL (e.g., http://192.168.100.1)
            username: Login username
            password: Login password
            output_dir: Directory to save downloaded files
            max_iterations: Maximum number of crawling iterations (safety limit)
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.max_iterations = max_iterations

        # Session management
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for local router

        # Configure keep-alive
        self.session.headers.update({
            'Connection': 'keep-alive',
            'Keep-Alive': 'timeout=300, max=1000'
        })

        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Track visited URLs to avoid duplicates
        self.visited_urls = set()
        self.downloaded_files = set()

        # Track authentication status
        self.is_authenticated = False
        self.last_auth_check = 0

        # Common resource extensions
        self.resource_extensions = {
            '.js', '.css', '.asp', '.cgi', '.html', '.htm',
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
            '.woff', '.woff2', '.ttf', '.eot',
            '.json', '.xml'
        }

        logger.info(f"Crawler initialized for {base_url}")
        logger.info(f"Output directory: {self.output_dir.absolute()}")
        logger.info(f"Max iterations: {max_iterations}")

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
                    self.is_authenticated = True
                    self.last_auth_check = time.time()
                    return True
                elif 'frame.asp' in response.url or 'main.asp' in response.url:
                    logger.info("Login successful! Redirected to main page")
                    self.is_authenticated = True
                    self.last_auth_check = time.time()
                    return True
                else:
                    logger.warning("Login may have succeeded but confirmation unclear")
                    self.is_authenticated = True
                    self.last_auth_check = time.time()
                    return True
            else:
                logger.error(f"Login failed with status code: {response.status_code}")
                self.is_authenticated = False
                return False

        except Exception as e:
            logger.error(f"Login error: {e}")
            self.is_authenticated = False
            return False

    def is_session_valid(self):
        """
        Check if the current session is still valid.

        Returns:
            bool: True if session is valid, False otherwise
        """
        # Check every 30 seconds to avoid too many validation requests
        current_time = time.time()
        if current_time - self.last_auth_check < 30:
            return self.is_authenticated

        try:
            # Try to access a protected page to validate session
            test_url = f"{self.base_url}/asp/GetRandCount.asp"
            response = self.session.get(test_url, timeout=5)

            # If we get redirected to login page or get 401/403, session is invalid
            if response.status_code in [401, 403] or 'login.asp' in response.url.lower():
                logger.warning("Session is no longer valid")
                self.is_authenticated = False
                return False

            self.last_auth_check = current_time
            self.is_authenticated = True
            return True

        except Exception as e:
            logger.warning(f"Session validation error: {e}")
            return self.is_authenticated

    def ensure_authenticated(self):
        """
        Ensure we have a valid authenticated session.
        Re-authenticates if session has expired.

        Returns:
            bool: True if authenticated, False otherwise
        """
        if not self.is_session_valid():
            logger.info("Session expired or invalid, re-authenticating...")
            return self.login()
        return True

    def file_already_downloaded(self, url):
        """
        Check if a file has already been downloaded.

        Args:
            url: URL to check

        Returns:
            bool: True if file exists, False otherwise
        """
        file_path = self.get_file_path(url)
        exists = file_path.exists() and file_path.stat().st_size > 0
        if exists:
            logger.debug(f"File already downloaded: {file_path}")
        return exists

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

    def extract_js_routes(self, content, base_url):
        """
        Extract routes and URLs from JavaScript content.

        Args:
            content: JavaScript or HTML content
            base_url: Base URL for resolving relative paths

        Returns:
            set: Set of discovered URLs
        """
        urls = set()

        try:
            # Pattern 1: String literals that look like paths/URLs
            # Matches: '/path/file.asp', 'path/file.cgi', '/folder/page.html'
            path_patterns = [
                r'["\']([/.]?[a-zA-Z0-9_\-./]+\.(?:asp|cgi|html?|js|css|json|xml))["\']',
                r'["\']([/][a-zA-Z0-9_\-/]+(?:\.[a-zA-Z0-9]+)?)["\']',
            ]

            for pattern in path_patterns:
                for match in re.finditer(pattern, content):
                    path = match.group(1)
                    # Skip very short paths or common false positives
                    if len(path) > 2 and not path.startswith('data:'):
                        absolute_url = urljoin(base_url, path)
                        if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                            urls.add(absolute_url)

            # Pattern 2: AJAX/fetch URLs
            # Matches: url: '/path', url:'/path', url="/path"
            ajax_patterns = [
                r'url\s*:\s*["\']([^"\']+)["\']',
                r'\.open\s*\([^,]+,\s*["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'\.ajax\s*\(\s*["\']([^"\']+)["\']',
            ]

            for pattern in ajax_patterns:
                for match in re.finditer(pattern, content):
                    path = match.group(1)
                    if not path.startswith('http') and not path.startswith('data:'):
                        absolute_url = urljoin(base_url, path)
                        if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                            urls.add(absolute_url)

            # Pattern 3: window.location, document.location
            location_patterns = [
                r'(?:window|document)\.location(?:\.\w+)?\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
            ]

            for pattern in location_patterns:
                for match in re.finditer(pattern, content):
                    path = match.group(1)
                    if not path.startswith('http') and not path.startswith('#'):
                        absolute_url = urljoin(base_url, path)
                        if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                            urls.add(absolute_url)

            # Pattern 4: Form actions
            form_pattern = r'\.setAction\s*\(\s*["\']([^"\']+)["\']'
            for match in re.finditer(form_pattern, content):
                path = match.group(1)
                absolute_url = urljoin(base_url, path)
                if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                    urls.add(absolute_url)

        except Exception as e:
            logger.error(f"Error extracting JS routes: {e}")

        return urls

    def extract_asp_routes(self, content, base_url):
        """
        Extract routes and endpoints from ASP content.

        Args:
            content: ASP or HTML content
            base_url: Base URL for resolving relative paths

        Returns:
            set: Set of discovered URLs
        """
        urls = set()

        try:
            # ASP includes and references
            asp_patterns = [
                r'<!--\s*#include\s+(?:virtual|file)\s*=\s*["\']([^"\']+)["\']',
                r'Response\.Redirect\s*["\']([^"\']+)["\']',
                r'Server\.Transfer\s*["\']([^"\']+)["\']',
            ]

            for pattern in asp_patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    path = match.group(1)
                    absolute_url = urljoin(base_url, path)
                    if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                        urls.add(absolute_url)

        except Exception as e:
            logger.error(f"Error extracting ASP routes: {e}")

        return urls

    def extract_menu_links(self, soup, base_url):
        """
        Extract links from navigation menus and common menu structures.

        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative links

        Returns:
            set: Set of URLs from menus
        """
        urls = set()

        try:
            # Find common menu containers
            menu_selectors = [
                'nav', 'menu', '[class*="menu"]', '[id*="menu"]',
                '[class*="nav"]', '[id*="nav"]', 'ul', 'ol'
            ]

            for selector in menu_selectors:
                menu_items = soup.select(selector)
                for item in menu_items:
                    # Find all links within menu items
                    for link in item.find_all('a', href=True):
                        url = link['href']
                        if url and not url.startswith('#') and not url.startswith('javascript:'):
                            absolute_url = urljoin(base_url, url)
                            if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                                urls.add(absolute_url)

            # Also check for onclick handlers that might contain URLs
            for element in soup.find_all(onclick=True):
                onclick = element['onclick']
                # Extract URLs from onclick handlers
                onclick_urls = re.findall(r'["\']([^"\']*\.(?:asp|cgi|html?)[^"\']*)["\']', onclick)
                for url in onclick_urls:
                    absolute_url = urljoin(base_url, url)
                    if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                        urls.add(absolute_url)

        except Exception as e:
            logger.error(f"Error extracting menu links: {e}")

        return urls

    def extract_links(self, html, base_url):
        """
        Extract all links and resources from HTML content.
        Enhanced to deeply analyze JavaScript, ASP, and all content.

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
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'source', 'form']):
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
                elif tag.name == 'form':
                    url = tag.get('action')

                if url and url.strip():
                    # Skip javascript: and # links
                    if not url.startswith('javascript:') and not url.startswith('#'):
                        # Resolve relative URLs
                        absolute_url = urljoin(base_url, url)

                        # Only include URLs from the same host
                        if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                            urls.add(absolute_url)

            # Extract URLs from CSS url() references
            css_pattern = r'url\([\'"]?([^\'")\s]+)[\'"]?\)'
            for match in re.finditer(css_pattern, html):
                url = match.group(1)
                if not url.startswith('data:'):
                    absolute_url = urljoin(base_url, url)
                    if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                        urls.add(absolute_url)

            # Extract JavaScript routes
            js_urls = self.extract_js_routes(html, base_url)
            urls.update(js_urls)
            logger.debug(f"Found {len(js_urls)} URLs from JavaScript analysis")

            # Extract ASP routes
            asp_urls = self.extract_asp_routes(html, base_url)
            urls.update(asp_urls)
            logger.debug(f"Found {len(asp_urls)} URLs from ASP analysis")

            # Extract menu links
            menu_urls = self.extract_menu_links(soup, base_url)
            urls.update(menu_urls)
            logger.debug(f"Found {len(menu_urls)} URLs from menu analysis")

            # Extract inline script content
            for script_tag in soup.find_all('script'):
                if script_tag.string:
                    script_urls = self.extract_js_routes(script_tag.string, base_url)
                    urls.update(script_urls)

        except Exception as e:
            logger.error(f"Error extracting links: {e}")

        return urls

    def crawl_page(self, url):
        """
        Crawl a single page and extract resources.
        Enhanced to deeply analyze content and extract all possible routes.
        Includes file skip check and auto re-authentication.

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
            # Check if file already exists (skip download)
            if self.file_already_downloaded(url):
                logger.info(f"Skipping already downloaded: {url}")

                # Still need to extract links from the existing file
                file_path = self.get_file_path(url)
                try:
                    content = file_path.read_text(encoding='utf-8')

                    # Extract links based on content type
                    if url.endswith('.js'):
                        new_urls = self.extract_js_routes(content, url)
                    elif url.endswith('.css'):
                        css_pattern = r'url\([\'"]?([^\'")\s]+)[\'"]?\)'
                        for match in re.finditer(css_pattern, content):
                            resource_url = match.group(1)
                            if not resource_url.startswith('data:'):
                                absolute_url = urljoin(url, resource_url)
                                if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                                    new_urls.add(absolute_url)
                    else:
                        # HTML/ASP/other text - full extraction
                        new_urls = self.extract_links(content, url)
                        js_urls = self.extract_js_routes(content, url)
                        new_urls.update(js_urls)
                        asp_urls = self.extract_asp_routes(content, url)
                        new_urls.update(asp_urls)

                    logger.info(f"Extracted {len(new_urls)} URLs from cached file: {url}")
                except Exception as e:
                    logger.warning(f"Could not read cached file {file_path}: {e}")

                return new_urls

            # Ensure we're authenticated before making request
            if not self.ensure_authenticated():
                logger.error(f"Failed to authenticate, skipping {url}")
                return new_urls

            logger.info(f"Crawling: {url}")
            response = self.session.get(url, timeout=15)

            # Check for authentication issues and retry once
            if response.status_code in [401, 403] or 'login.asp' in response.url.lower():
                logger.warning(f"Authentication required for {url}, attempting re-login...")
                if self.login():
                    # Retry the request after successful login
                    response = self.session.get(url, timeout=15)
                else:
                    logger.error(f"Re-authentication failed for {url}")
                    return new_urls

            if response.status_code == 200:
                # Save the page
                file_path = self.get_file_path(url)
                file_path.parent.mkdir(parents=True, exist_ok=True)

                content_type = response.headers.get('Content-Type', '')

                # Determine if this is text content
                is_text = ('text' in content_type or
                          any(url.endswith(ext) for ext in ['.js', '.css', '.html', '.htm', '.asp', '.cgi', '.xml', '.json']))

                if is_text:
                    content = response.text
                    file_path.write_text(content, encoding='utf-8')

                    # Extract links based on content type
                    if url.endswith('.js'):
                        # JavaScript file - extract routes from JS
                        logger.info(f"Analyzing JavaScript file: {url}")
                        new_urls = self.extract_js_routes(content, url)
                    elif url.endswith('.css'):
                        # CSS file - extract url() references
                        css_pattern = r'url\([\'"]?([^\'")\s]+)[\'"]?\)'
                        for match in re.finditer(css_pattern, content):
                            resource_url = match.group(1)
                            if not resource_url.startswith('data:'):
                                absolute_url = urljoin(url, resource_url)
                                if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                                    new_urls.add(absolute_url)
                    else:
                        # HTML/ASP/other text - full extraction
                        new_urls = self.extract_links(content, url)

                        # Also extract JS routes from inline scripts
                        js_urls = self.extract_js_routes(content, url)
                        new_urls.update(js_urls)

                        # Extract ASP routes
                        asp_urls = self.extract_asp_routes(content, url)
                        new_urls.update(asp_urls)

                    logger.info(f"Extracted {len(new_urls)} URLs from {url}")
                else:
                    # Binary file
                    file_path.write_bytes(response.content)
                    logger.info(f"Saved binary file: {file_path}")

                logger.info(f"Saved: {file_path}")

            elif response.status_code == 404:
                logger.debug(f"Not found (404): {url}")
            elif response.status_code == 403:
                logger.warning(f"Forbidden (403): {url}")
            else:
                logger.warning(f"Status {response.status_code}: {url}")

        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")

        return new_urls

    def crawl(self, start_urls=None):
        """
        Start the crawling process.
        Enhanced with recursive and comprehensive URL discovery.

        Args:
            start_urls: List of URLs to start crawling from
        """
        if start_urls is None:
            start_urls = [
                f"{self.base_url}/",
                f"{self.base_url}/index.asp",
                f"{self.base_url}/index.html",
                f"{self.base_url}/frame.asp",
                f"{self.base_url}/main.asp",
                f"{self.base_url}/menu.asp",
                f"{self.base_url}/top.asp",
                f"{self.base_url}/left.asp",
            ]

        # Queue of URLs to visit
        to_visit = set(start_urls)

        logger.info(f"Starting crawl with {len(to_visit)} initial URLs")

        # Extended list of common router admin pages and endpoints
        common_pages = [
            # Main pages
            '/status.asp', '/info.asp', '/config.asp', '/home.asp',
            '/network.asp', '/wan.asp', '/lan.asp',

            # WiFi/Wireless
            '/wifi.asp', '/wireless.asp', '/wlan.asp', '/ssid.asp',
            '/wificonfig.asp', '/wirelessconfig.asp',

            # Security
            '/security.asp', '/firewall.asp', '/filter.asp',
            '/port.asp', '/portforward.asp', '/dmz.asp',

            # System/Admin
            '/system.asp', '/admin.asp', '/management.asp',
            '/diagnostic.asp', '/tools.asp', '/ping.asp',
            '/backup.asp', '/update.asp', '/firmware.asp',
            '/restore.asp', '/reboot.asp', '/upgrade.asp',

            # Advanced
            '/advanced.asp', '/nat.asp', '/routing.asp',
            '/dhcp.asp', '/dns.asp', '/qos.asp',
            '/upnp.asp', '/ddns.asp', '/vpn.asp',

            # CGI endpoints
            '/login.cgi', '/logout.cgi', '/apply.cgi',
            '/get.cgi', '/set.cgi', '/status.cgi',

            # ASP endpoints from common patterns
            '/asp/GetRandCount.asp', '/asp/GetRandInfo.asp',
            '/asp/status.asp', '/asp/info.asp',

            # Frame pages
            '/htm/main.htm', '/html/main.html',
            '/frame.html', '/frameset.html',

            # Resource directories (will try to list)
            '/resource/', '/images/', '/js/', '/css/',
            '/Cuscss/', '/frameaspdes/',
        ]

        for page in common_pages:
            to_visit.add(f"{self.base_url}{page}")

        # Counter for tracking progress
        previous_visited_count = 0
        iteration = 0

        # Crawl pages recursively until no new URLs are found
        while to_visit:
            iteration += 1

            # Safety check: prevent infinite loops
            if iteration > self.max_iterations:
                logger.warning(f"Reached maximum iteration limit ({self.max_iterations}). Stopping crawl.")
                logger.warning(f"There are still {len(to_visit)} URLs in queue that were not visited.")
                break

            current_batch_size = len(to_visit)

            logger.info(f"=== Iteration {iteration}: {current_batch_size} URLs in queue, {len(self.visited_urls)} visited ===")

            # Process current batch
            current_batch = list(to_visit)
            to_visit.clear()

            for url in current_batch:
                # Skip if already visited
                if url in self.visited_urls:
                    continue

                # Crawl page and get new URLs
                new_urls = self.crawl_page(url)

                # Add new URLs to visit queue
                for new_url in new_urls:
                    if new_url not in self.visited_urls:
                        to_visit.add(new_url)

            # Check if we discovered any new URLs this iteration
            current_visited_count = len(self.visited_urls)
            new_discoveries = current_visited_count - previous_visited_count
            logger.info(f"Iteration {iteration} complete: {new_discoveries} new URLs discovered")

            previous_visited_count = current_visited_count

            # Safety check: if no new URLs discovered in this iteration, we're done
            if not to_visit:
                logger.info("No more URLs to crawl - exhaustive crawl complete!")
                break

        logger.info(f"=== Crawling complete ===")
        logger.info(f"Total iterations: {iteration}")
        logger.info(f"Total URLs visited: {len(self.visited_urls)}")
        logger.info(f"Total files downloaded: {len(self.downloaded_files)}")

        # Print some statistics
        file_types = {}
        for url in self.visited_urls:
            ext = Path(urlparse(url).path).suffix or 'no_extension'
            file_types[ext] = file_types.get(ext, 0) + 1

        logger.info("File types discovered:")
        for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {ext}: {count}")

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
    parser.add_argument(
        '--max-iterations',
        type=int,
        default=50,
        help='Maximum crawling iterations (default: 50)'
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
        args.output,
        args.max_iterations
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
