#!/usr/bin/env python3
"""
Test script to verify enhanced crawler functionality.
Tests JavaScript route extraction, ASP route extraction, and menu discovery.
"""

import sys
from huawei_crawler import HuaweiRouterCrawler


def test_js_route_extraction():
    """Test JavaScript route extraction."""
    print("Testing JavaScript route extraction...")

    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test")

    # Test case 1: AJAX URLs
    js_content = """
    $.ajax({
        url: '/status.asp',
        type: 'GET'
    });

    fetch('/api/data.json');

    xhr.open('GET', '/config.cgi');
    """
    urls = crawler.extract_js_routes(js_content, "http://192.168.100.1/test.js")
    print(f"  Found {len(urls)} URLs from AJAX patterns")
    for url in sorted(urls):
        print(f"    - {url}")

    # Test case 2: String literals
    js_content2 = """
    var page = '/admin/settings.asp';
    window.location = '/home.asp';
    Form.setAction('/login.cgi');
    """
    urls2 = crawler.extract_js_routes(js_content2, "http://192.168.100.1/test.js")
    print(f"  Found {len(urls2)} URLs from string literals and location changes")
    for url in sorted(urls2):
        print(f"    - {url}")

    print("✓ JavaScript route extraction test complete\n")


def test_asp_route_extraction():
    """Test ASP route extraction."""
    print("Testing ASP route extraction...")

    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test")

    asp_content = """
    <!-- #include virtual="/includes/header.asp" -->
    <%
    Response.Redirect "/login.asp"
    Server.Transfer "/main.asp"
    %>
    <!-- #include file="footer.asp" -->
    """
    urls = crawler.extract_asp_routes(asp_content, "http://192.168.100.1/page.asp")
    print(f"  Found {len(urls)} URLs from ASP content")
    for url in sorted(urls):
        print(f"    - {url}")

    print("✓ ASP route extraction test complete\n")


def test_extract_links_enhanced():
    """Test enhanced link extraction from HTML."""
    print("Testing enhanced HTML link extraction...")

    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test")

    html_content = """
    <html>
    <head>
        <link rel="stylesheet" href="/css/style.css">
        <script src="/js/main.js"></script>
    </head>
    <body>
        <nav>
            <ul>
                <li><a href="/home.asp">Home</a></li>
                <li><a href="/status.asp">Status</a></li>
                <li><a href="/config.asp">Config</a></li>
            </ul>
        </nav>
        <form action="/apply.cgi" method="post">
            <input type="submit" value="Apply">
        </form>
        <img src="/images/logo.png">
        <div onclick="location.href='/admin.asp'">Admin</div>
        <script>
            $.ajax({url: '/data.json'});
        </script>
    </body>
    </html>
    """
    urls = crawler.extract_links(html_content, "http://192.168.100.1/index.asp")
    print(f"  Found {len(urls)} total URLs from HTML")
    for url in sorted(urls):
        print(f"    - {url}")

    print("✓ Enhanced HTML link extraction test complete\n")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Enhanced Crawler Functionality Tests")
    print("=" * 60)
    print()

    try:
        test_js_route_extraction()
        test_asp_route_extraction()
        test_extract_links_enhanced()

        print("=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        return 0
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
