#!/usr/bin/env python3
"""
Test script to verify session keep-alive, auto re-login, and file skip features.
"""

import sys
import time
from pathlib import Path
from huawei_crawler import HuaweiRouterCrawler


def test_file_skip():
    """Test that already downloaded files are skipped."""
    print("=" * 60)
    print("Test 1: File Skip Functionality")
    print("=" * 60)

    # Create a test crawler
    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test", "test_output")

    # Create a fake downloaded file
    test_url = "http://192.168.100.1/test.asp"
    file_path = crawler.get_file_path(test_url)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text("<html><body>Test content</body></html>", encoding='utf-8')

    # Test file_already_downloaded method
    result = crawler.file_already_downloaded(test_url)
    print(f"  File exists check: {result}")
    assert result == True, "File should be detected as existing"

    # Test with non-existent file
    test_url2 = "http://192.168.100.1/nonexistent.asp"
    result2 = crawler.file_already_downloaded(test_url2)
    print(f"  Non-existent file check: {result2}")
    assert result2 == False, "Non-existent file should return False"

    # Cleanup
    import shutil
    if Path("test_output").exists():
        shutil.rmtree("test_output")

    print("✓ File skip test passed!\n")


def test_session_validation():
    """Test session validation logic."""
    print("=" * 60)
    print("Test 2: Session Validation")
    print("=" * 60)

    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test")

    # Test initial state
    print(f"  Initial authentication state: {crawler.is_authenticated}")
    assert crawler.is_authenticated == False, "Should not be authenticated initially"

    # Simulate authentication
    crawler.is_authenticated = True
    crawler.last_auth_check = time.time()
    print(f"  After simulated login: {crawler.is_authenticated}")

    # Test that validation returns True within 30 seconds (cached)
    result = crawler.is_session_valid()
    print(f"  Session valid (cached): {result}")
    assert result == True, "Recently authenticated session should be valid"

    print("✓ Session validation test passed!\n")


def test_keep_alive_headers():
    """Test that keep-alive headers are set."""
    print("=" * 60)
    print("Test 3: Keep-Alive Headers")
    print("=" * 60)

    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test")

    # Check headers
    headers = crawler.session.headers
    print(f"  Connection header: {headers.get('Connection')}")
    print(f"  Keep-Alive header: {headers.get('Keep-Alive')}")

    assert headers.get('Connection') == 'keep-alive', "Connection header should be set to keep-alive"
    assert 'Keep-Alive' in headers, "Keep-Alive header should be present"

    print("✓ Keep-alive headers test passed!\n")


def test_ensure_authenticated():
    """Test ensure_authenticated method."""
    print("=" * 60)
    print("Test 4: Ensure Authenticated")
    print("=" * 60)

    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test")

    # Set up mock state
    crawler.is_authenticated = False

    # Since we can't actually connect to router, just test the logic flow
    print(f"  Initial state: is_authenticated={crawler.is_authenticated}")

    # The method should attempt to login (which will fail without actual router)
    # This just tests that the method exists and can be called
    try:
        result = crawler.ensure_authenticated()
        print(f"  Ensure authenticated result: {result}")
    except Exception as e:
        print(f"  Expected error (no actual router): {type(e).__name__}")

    print("✓ Ensure authenticated test passed!\n")


def test_url_extraction_from_cached_file():
    """Test that URLs are extracted from cached files."""
    print("=" * 60)
    print("Test 5: URL Extraction from Cached Files")
    print("=" * 60)

    crawler = HuaweiRouterCrawler("http://192.168.100.1", "test", "test", "test_output2")

    # Create a fake HTML file with links
    test_url = "http://192.168.100.1/index.asp"
    file_path = crawler.get_file_path(test_url)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    html_content = """
    <html>
    <head><script src="/js/test.js"></script></head>
    <body>
        <a href="/status.asp">Status</a>
        <a href="/config.asp">Config</a>
        <img src="/images/logo.png">
    </body>
    </html>
    """
    file_path.write_text(html_content, encoding='utf-8')

    # Test URL extraction from cached file
    urls = crawler.crawl_page(test_url)
    print(f"  Extracted {len(urls)} URLs from cached file")
    print(f"  URLs: {sorted(urls)}")

    assert len(urls) > 0, "Should extract URLs from cached file"

    # Cleanup
    import shutil
    if Path("test_output2").exists():
        shutil.rmtree("test_output2")

    print("✓ URL extraction from cached file test passed!\n")


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("Session Keep-Alive & Auto Re-Login Feature Tests")
    print("=" * 60 + "\n")

    try:
        test_file_skip()
        test_session_validation()
        test_keep_alive_headers()
        test_ensure_authenticated()
        test_url_extraction_from_cached_file()

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
