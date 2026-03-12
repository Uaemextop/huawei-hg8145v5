"""
Tests for the extraction features added for androidacy.com crawling.

Covers:
  - XML sitemap <loc> extraction (links.py)
  - data-src attribute extraction on <script> tags (html_parser.py)
  - Speculation rules URL extraction (html_parser.py)
  - Percent-encoded data:text/javascript decoding (html_parser.py)
  - JSON-LD URL extraction (html_parser.py)
  - JSON path extraction with WP loop filtering (json_extract.py)
  - Brotli encoding omission in session.py (Accept-Encoding header)
"""

import unittest

from web_crawler.extraction.links import extract_links, _extract_xml_loc_urls
from web_crawler.extraction.html_parser import (
    extract_html_attrs,
    _extract_jsonld_urls,
    _extract_speculation_urls,
)
from web_crawler.extraction.json_extract import extract_json_paths
from web_crawler.session import build_session


BASE = "https://www.example.com"
PAGE = "https://www.example.com/page"


# ------------------------------------------------------------------
# XML sitemap <loc> extraction
# ------------------------------------------------------------------

class TestXmlLocExtraction(unittest.TestCase):
    """Tests for _extract_xml_loc_urls and the XML branch of extract_links."""

    def test_basic_loc(self):
        xml = (
            '<?xml version="1.0"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>https://www.example.com/page1</loc></url>'
            '<url><loc>https://www.example.com/page2</loc></url>'
            '</urlset>'
        )
        urls = _extract_xml_loc_urls(xml, PAGE, BASE)
        self.assertIn("https://www.example.com/page1", urls)
        self.assertIn("https://www.example.com/page2", urls)
        self.assertEqual(len(urls), 2)

    def test_cdata_wrapped_loc(self):
        xml = (
            '<urlset><url>'
            '<loc><![CDATA[https://www.example.com/cdata-page]]></loc>'
            '</url></urlset>'
        )
        urls = _extract_xml_loc_urls(xml, PAGE, BASE)
        self.assertIn("https://www.example.com/cdata-page", urls)

    def test_image_loc(self):
        xml = (
            '<urlset xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">'
            '<url><loc>https://www.example.com/page</loc>'
            '<image:image><image:loc>https://www.example.com/img.jpg</image:loc></image:image>'
            '</url></urlset>'
        )
        urls = _extract_xml_loc_urls(xml, PAGE, BASE)
        self.assertIn("https://www.example.com/page", urls)
        self.assertIn("https://www.example.com/img.jpg", urls)

    def test_sitemap_index(self):
        xml = (
            '<sitemapindex>'
            '<sitemap><loc>https://www.example.com/sitemap-posts.xml</loc></sitemap>'
            '<sitemap><loc>https://www.example.com/sitemap-pages.xml</loc></sitemap>'
            '</sitemapindex>'
        )
        urls = _extract_xml_loc_urls(xml, PAGE, BASE)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://www.example.com/sitemap-posts.xml", urls)

    def test_extract_links_xml_content_type(self):
        """XML content served as text/xml should trigger loc extraction."""
        xml = '<urlset><url><loc>https://www.example.com/from-xml</loc></url></urlset>'
        urls = extract_links(xml, "text/xml", PAGE, BASE)
        self.assertIn("https://www.example.com/from-xml", urls)

    def test_extract_links_xml_extension(self):
        """Files ending in .xml should trigger loc extraction even with wrong CT."""
        xml = '<urlset><url><loc>https://www.example.com/from-ext</loc></url></urlset>'
        urls = extract_links(xml, "text/html",
                             "https://www.example.com/sitemap.xml", BASE)
        self.assertIn("https://www.example.com/from-ext", urls)

    def test_empty_loc(self):
        xml = '<urlset><url><loc></loc></url></urlset>'
        urls = _extract_xml_loc_urls(xml, PAGE, BASE)
        self.assertEqual(len(urls), 0)

    def test_whitespace_in_loc(self):
        xml = (
            '<urlset><url><loc>  \n'
            '  https://www.example.com/spaced  \n'
            '</loc></url></urlset>'
        )
        urls = _extract_xml_loc_urls(xml, PAGE, BASE)
        self.assertIn("https://www.example.com/spaced", urls)


# ------------------------------------------------------------------
# data-src extraction on <script> tags
# ------------------------------------------------------------------

class TestDataSrcExtraction(unittest.TestCase):
    """Tests for data-src attribute extraction in html_parser."""

    def test_script_data_src_url(self):
        """<script data-src="url"> should be extracted."""
        html = '<script data-src="/sdk.js"></script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/sdk.js", urls)

    def test_script_data_src_data_uri(self):
        """data:text/javascript,... data-src should be decoded and JS-parsed."""
        import urllib.parse
        js_code = 'var api_url = "/api/endpoint";'
        encoded = "data:text/javascript," + urllib.parse.quote(js_code)
        html = f'<script data-src="{encoded}"></script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/api/endpoint", urls)

    def test_non_data_uri_not_decoded(self):
        """Regular data-src URLs should be extracted as normal src."""
        html = '<script data-src="/script.js"></script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/script.js", urls)

    def test_inline_script_without_data_src(self):
        """Inline scripts without data-src should still be JS-parsed."""
        html = '<script>fetch("/api/items")</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/api/items", urls)


# ------------------------------------------------------------------
# Speculation rules URL extraction
# ------------------------------------------------------------------

class TestSpeculationRules(unittest.TestCase):
    """Tests for <script type="speculationrules"> parsing."""

    def test_prefetch_urls(self):
        html = '<script type="speculationrules">{"prefetch": [{"source": "list", "urls": ["/page1", "/page2"]}]}</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/page1", urls)
        self.assertIn("https://www.example.com/page2", urls)

    def test_prerender_urls(self):
        html = '<script type="speculationrules">{"prerender": [{"source": "list", "urls": ["/prerender-target"]}]}</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/prerender-target", urls)

    def test_document_rules_no_urls(self):
        """Document rules with href_matches but no urls array should not crash."""
        html = '''
        <script type="speculationrules">
        {"prefetch": [{"source": "document",
          "where": {"href_matches": "/*"},
          "eagerness": "conservative"}]}
        </script>
        '''
        urls = extract_html_attrs(html, PAGE, BASE)
        # No concrete URLs to extract, should not crash
        self.assertIsInstance(urls, set)

    def test_invalid_json_speculation(self):
        """Malformed speculation rules JSON should not crash."""
        html = '<script type="speculationrules">{invalid json</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIsInstance(urls, set)

    def test_extract_speculation_urls_direct(self):
        """Direct test of _extract_speculation_urls helper."""
        collected = []
        spec = {
            "prefetch": [
                {"urls": ["/a", "/b"]},
                {"urls": ["https://www.example.com/c"]},
            ],
            "prerender": [
                {"urls": ["/d"]},
            ],
        }
        _extract_speculation_urls(spec, lambda u, **kw: collected.append(u))
        self.assertEqual(sorted(collected), ["/a", "/b", "/d",
                                              "https://www.example.com/c"])


# ------------------------------------------------------------------
# JSON-LD URL extraction
# ------------------------------------------------------------------

class TestJsonLdExtraction(unittest.TestCase):
    """Tests for JSON-LD structured data URL extraction."""

    def test_video_object_content_url(self):
        html = '<script type="application/ld+json">{"@type": "VideoObject", "contentUrl": "/video.mp4", "thumbnailUrl": "/thumb.jpg"}</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/video.mp4", urls)
        self.assertIn("https://www.example.com/thumb.jpg", urls)

    def test_nested_jsonld(self):
        html = '<script type="application/ld+json">{"@type": "WebPage", "video": {"@type": "VideoObject", "embedUrl": "/embed/v1"}}</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/embed/v1", urls)

    def test_jsonld_array(self):
        html = '<script type="application/ld+json">[{"@type": "Article", "url": "/article1"}, {"@type": "Article", "url": "/article2"}]</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIn("https://www.example.com/article1", urls)
        self.assertIn("https://www.example.com/article2", urls)

    def test_invalid_jsonld(self):
        """Malformed JSON-LD should not crash."""
        html = '<script type="application/ld+json">{bad json</script>'
        urls = extract_html_attrs(html, PAGE, BASE)
        self.assertIsInstance(urls, set)

    def test_extract_jsonld_urls_direct(self):
        """Direct test of _extract_jsonld_urls helper."""
        collected = []
        keys = frozenset({"contentUrl", "url"})
        obj = {
            "contentUrl": "https://cdn.example.com/v.mp4",
            "nested": {
                "url": "/page",
                "other": "not-a-url",
            },
        }
        _extract_jsonld_urls(
            obj, keys,
            lambda u, **kw: collected.append(u),
        )
        self.assertIn("https://cdn.example.com/v.mp4", collected)
        self.assertIn("/page", collected)
        self.assertEqual(len(collected), 2)


# ------------------------------------------------------------------
# JSON path extraction with WP loop filtering
# ------------------------------------------------------------------

class TestJsonPathExtraction(unittest.TestCase):
    """Tests for JSON path extraction and WP REST API loop filtering."""

    def test_basic_url_extraction(self):
        text = '{"link": "https://www.example.com/post/1"}'
        urls = extract_json_paths(text, PAGE, BASE)
        self.assertIn("https://www.example.com/post/1", urls)

    def test_nested_url(self):
        text = '{"data": [{"url": "https://www.example.com/nested"}]}'
        urls = extract_json_paths(text, PAGE, BASE)
        self.assertIn("https://www.example.com/nested", urls)

    def test_relative_path(self):
        text = '{"path": "/api/data"}'
        urls = extract_json_paths(text, PAGE, BASE)
        self.assertIn("https://www.example.com/api/data", urls)

    def test_wp_revision_filtered(self):
        """WP REST API revision links should be filtered out."""
        text = '{"href": "https://www.example.com/wp-json/wp/v2/posts/123/revisions"}'
        urls = extract_json_paths(text, PAGE, BASE)
        self.assertEqual(len(urls), 0)

    def test_wp_paginated_collection_filtered(self):
        """WP REST API paginated collection queries should be filtered."""
        text = '{"href": "https://www.example.com/wp-json/wp/v2/posts?page=2"}'
        urls = extract_json_paths(text, PAGE, BASE)
        self.assertEqual(len(urls), 0)

    def test_wc_cart_filtered(self):
        """WooCommerce cart endpoints should be filtered."""
        text = '{"href": "https://www.example.com/wp-json/wc/store/v1/cart/items"}'
        urls = extract_json_paths(text, PAGE, BASE)
        self.assertEqual(len(urls), 0)

    def test_invalid_json(self):
        """Invalid JSON should return empty set, not crash."""
        urls = extract_json_paths("{bad", PAGE, BASE)
        self.assertEqual(len(urls), 0)

    def test_non_url_strings_skipped(self):
        """Non-URL strings should be skipped."""
        text = '{"name": "hello world", "count": 42}'
        urls = extract_json_paths(text, PAGE, BASE)
        self.assertEqual(len(urls), 0)


# ------------------------------------------------------------------
# Session Accept-Encoding (no brotli)
# ------------------------------------------------------------------

class TestSessionEncoding(unittest.TestCase):
    """Verify that the session does not advertise brotli encoding."""

    def test_no_brotli_in_accept_encoding(self):
        """requests library cannot decode brotli; ensure 'br' is not
        included in Accept-Encoding to prevent binary garbage responses."""
        session = build_session()
        ae = session.headers.get("Accept-Encoding", "")
        self.assertNotIn("br", ae)
        self.assertIn("gzip", ae)
        self.assertIn("deflate", ae)


# ------------------------------------------------------------------
# Master dispatcher routing
# ------------------------------------------------------------------

class TestExtractLinksDispatcher(unittest.TestCase):
    """Tests for the extract_links dispatcher in links.py."""

    def test_html_routes_to_html_parser(self):
        html = '<a href="/link1">link</a>'
        urls = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://www.example.com/link1", urls)

    def test_json_routes_to_json_extract(self):
        text = '{"url": "https://www.example.com/json-link"}'
        urls = extract_links(text, "application/json", PAGE, BASE)
        self.assertIn("https://www.example.com/json-link", urls)

    def test_javascript_content_type(self):
        js = 'window.location = "/js-redirect";'
        urls = extract_links(js, "text/javascript", PAGE, BASE)
        self.assertIn("https://www.example.com/js-redirect", urls)

    def test_php_extension_treated_as_html(self):
        html = '<a href="/php-link">link</a>'
        urls = extract_links(html, "text/plain",
                             "https://www.example.com/page.php", BASE)
        self.assertIn("https://www.example.com/php-link", urls)

    def test_bytes_input_decoded(self):
        html = b'<a href="/bytes-link">link</a>'
        urls = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://www.example.com/bytes-link", urls)


if __name__ == "__main__":
    unittest.main()
