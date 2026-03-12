"""Tests for specialized extraction plugin."""

import unittest

from web_crawler.plugins.specialized_extractor import SpecializedExtractorPlugin


class TestSpecializedExtractor(unittest.TestCase):
    """Tests for the SpecializedExtractorPlugin."""

    def setUp(self):
        self.plugin = SpecializedExtractorPlugin()

    def test_google_drive_links(self):
        body = '''
        <a href="https://drive.google.com/file/d/1aBcDeFgHiJkLmNoPqRs/view">Download</a>
        <a href="https://drive.google.com/open?id=2xYzAbCdEfGhIjKlMn">Open</a>
        <a href="https://docs.google.com/document/d/3pQrStUvWxYzAbCd/edit">Doc</a>
        '''
        links = self.plugin.extract_links("http://example.com", body, "text/html")
        gdrive_links = [l for l in links if "google.com" in l]
        self.assertTrue(len(gdrive_links) >= 3)

    def test_iframe_extraction(self):
        body = '<iframe src="https://youtube.com/embed/abc123"></iframe>'
        links = self.plugin.extract_links("http://example.com", body, "text/html")
        self.assertTrue(any("youtube.com" in l for l in links))

    def test_meta_refresh_redirect(self):
        body = '<meta http-equiv="refresh" content="5;url=https://new.example.com/page">'
        links = self.plugin.extract_links("http://example.com", body, "text/html")
        self.assertTrue(any("new.example.com" in l for l in links))

    def test_js_redirect_window_location(self):
        body = 'window.location.href = "https://redirect.example.com/target";'
        links = self.plugin.extract_links("http://example.com", body, "text/html")
        self.assertTrue(any("redirect.example.com" in l for l in links))

    def test_js_redirect_location_replace(self):
        body = 'location.replace("https://other.example.com/page");'
        links = self.plugin.extract_links("http://example.com", body, "text/html")
        self.assertTrue(any("other.example.com" in l for l in links))

    def test_data_src_lazy_load(self):
        body = '<img data-src="https://cdn.example.com/image.jpg">'
        links = self.plugin.extract_links("http://example.com", body, "text/html")
        self.assertTrue(any("cdn.example.com" in l for l in links))

    def test_base64_encoded_urls(self):
        import base64
        url = "https://hidden.example.com/secret"
        encoded = base64.b64encode(url.encode()).decode()
        body = f'var url = atob("{encoded}");'
        links = self.plugin.extract_links("http://example.com", body, "text/html")
        self.assertIn(url, links)

    def test_relative_iframe_resolved(self):
        body = '<iframe src="/embed/video"></iframe>'
        links = self.plugin.extract_links("http://example.com/page", body, "text/html")
        self.assertTrue(any("example.com/embed/video" in l for l in links))

    def test_non_html_skipped(self):
        body = '<iframe src="https://youtube.com/embed/abc"></iframe>'
        links = self.plugin.extract_links("http://example.com", body, "image/png")
        self.assertEqual(len(links), 0)

    def test_javascript_content_type(self):
        body = 'window.location.href = "https://redirect.example.com/js";'
        links = self.plugin.extract_links(
            "http://example.com", body, "application/javascript"
        )
        self.assertTrue(any("redirect.example.com" in l for l in links))


if __name__ == "__main__":
    unittest.main()
