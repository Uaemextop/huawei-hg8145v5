"""Tests verifying that the URL link crawler has been removed."""

import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path


class TestLinkCrawlerRemoved(unittest.TestCase):
    """Verify that the URL link extraction code is no longer active."""

    def test_extract_links_not_imported_in_engine(self):
        """engine.py must not import extract_links."""
        import crawl4ai.extensions.crawler.engine as engine_mod
        self.assertFalse(
            hasattr(engine_mod, "extract_links"),
            "extract_links should not be imported in engine.py",
        )

    def test_parse_local_file_returns_zero(self):
        """_parse_local_file should return 0 (no link extraction)."""
        from crawl4ai.extensions.crawler.engine import Crawler
        crawler = Crawler.__new__(Crawler)
        result = crawler._parse_local_file(Path("/nonexistent"), "https://x")
        self.assertEqual(result, 0)

    def test_extraction_module_still_exists(self):
        """The extraction module should still be importable for
        other consumers, even though the engine no longer uses it."""
        from crawl4ai.extensions.extraction import extract_links, extract_all
        self.assertTrue(callable(extract_links))
        self.assertTrue(callable(extract_all))


if __name__ == "__main__":
    unittest.main()
