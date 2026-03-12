"""Tests for the log analysis module."""

import tempfile
import unittest
from pathlib import Path

from web_crawler.analysis import LogAnalyser, LogAnalysisResult


class TestLogAnalysisResult(unittest.TestCase):
    """Tests for the LogAnalysisResult dataclass."""

    def test_defaults(self):
        r = LogAnalysisResult()
        self.assertEqual(r.potential_urls, [])
        self.assertEqual(r.interesting_paths, [])
        self.assertEqual(r.repeated_patterns, {})
        self.assertEqual(r.unexplored_links, [])
        self.assertEqual(r.error_summary, {})


class TestLogAnalyser(unittest.TestCase):
    """Tests for the LogAnalyser."""

    def test_analyse_empty_lines(self):
        analyser = LogAnalyser()
        result = analyser.analyse_lines([])
        self.assertEqual(result.potential_urls, [])

    def test_extract_urls_from_lines(self):
        analyser = LogAnalyser()
        result = analyser.analyse_lines([
            "Fetching https://example.com/page1",
            "Found link https://example.com/page2",
            "Error at https://example.com/page3",
        ])
        self.assertEqual(len(result.potential_urls), 3)
        self.assertIn("https://example.com/page1", result.potential_urls)

    def test_extract_paths(self):
        analyser = LogAnalyser()
        result = analyser.analyse_lines([
            "GET /api/v1/users 200",
            "GET /api/v1/users 200",
            "GET /api/v1/users 200",
            "POST /api/v1/login 302",
        ])
        self.assertIn("/api/v1/users", result.repeated_patterns)
        self.assertEqual(result.repeated_patterns["/api/v1/users"], 3)

    def test_extract_redirects(self):
        analyser = LogAnalyser()
        result = analyser.analyse_lines([
            "redirect https://new.example.com/page",
            "-> https://other.example.com/page",
        ])
        # Redirect URLs are discovered as potential URLs or unexplored links
        all_found = result.potential_urls + result.unexplored_links
        self.assertTrue(any("new.example.com" in u for u in all_found))

    def test_error_summary(self):
        analyser = LogAnalyser()
        result = analyser.analyse_lines([
            "GET /page 404 Not Found",
            "GET /other 404 Not Found",
            "GET /broken 500 Internal Server Error",
        ])
        self.assertIn("404", result.error_summary)
        self.assertEqual(result.error_summary["404"], 2)
        self.assertIn("500", result.error_summary)

    def test_interesting_paths(self):
        analyser = LogAnalyser()
        result = analyser.analyse_lines([
            "GET /wp-admin/plugins.php 200",
            "GET /api/config 200",
            "GET /backup/db.sql 403",
        ])
        interesting = result.interesting_paths
        self.assertTrue(
            any("wp-admin" in p for p in interesting)
            or any("api" in p for p in interesting)
        )

    def test_deduplication(self):
        analyser = LogAnalyser()
        result = analyser.analyse_lines([
            "Found https://example.com/page1",
            "Found https://example.com/page1",
            "Found https://example.com/page1",
        ])
        self.assertEqual(len(result.potential_urls), 1)

    def test_analyse_file(self):
        analyser = LogAnalyser()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as f:
            f.write("Fetching https://example.com/test\n")
            f.write("GET /api/data 200\n")
            f.flush()
            result = analyser.analyse_file(f.name)

        self.assertTrue(len(result.potential_urls) >= 1)
        Path(f.name).unlink()

    def test_analyse_missing_file(self):
        analyser = LogAnalyser()
        result = analyser.analyse_file("/tmp/nonexistent_log_file.log")
        self.assertEqual(result.potential_urls, [])


if __name__ == "__main__":
    unittest.main()
