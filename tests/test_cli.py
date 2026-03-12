"""Tests for CLI argument parsing and helper utilities."""

import unittest
from unittest.mock import patch

from web_crawler.cli import parse_args, _parse_extensions


class TestParseExtensions(unittest.TestCase):
    def test_all_returns_empty(self):
        self.assertEqual(_parse_extensions("all"), frozenset())

    def test_empty_returns_empty(self):
        self.assertEqual(_parse_extensions(""), frozenset())

    def test_single_extension(self):
        result = _parse_extensions("zip")
        self.assertIn(".zip", result)

    def test_multiple_extensions(self):
        result = _parse_extensions("zip,exe,rar")
        self.assertEqual(result, frozenset({".zip", ".exe", ".rar"}))

    def test_dot_prefix_handling(self):
        result = _parse_extensions(".zip,.exe")
        self.assertEqual(result, frozenset({".zip", ".exe"}))

    def test_whitespace_handling(self):
        result = _parse_extensions(" zip , exe , rar ")
        self.assertEqual(result, frozenset({".zip", ".exe", ".rar"}))

    def test_all_as_empty_false(self):
        result = _parse_extensions("all", all_as_empty=False)
        self.assertIn(".zip", result)
        self.assertIn(".exe", result)


class TestParseArgs(unittest.TestCase):
    def test_minimal_args(self):
        with patch("sys.argv", ["cli.py", "https://example.com"]):
            args = parse_args()
        self.assertEqual(args.url, "https://example.com")
        self.assertEqual(args.depth, 0)
        self.assertEqual(args.delay, 0.25)

    def test_no_ai_captcha_args(self):
        """AI CAPTCHA arguments should no longer exist."""
        with patch("sys.argv", ["cli.py", "https://example.com"]):
            args = parse_args()
        self.assertFalse(hasattr(args, "ai_captcha"))
        self.assertFalse(hasattr(args, "ai_captcha_url"))
        self.assertFalse(hasattr(args, "ai_captcha_type"))
        self.assertFalse(hasattr(args, "ai_model"))
        self.assertFalse(hasattr(args, "ai_login_user"))
        self.assertFalse(hasattr(args, "ai_login_pass"))

    def test_depth_flag(self):
        with patch("sys.argv", ["cli.py", "--depth", "3", "https://example.com"]):
            args = parse_args()
        self.assertEqual(args.depth, 3)

    def test_concurrency_default(self):
        with patch("sys.argv", ["cli.py", "https://example.com"]):
            args = parse_args()
        self.assertEqual(args.concurrency, "auto")


if __name__ == "__main__":
    unittest.main()
