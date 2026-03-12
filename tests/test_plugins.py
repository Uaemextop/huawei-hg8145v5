"""Tests for the plugin architecture."""

import argparse
import unittest

from web_crawler.plugins.base import CrawlerPlugin
from web_crawler.plugins.registry import PluginRegistry


class DummyPlugin(CrawlerPlugin):
    name = "dummy"
    priority = 50

    def detect_technology(self, url, headers, body):
        if "wordpress" in body.lower():
            return ["test_wp"]
        return []


class HighPriorityPlugin(CrawlerPlugin):
    name = "high_priority"
    priority = 1


class LowPriorityPlugin(CrawlerPlugin):
    name = "low_priority"
    priority = 999


class TestCrawlerPlugin(unittest.TestCase):
    """Tests for the CrawlerPlugin base class."""

    def test_default_hooks_are_noop(self):
        plugin = DummyPlugin()
        # before_request returns headers unchanged
        headers = {"User-Agent": "test"}
        self.assertEqual(plugin.before_request("http://x", headers), headers)
        # detect_protection returns empty
        self.assertEqual(plugin.detect_protection("http://x", {}, ""), [])
        # extract_links returns empty set
        self.assertEqual(plugin.extract_links("http://x", "", "text/html"), set())
        # extract_seed_urls returns empty list
        self.assertEqual(plugin.extract_seed_urls(), [])
        # on_discovery returns True
        self.assertTrue(plugin.on_discovery("http://x"))

    def test_detect_technology_override(self):
        plugin = DummyPlugin()
        self.assertEqual(
            plugin.detect_technology("http://x", {}, "wp-content wordpress"),
            ["test_wp"],
        )
        self.assertEqual(
            plugin.detect_technology("http://x", {}, "plain page"),
            [],
        )

    def test_register_cli_args_noop(self):
        plugin = DummyPlugin()
        parser = argparse.ArgumentParser()
        # Should not raise
        plugin.register_cli_args(parser)

    def test_configure_noop(self):
        plugin = DummyPlugin()
        args = argparse.Namespace(foo="bar")
        # Should not raise
        plugin.configure(args)


class TestPluginRegistry(unittest.TestCase):
    """Tests for the PluginRegistry."""

    def test_register_and_access(self):
        reg = PluginRegistry()
        p = DummyPlugin()
        reg.register(p)
        self.assertEqual(len(reg.plugins), 1)
        self.assertIs(reg.plugins[0], p)

    def test_get_by_name(self):
        reg = PluginRegistry()
        p = DummyPlugin()
        reg.register(p)
        self.assertIs(reg.get("dummy"), p)
        self.assertIsNone(reg.get("nonexistent"))

    def test_priority_ordering(self):
        reg = PluginRegistry()
        low = LowPriorityPlugin()
        high = HighPriorityPlugin()
        reg.register(low)
        reg.register(high)
        self.assertEqual(reg.plugins[0].name, "high_priority")
        self.assertEqual(reg.plugins[1].name, "low_priority")

    def test_auto_discover(self):
        reg = PluginRegistry()
        reg.auto_discover()
        names = {p.name for p in reg.plugins}
        self.assertIn("tech_detector", names)
        self.assertIn("waf_detector", names)
        self.assertIn("specialized_extractor", names)

    def test_detect_technologies(self):
        reg = PluginRegistry()
        reg.auto_discover()
        techs = reg.detect_technologies(
            "http://example.com",
            {"Server": "nginx", "X-Powered-By": "PHP/8.2"},
            "<html>wp-content wp-includes</html>",
        )
        self.assertIn("nginx", techs)
        self.assertIn("php", techs)
        self.assertIn("wordpress", techs)

    def test_detect_protections(self):
        reg = PluginRegistry()
        reg.auto_discover()
        prots = reg.detect_protections(
            "http://example.com",
            {"cf-ray": "abc123", "Server": "cloudflare"},
            "<html>cf-browser-verification</html>",
        )
        self.assertIn("cloudflare", prots)

    def test_collect_extra_links(self):
        reg = PluginRegistry()
        reg.auto_discover()
        links = reg.collect_extra_links(
            "http://example.com/page",
            '<iframe src="https://youtube.com/embed/abc"></iframe>',
            "text/html",
        )
        self.assertTrue(any("youtube.com" in l for l in links))

    def test_call_hook(self):
        reg = PluginRegistry()
        p = DummyPlugin()
        reg.register(p)
        results = reg.call_hook("detect_technology", "http://x", {}, "wordpress")
        self.assertEqual(results, [["test_wp"]])


class TestPluginRegistryErrorHandling(unittest.TestCase):
    """Error-handling tests for the plugin registry."""

    def test_call_hook_handles_exception(self):
        class BadPlugin(CrawlerPlugin):
            name = "bad"
            def detect_technology(self, url, headers, body):
                raise RuntimeError("boom")

        reg = PluginRegistry()
        reg.register(BadPlugin())
        # Should not raise; returns empty result for the failed plugin
        results = reg.call_hook("detect_technology", "http://x", {}, "")
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
