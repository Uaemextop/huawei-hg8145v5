"""Tests for the plugin system."""

import threading
import unittest

from web_crawler.plugins.registry import (
    BasePlugin,
    PluginRegistry,
    VALID_CATEGORIES,
)


class DummyPlugin(BasePlugin):
    @property
    def name(self):
        return "dummy"

    def run(self, context):
        return {"ok": True}


class TestPluginRegistry(unittest.TestCase):
    def test_register_and_get(self):
        reg = PluginRegistry()
        plug = DummyPlugin()
        reg.register_detector(plug)
        self.assertEqual(reg.get_plugin("detector", "dummy"), plug)

    def test_get_plugins_list(self):
        reg = PluginRegistry()
        reg.register_detector(DummyPlugin())
        detectors = reg.get_plugins("detector")
        self.assertEqual(len(detectors), 1)
        self.assertEqual(detectors[0].name, "dummy")

    def test_invalid_category(self):
        reg = PluginRegistry()
        with self.assertRaises(ValueError):
            reg.register("invalid_cat", DummyPlugin())

    def test_get_nonexistent_plugin(self):
        reg = PluginRegistry()
        self.assertIsNone(reg.get_plugin("detector", "nonexistent"))

    def test_get_plugins_empty_category(self):
        reg = PluginRegistry()
        self.assertEqual(reg.get_plugins("extractor"), [])

    def test_discover_loads_builtin_plugins(self):
        reg = PluginRegistry()
        reg.discover()
        # Should at least have waf_detector and tech_detector
        detectors = reg.get_plugins("detector")
        names = [d.name for d in detectors]
        self.assertIn("waf_detector", names)
        self.assertIn("tech_detector", names)

    def test_discover_loads_strategies(self):
        reg = PluginRegistry()
        reg.discover()
        strategies = reg.get_plugins("strategy")
        names = [s.name for s in strategies]
        self.assertIn("wordpress", names)

    def test_thread_safety(self):
        reg = PluginRegistry()
        errors = []

        def register_many(prefix, count):
            for i in range(count):
                class P(BasePlugin):
                    _name = f"{prefix}_{i}"

                    @property
                    def name(self):
                        return self._name

                    def run(self, ctx):
                        return {}

                try:
                    reg.register_detector(P())
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=register_many, args=(f"t{t}", 20))
            for t in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        detectors = reg.get_plugins("detector")
        self.assertEqual(len(detectors), 100)  # 5 threads * 20 plugins


class TestWAFDetectorPlugin(unittest.TestCase):
    def setUp(self):
        self.reg = PluginRegistry()
        self.reg.discover()
        self.waf = self.reg.get_plugin("detector", "waf_detector")

    def test_detects_cloudflare(self):
        result = self.waf.run({
            "headers": {"cf-mitigated": "challenge"},
            "body": "",
        })
        self.assertIn("cloudflare", result["protections"])

    def test_detects_captcha_in_body(self):
        result = self.waf.run({
            "headers": {},
            "body": '<div class="g-recaptcha"></div>',
        })
        self.assertIn("captcha", result["protections"])

    def test_clean_page(self):
        result = self.waf.run({
            "headers": {"server": "Apache/2.4"},
            "body": "<html>Hello</html>",
        })
        self.assertEqual(result["protections"], [])

    def test_permissions_policy_excluded(self):
        result = self.waf.run({
            "headers": {"permissions-policy": "recaptcha.net cloudflare.com"},
            "body": "<html>Normal</html>",
        })
        self.assertNotIn("cloudflare", result["protections"])

    def test_body_truncated_to_8k(self):
        # WAF signature deep in page should be ignored
        body = "x" * 10000 + "cloudflare"
        result = self.waf.run({"headers": {}, "body": body})
        self.assertNotIn("cloudflare", result["protections"])


class TestTechDetectorPlugin(unittest.TestCase):
    def setUp(self):
        self.reg = PluginRegistry()
        self.reg.discover()
        self.tech = self.reg.get_plugin("detector", "tech_detector")

    def test_detects_wordpress(self):
        result = self.tech.run({
            "headers": {},
            "body": '<link rel="stylesheet" href="/wp-content/themes/style.css">',
            "cookies": [],
            "scripts": [],
        })
        names = [t["name"] for t in result["technologies"]]
        self.assertIn("WordPress", names)

    def test_detects_php(self):
        result = self.tech.run({
            "headers": {"x-powered-by": "PHP/8.1"},
            "body": "",
            "cookies": ["PHPSESSID"],
            "scripts": [],
        })
        names = [t["name"] for t in result["technologies"]]
        self.assertIn("PHP", names)

    def test_detects_jquery_from_scripts(self):
        result = self.tech.run({
            "headers": {},
            "body": "",
            "cookies": [],
            "scripts": ["https://cdn.example.com/jquery.min.js"],
        })
        names = [t["name"] for t in result["technologies"]]
        self.assertIn("jQuery", names)

    def test_detects_react(self):
        result = self.tech.run({
            "headers": {},
            "body": '<div id="root" data-reactroot></div>',
            "cookies": [],
            "scripts": [],
        })
        names = [t["name"] for t in result["technologies"]]
        self.assertIn("React", names)

    def test_detects_cloudflare_cdn(self):
        result = self.tech.run({
            "headers": {"server": "cloudflare", "cf-ray": "abc123"},
            "body": "",
            "cookies": [],
            "scripts": [],
        })
        names = [t["name"] for t in result["technologies"]]
        self.assertIn("Cloudflare", names)

    def test_clean_page_no_tech(self):
        result = self.tech.run({
            "headers": {},
            "body": "<html><body>Hello</body></html>",
            "cookies": [],
            "scripts": [],
        })
        self.assertEqual(result["technologies"], [])


if __name__ == "__main__":
    unittest.main()
