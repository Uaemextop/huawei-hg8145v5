"""Tests for the plugin system, pipeline, and detection engines."""

import unittest

from web_crawler.plugins.base import BasePlugin, PluginRegistry, load_plugins
from web_crawler.engine.pipeline import Pipeline, PageResult


class TestPluginRegistry(unittest.TestCase):
    """Tests for plugin registration and discovery."""

    def setUp(self):
        # Store original plugins and restore after test
        self._original = list(PluginRegistry._plugins)

    def tearDown(self):
        PluginRegistry._plugins = self._original

    def test_load_plugins_returns_list(self):
        plugins = load_plugins()
        self.assertIsInstance(plugins, list)
        self.assertTrue(len(plugins) > 0)

    def test_all_plugins_have_name_and_kind(self):
        plugins = load_plugins()
        for p in plugins:
            self.assertTrue(p.name, f"Plugin {p.__class__.__name__} has no name")
            self.assertTrue(p.kind, f"Plugin {p.__class__.__name__} has no kind")

    def test_by_kind_filters_correctly(self):
        load_plugins()
        tech = PluginRegistry.by_kind("tech_detector")
        waf = PluginRegistry.by_kind("waf_detector")
        self.assertTrue(len(tech) >= 1)
        self.assertTrue(len(waf) >= 1)
        for p in tech:
            self.assertEqual(p.kind, "tech_detector")
        for p in waf:
            self.assertEqual(p.kind, "waf_detector")

    def test_clear_removes_all(self):
        load_plugins()
        self.assertTrue(len(PluginRegistry.all()) > 0)
        PluginRegistry.clear()
        self.assertEqual(len(PluginRegistry.all()), 0)

    def test_register_adds_plugin(self):
        PluginRegistry.clear()

        class _TestPlugin(BasePlugin):
            name = "test_plugin"
            kind = "test"

        # Metaclass auto-registers
        self.assertEqual(len(PluginRegistry.all()), 1)
        self.assertEqual(PluginRegistry.all()[0].name, "test_plugin")


class TestTechDetection(unittest.TestCase):
    """Tests for the technology detection plugin."""

    def setUp(self):
        load_plugins()
        self.pipeline = Pipeline()

    def test_detect_wordpress(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><script src="/wp-content/themes/x/app.js"></script></html>',
            base="https://example.com",
        )
        names = [t["name"] for t in result.technologies]
        self.assertIn("WordPress", names)
        self.assertTrue(result.is_wordpress)

    def test_detect_react(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><div data-reactroot></div></html>',
            base="https://example.com",
        )
        names = [t["name"] for t in result.technologies]
        self.assertIn("React", names)

    def test_detect_nginx_from_headers(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html", "Server": "nginx/1.24.0"},
            body="<html><body>Hello</body></html>",
            base="https://example.com",
        )
        names = [t["name"] for t in result.technologies]
        self.assertIn("Nginx", names)

    def test_detect_django_from_cookies(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><input name="csrfmiddlewaretoken"></html>',
            base="https://example.com",
            cookies={"csrftoken": "abc123"},
        )
        names = [t["name"] for t in result.technologies]
        self.assertIn("Django", names)

    def test_detect_cloudflare_cdn(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "CF-RAY": "abc123",
                "Server": "cloudflare",
            },
            body="<html><body>Hello</body></html>",
            base="https://example.com",
        )
        names = [t["name"] for t in result.technologies]
        self.assertIn("Cloudflare CDN", names)

    def test_no_duplicates(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><script src="/wp-content/x.js"></script>'
                 '<meta name="generator" content="WordPress 6.4"></html>',
            base="https://example.com",
        )
        names = [t["name"] for t in result.technologies]
        self.assertEqual(names.count("WordPress"), 1)


class TestWAFDetection(unittest.TestCase):
    """Tests for the WAF detection plugin."""

    def setUp(self):
        load_plugins()
        self.pipeline = Pipeline()

    def test_detect_cloudflare_waf(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=403,
            headers={"Content-Type": "text/html", "cf-mitigated": "challenge"},
            body="<html>Attention Required! | Cloudflare</html>",
            base="https://example.com",
        )
        self.assertIn("cloudflare", result.protections)

    def test_no_false_positive(self):
        result = self.pipeline.process(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html><body>Normal page content</body></html>",
            base="https://example.com",
        )
        self.assertEqual(result.protections, [])


class TestEndpointDiscovery(unittest.TestCase):
    """Tests for the endpoint discovery plugin."""

    def setUp(self):
        load_plugins()
        self.pipeline = Pipeline()

    def test_discover_api_endpoints(self):
        result = self.pipeline.process(
            url="https://example.com/page",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='''<html><script>
                fetch('/api/v1/users');
                axios.get('/rest/data');
            </script></html>''',
            base="https://example.com",
        )
        urls = {u for u in result.discovered_links}
        self.assertTrue(any("/api/v1/users" in u for u in urls))

    def test_discover_iframes(self):
        result = self.pipeline.process(
            url="https://example.com/page",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><iframe src="https://example.com/embed"></iframe></html>',
            base="https://example.com",
        )
        self.assertIn("https://example.com/embed", result.discovered_links)

    def test_discover_wp_plugin_slugs(self):
        result = self.pipeline.process(
            url="https://example.com/page",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><link href="/wp-content/plugins/jetpack/style.css"></html>',
            base="https://example.com",
        )
        self.assertTrue(
            any("jetpack" in u for u in result.discovered_links),
            f"Expected jetpack link in {result.discovered_links}",
        )


class TestExternalLinkClassification(unittest.TestCase):
    """Tests for external link classification."""

    def setUp(self):
        load_plugins()
        self.pipeline = Pipeline()

    def test_classify_google_drive(self):
        result = self.pipeline.process(
            url="https://example.com/page",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><a href="https://drive.google.com/file/d/xxx">Download</a></html>',
            base="https://example.com",
        )
        self.assertTrue(len(result.external_links) >= 1)
        services = [l["service"] for l in result.external_links]
        self.assertIn("google_drive", services)

    def test_classify_mega(self):
        result = self.pipeline.process(
            url="https://example.com/page",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><a href="https://mega.nz/folder/abc123">Mega</a></html>',
            base="https://example.com",
        )
        services = [l["service"] for l in result.external_links]
        self.assertIn("mega", services)

    def test_no_classify_internal_links(self):
        result = self.pipeline.process(
            url="https://example.com/page",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><a href="https://example.com/internal">Link</a></html>',
            base="https://example.com",
        )
        self.assertEqual(result.external_links, [])


class TestPageResult(unittest.TestCase):
    """Tests for PageResult dataclass."""

    def test_has_protection(self):
        r = PageResult(url="https://x.com", protections=["cloudflare"])
        self.assertTrue(r.has_protection)

    def test_no_protection(self):
        r = PageResult(url="https://x.com")
        self.assertFalse(r.has_protection)

    def test_is_wordpress(self):
        r = PageResult(
            url="https://x.com",
            technologies=[{"name": "WordPress", "category": "cms"}],
        )
        self.assertTrue(r.is_wordpress)

    def test_not_wordpress(self):
        r = PageResult(
            url="https://x.com",
            technologies=[{"name": "Django", "category": "backend_framework"}],
        )
        self.assertFalse(r.is_wordpress)


class TestScheduler(unittest.TestCase):
    """Tests for the URL scheduler."""

    def test_enqueue_and_dequeue(self):
        from web_crawler.engine.scheduler import Scheduler
        s = Scheduler(delay=0)
        self.assertTrue(s.enqueue("https://example.com/a", 0))
        self.assertFalse(s.is_empty)
        task = s.next_task()
        self.assertIsNotNone(task)
        self.assertEqual(task.url, "https://example.com/a")
        self.assertTrue(s.is_empty)

    def test_dedup(self):
        from web_crawler.engine.scheduler import Scheduler
        s = Scheduler(delay=0)
        self.assertTrue(s.enqueue("https://example.com/a", 0))
        self.assertFalse(s.enqueue("https://example.com/a", 0))
        self.assertEqual(s.queue_size, 1)

    def test_depth_limit(self):
        from web_crawler.engine.scheduler import Scheduler
        s = Scheduler(delay=0, max_depth=2)
        self.assertTrue(s.enqueue("https://example.com/a", 1))
        self.assertTrue(s.enqueue("https://example.com/b", 2))
        self.assertFalse(s.enqueue("https://example.com/c", 3))

    def test_priority(self):
        from web_crawler.engine.scheduler import Scheduler
        s = Scheduler(delay=0)
        s.enqueue("https://example.com/a", 0)
        s.enqueue("https://example.com/b", 0, priority=True)
        task = s.next_task()
        self.assertEqual(task.url, "https://example.com/b")

    def test_bulk_enqueue(self):
        from web_crawler.engine.scheduler import Scheduler
        s = Scheduler(delay=0)
        added = s.bulk_enqueue([
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/a",  # duplicate
        ], depth=0)
        self.assertEqual(added, 2)
        self.assertEqual(s.queue_size, 2)

    def test_mark_visited(self):
        from web_crawler.engine.scheduler import Scheduler
        s = Scheduler(delay=0)
        s.mark_visited("https://example.com/a")
        self.assertTrue(s.is_visited("https://example.com/a"))
        self.assertFalse(s.enqueue("https://example.com/a", 0))


if __name__ == "__main__":
    unittest.main()
