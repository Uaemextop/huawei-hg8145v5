"""Tests for the pipeline system."""

import unittest

from web_crawler.pipeline import Pipeline, PipelineStage
from web_crawler.pipeline.builtin_stages import (
    URLDiscoveryStage,
    TechDetectionStage,
    StrategySelectionStage,
    DataProcessingStage,
)
from web_crawler.plugins.registry import PluginRegistry


class EchoStage(PipelineStage):
    """A simple test stage that copies a key."""

    @property
    def name(self):
        return "echo"

    def process(self, context):
        context["echo_ran"] = True
        return context


class FailStage(PipelineStage):
    """A stage that always raises an exception."""

    @property
    def name(self):
        return "fail"

    def process(self, context):
        raise RuntimeError("intentional failure")


class ShortCircuitStage(PipelineStage):
    """A stage that sets the skip flag to short-circuit the pipeline."""

    @property
    def name(self):
        return "short_circuit"

    def process(self, context):
        context["skip"] = True
        context["reason"] = "testing"
        return context


class TestPipeline(unittest.TestCase):
    def test_basic_execution(self):
        p = Pipeline()
        p.add_stage(EchoStage())
        result = p.execute({})
        self.assertTrue(result.get("echo_ran"))

    def test_stage_ordering(self):
        order = []

        class StageA(PipelineStage):
            name = "a"

            def process(self, ctx):
                order.append("a")
                return ctx

        class StageB(PipelineStage):
            name = "b"

            def process(self, ctx):
                order.append("b")
                return ctx

        p = Pipeline()
        p.add_stage(StageA())
        p.add_stage(StageB())
        p.execute({})
        self.assertEqual(order, ["a", "b"])

    def test_error_handling(self):
        p = Pipeline()
        p.add_stage(FailStage())
        p.add_stage(EchoStage())
        result = p.execute({})
        # Pipeline should continue despite failure
        self.assertTrue(result.get("echo_ran"))
        self.assertIn("fail", result.get("errors", []))

    def test_short_circuit(self):
        p = Pipeline()
        p.add_stage(ShortCircuitStage())
        p.add_stage(EchoStage())
        result = p.execute({})
        self.assertTrue(result.get("skip"))
        self.assertNotIn("echo_ran", result)

    def test_empty_pipeline(self):
        p = Pipeline()
        result = p.execute({"key": "value"})
        self.assertEqual(result, {"key": "value"})


class TestBuiltinStages(unittest.TestCase):
    def test_url_discovery_stage(self):
        stage = URLDiscoveryStage()
        self.assertEqual(stage.name, "url_discovery")
        # URLDiscoveryStage uses "content" key (not "body")
        ctx = {
            "content": '<a href="https://example.com/page">link</a>',
            "content_type": "text/html",
            "url": "https://example.com",
            "base_url": "https://example.com",
        }
        result = stage.process(ctx)
        self.assertIn("discovered_urls", result)

    def test_url_discovery_empty_content(self):
        stage = URLDiscoveryStage()
        result = stage.process({
            "content": "",
            "content_type": "",
            "url": "https://example.com",
            "base_url": "https://example.com",
        })
        urls = result.get("discovered_urls", set())
        self.assertEqual(len(urls), 0)

    def test_tech_detection_with_registry(self):
        reg = PluginRegistry()
        reg.discover()
        stage = TechDetectionStage()
        ctx = {
            "headers": {"server": "nginx"},
            "body": "<html></html>",
            "cookies": [],
            "scripts": [],
            "plugin_registry": reg,
        }
        result = stage.process(ctx)
        self.assertIn("technologies", result)
        self.assertIn("protections", result)

    def test_tech_detection_without_registry(self):
        stage = TechDetectionStage()
        ctx = {"headers": {}, "body": ""}
        result = stage.process(ctx)
        # Without registry, original context is returned
        self.assertNotIn("technologies", result)

    def test_strategy_selection_with_registry(self):
        reg = PluginRegistry()
        reg.discover()
        stage = StrategySelectionStage()
        ctx = {
            "technologies": [{"name": "WordPress", "category": "cms"}],
            "plugin_registry": reg,
        }
        result = stage.process(ctx)
        self.assertIn("strategy_urls", result)

    def test_strategy_selection_without_registry(self):
        stage = StrategySelectionStage()
        ctx = {"technologies": [{"name": "WordPress", "category": "cms"}]}
        result = stage.process(ctx)
        # Without registry, original context is returned
        self.assertNotIn("crawl_strategy", result)

    def test_data_processing_without_registry(self):
        stage = DataProcessingStage()
        ctx = {
            "url": "https://example.com",
            "technologies": [{"name": "nginx", "category": "web_server"}],
            "protections": ["cloudflare"],
        }
        result = stage.process(ctx)
        # Without registry, original context is returned
        self.assertEqual(result["url"], "https://example.com")


if __name__ == "__main__":
    unittest.main()
