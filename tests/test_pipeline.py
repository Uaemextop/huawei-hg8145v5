"""Tests for the crawling pipeline."""

import unittest

from web_crawler.pipeline import (
    CrawlingPipeline,
    ContentProcessingStage,
    DiscoveryStage,
    LinkExtractionStage,
    PipelineStage,
    ProtectionDetectionStage,
    TechnologyDetectionStage,
)
from web_crawler.plugins.registry import PluginRegistry


class TestPipelineStages(unittest.TestCase):
    """Tests for individual pipeline stages."""

    def test_discovery_stage_initialises_defaults(self):
        stage = DiscoveryStage()
        ctx = stage.process({"url": "http://example.com"})
        self.assertIn("technologies", ctx)
        self.assertIn("protections", ctx)
        self.assertIn("links", ctx)
        self.assertFalse(ctx["skip"])

    def test_content_processing_stage_passthrough(self):
        stage = ContentProcessingStage()
        ctx = {"url": "http://x", "body": "hello"}
        self.assertEqual(stage.process(ctx), ctx)

    def test_tech_detection_stage_with_registry(self):
        reg = PluginRegistry()
        reg.auto_discover()
        stage = TechnologyDetectionStage(reg)
        ctx = {
            "url": "http://example.com",
            "headers": {"Server": "nginx"},
            "body": "<html>hello</html>",
            "skip": False,
        }
        result = stage.process(ctx)
        self.assertIn("nginx", result["technologies"])

    def test_protection_detection_stage_with_registry(self):
        reg = PluginRegistry()
        reg.auto_discover()
        stage = ProtectionDetectionStage(reg)
        ctx = {
            "url": "http://example.com",
            "headers": {"cf-ray": "abc"},
            "body": "",
            "skip": False,
        }
        result = stage.process(ctx)
        self.assertIn("cloudflare", result["protections"])

    def test_link_extraction_stage(self):
        reg = PluginRegistry()
        reg.auto_discover()
        stage = LinkExtractionStage(reg)
        ctx = {
            "url": "http://example.com",
            "body": '<iframe src="https://other.com/page"></iframe>',
            "content_type": "text/html",
            "links": set(),
            "skip": False,
        }
        result = stage.process(ctx)
        self.assertTrue(len(result["links"]) > 0)

    def test_skip_flag_skips_detection(self):
        reg = PluginRegistry()
        reg.auto_discover()
        stage = TechnologyDetectionStage(reg)
        ctx = {
            "url": "http://example.com",
            "headers": {"Server": "nginx"},
            "body": "<html>hello</html>",
            "skip": True,
            "technologies": [],
        }
        result = stage.process(ctx)
        self.assertEqual(result["technologies"], [])


class TestCrawlingPipeline(unittest.TestCase):
    """Tests for the CrawlingPipeline orchestrator."""

    def test_empty_pipeline(self):
        pipeline = CrawlingPipeline()
        ctx = {"url": "http://x"}
        self.assertEqual(pipeline.execute(ctx), ctx)

    def test_stages_execute_in_order(self):
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

        pipeline = CrawlingPipeline([StageA(), StageB()])
        pipeline.execute({})
        self.assertEqual(order, ["a", "b"])

    def test_add_stage(self):
        pipeline = CrawlingPipeline()
        self.assertEqual(len(pipeline.stages), 0)
        pipeline.add_stage(DiscoveryStage())
        self.assertEqual(len(pipeline.stages), 1)

    def test_insert_stage(self):
        pipeline = CrawlingPipeline([DiscoveryStage(), ContentProcessingStage()])
        self.assertEqual(len(pipeline.stages), 2)

        class CustomStage(PipelineStage):
            name = "custom"
            def process(self, ctx):
                return ctx

        pipeline.insert_stage(1, CustomStage())
        self.assertEqual(len(pipeline.stages), 3)
        self.assertEqual(pipeline.stages[1].name, "custom")

    def test_pipeline_handles_stage_error(self):
        class ErrorStage(PipelineStage):
            name = "error"
            def process(self, ctx):
                raise RuntimeError("stage error")

        pipeline = CrawlingPipeline([
            DiscoveryStage(),
            ErrorStage(),
            ContentProcessingStage(),
        ])
        ctx = pipeline.execute({"url": "http://x"})
        # Pipeline should continue despite error
        self.assertIn("technologies", ctx)

    def test_full_pipeline_integration(self):
        reg = PluginRegistry()
        reg.auto_discover()
        pipeline = CrawlingPipeline([
            DiscoveryStage(),
            TechnologyDetectionStage(reg),
            ProtectionDetectionStage(reg),
            LinkExtractionStage(reg),
            ContentProcessingStage(),
        ])
        ctx = pipeline.execute({
            "url": "http://example.com",
            "headers": {"Server": "Apache", "X-Powered-By": "PHP/8.1"},
            "body": "<html>wp-content</html>",
            "content_type": "text/html",
            "response": None,
        })
        self.assertIn("apache", ctx["technologies"])
        self.assertIn("php", ctx["technologies"])
        self.assertIn("wordpress", ctx["technologies"])


if __name__ == "__main__":
    unittest.main()
