"""
Tests for the link extraction module.
"""

import unittest
from pathlib import Path

from web_crawler.extraction.links import extract_links
from web_crawler.extraction.css import extract_css_urls
from web_crawler.extraction.javascript import extract_js_paths
from web_crawler.extraction.json_extract import extract_json_paths


BASE = "https://example.com"
PAGE = "https://example.com/index.html"


class TestCssExtraction(unittest.TestCase):
    def test_url_function(self):
        css = "background: url('/images/bg.png');"
        result = extract_css_urls(css, PAGE, BASE)
        self.assertIn("https://example.com/images/bg.png", result)

    def test_import(self):
        css = '@import "/css/reset.css";'
        result = extract_css_urls(css, PAGE, BASE)
        self.assertIn("https://example.com/css/reset.css", result)


class TestJsExtraction(unittest.TestCase):
    def test_window_location(self):
        js = "window.location.href = '/about.html';"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/about.html", result)

    def test_fetch_url(self):
        js = "fetch('/api/data.json');"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/api/data.json", result)

    def test_ajax_url(self):
        js = "$.ajax({ url: '/api/users', type: 'GET' });"
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/api/users", result)


class TestJsonExtraction(unittest.TestCase):
    def test_json_path_value(self):
        data = '{"page": "/blog/post.html"}'
        result = extract_json_paths(data, PAGE, BASE)
        self.assertIn("https://example.com/blog/post.html", result)

    def test_invalid_json(self):
        result = extract_json_paths("not json", PAGE, BASE)
        self.assertEqual(len(result), 0)


class TestExtractLinks(unittest.TestCase):
    def test_html_extraction(self):
        html = '<a href="/about.html">About</a>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/about.html", result)

    def test_css_extraction(self):
        css = "body { background: url('/images/bg.png'); }"
        result = extract_links(css, "text/css", PAGE, BASE)
        self.assertIn("https://example.com/images/bg.png", result)

    def test_js_extraction(self):
        js = "var page = '/blog/index.html';"
        result = extract_links(js, "application/javascript", PAGE, BASE)
        self.assertIn("https://example.com/blog/index.html", result)

    def test_html_with_multiple_links(self):
        html = """
        <html>
        <head>
            <link href="/css/style.css" rel="stylesheet">
            <script src="/js/main.js"></script>
        </head>
        <body>
            <a href="/about.html">About</a>
            <img src="/images/logo.png">
        </body>
        </html>
        """
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/css/style.css", result)
        self.assertIn("https://example.com/js/main.js", result)
        self.assertIn("https://example.com/about.html", result)
        self.assertIn("https://example.com/images/logo.png", result)


class TestHiddenFileExtraction(unittest.TestCase):
    """Test that hidden/config file references are extracted from JS/HTML."""

    def test_js_env_path(self):
        js = 'var config = "/.env";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.env", result)

    def test_js_htaccess_path(self):
        js = 'var path = "/.htaccess";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.htaccess", result)

    def test_js_config_path(self):
        js = 'var f = "/app/.config";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/app/.config", result)

    def test_js_cfg_path(self):
        js = 'var f = "/settings.cfg";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/settings.cfg", result)

    def test_js_hst_path(self):
        js = 'var f = "/data/history.hst";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/data/history.hst", result)

    def test_js_env_local_path(self):
        js = 'var f = "/.env.local";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.env.local", result)

    def test_js_gitignore_path(self):
        js = 'var f = "/.gitignore";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/.gitignore", result)

    def test_hidden_file_in_html_link(self):
        html = '<a href="/.env">env</a>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/.env", result)

    def test_hidden_file_in_html_script(self):
        html = '<script>var x = "/config.ini";</script>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/config.ini", result)


class TestHiddenFileProbeConfig(unittest.TestCase):
    """Test that the probe list is properly configured."""

    def test_probe_list_not_empty(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertGreater(len(HIDDEN_FILE_PROBES), 0)

    def test_probe_list_contains_env(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".env", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_htaccess(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".htaccess", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_cfg(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".cfg", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_hst(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".hst", HIDDEN_FILE_PROBES)

    def test_probe_list_contains_config(self):
        from web_crawler.config import HIDDEN_FILE_PROBES
        self.assertIn(".config", HIDDEN_FILE_PROBES)


class TestVideoExtraction(unittest.TestCase):
    """Test that video-related URLs are extracted from HTML."""

    def test_video_src(self):
        html = '<video src="/videos/clip.mp4"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/clip.mp4", result)

    def test_video_poster(self):
        html = '<video poster="/images/thumb.jpg"><source src="/videos/clip.webm"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/images/thumb.jpg", result)
        self.assertIn("https://example.com/videos/clip.webm", result)

    def test_video_data_src(self):
        html = '<video data-src="/videos/lazy.mp4"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/lazy.mp4", result)

    def test_source_data_src(self):
        html = '<video><source data-src="/videos/lazy.webm"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/lazy.webm", result)

    def test_audio_data_src(self):
        html = '<audio data-src="/audio/lazy.mp3"></audio>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/audio/lazy.mp3", result)

    def test_video_multiple_sources(self):
        html = """
        <video poster="/thumb.jpg">
            <source src="/videos/clip.mp4" type="video/mp4">
            <source src="/videos/clip.webm" type="video/webm">
            <source src="/videos/clip.ogv" type="video/ogg">
        </video>
        """
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/clip.mp4", result)
        self.assertIn("https://example.com/videos/clip.webm", result)
        self.assertIn("https://example.com/videos/clip.ogv", result)
        self.assertIn("https://example.com/thumb.jpg", result)

    def test_video_formats_in_js(self):
        js = 'var video = "/content/movie.mkv";'
        from web_crawler.extraction.javascript import extract_js_paths
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/content/movie.mkv", result)

    def test_m3u8_in_js(self):
        js = 'var src = "/stream/playlist.m3u8";'
        from web_crawler.extraction.javascript import extract_js_paths
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/stream/playlist.m3u8", result)

    def test_mpd_in_js(self):
        js = 'var src = "/stream/manifest.mpd";'
        from web_crawler.extraction.javascript import extract_js_paths
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://example.com/stream/manifest.mpd", result)


class TestCdnMediaExtraction(unittest.TestCase):
    """Test that external CDN media URLs are extracted from HTML."""

    def test_video_src_external_cdn(self):
        html = '<video src="https://cdn.example.net/videos/clip.mp4"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/videos/clip.mp4", result)

    def test_source_src_external_cdn(self):
        html = '<video><source src="https://cdn.example.net/v.webm"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/v.webm", result)

    def test_audio_src_external_cdn(self):
        html = '<audio src="https://cdn.example.net/a.mp3"></audio>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/a.mp3", result)

    def test_schema_org_contenturl_external(self):
        html = '<meta itemprop="contentURL" content="https://cdn.example.net/movie.mp4" />'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/movie.mp4", result)

    def test_schema_org_embedurl_external(self):
        html = '<meta itemprop="embedURL" content="https://cdn.example.net/embed/1" />'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/embed/1", result)

    def test_non_media_external_rejected(self):
        """Regular <a> tags to external hosts should still be rejected."""
        html = '<a href="https://cdn.example.net/page.html">Link</a>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertNotIn("https://cdn.example.net/page.html", result)

    def test_og_image_external(self):
        html = '<meta property="og:image" content="https://cdn.example.net/thumb.jpg" />'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/thumb.jpg", result)

    def test_og_video_external(self):
        html = '<meta property="og:video" content="https://cdn.example.net/movie.mp4" />'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/movie.mp4", result)

    def test_og_audio_external(self):
        html = '<meta property="og:audio" content="https://cdn.example.net/track.mp3" />'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/track.mp3", result)

    def test_twitter_image_external(self):
        html = '<meta name="twitter:image" content="https://cdn.example.net/card.jpg" />'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/card.jpg", result)

    def test_og_video_secure_url(self):
        html = '<meta property="og:video:secure_url" content="https://cdn.example.net/secure.mp4" />'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/secure.mp4", result)

    def test_img_external_rejected(self):
        """<img> tags to external hosts should still be rejected."""
        html = '<img src="https://cdn.example.net/image.jpg">'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertNotIn("https://cdn.example.net/image.jpg", result)


class TestNormaliseUrlAllowExternal(unittest.TestCase):
    """Test allow_external parameter of normalise_url."""

    def test_external_rejected_by_default(self):
        from web_crawler.utils.url import normalise_url
        result = normalise_url("https://cdn.example.net/v.mp4", PAGE, BASE)
        self.assertIsNone(result)

    def test_external_allowed_when_flag_set(self):
        from web_crawler.utils.url import normalise_url
        result = normalise_url("https://cdn.example.net/v.mp4", PAGE, BASE,
                               allow_external=True)
        self.assertEqual(result, "https://cdn.example.net/v.mp4")

    def test_external_keeps_original_scheme(self):
        from web_crawler.utils.url import normalise_url
        result = normalise_url("http://cdn.example.net/v.mp4", PAGE, BASE,
                               allow_external=True)
        self.assertEqual(result, "http://cdn.example.net/v.mp4")


class TestVideoContentTypeMappings(unittest.TestCase):
    """Test that video content types map to correct file extensions."""

    def test_mp4_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/mp4")
        self.assertEqual(p.suffix, ".mp4")

    def test_webm_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/webm")
        self.assertEqual(p.suffix, ".webm")

    def test_wmv_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/x-ms-wmv")
        self.assertEqual(p.suffix, ".wmv")

    def test_m4v_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/x-m4v")
        self.assertEqual(p.suffix, ".m4v")

    def test_3gp_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/3gpp")
        self.assertEqual(p.suffix, ".3gp")

    def test_mpeg_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/mpeg")
        self.assertEqual(p.suffix, ".mpeg")

    def test_m3u8_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/stream", Path("/out"),
                             "application/vnd.apple.mpegurl")
        self.assertEqual(p.suffix, ".m3u8")

    def test_mpd_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/stream", Path("/out"),
                             "application/dash+xml")
        self.assertEqual(p.suffix, ".mpd")

    def test_flv_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/x-flv")
        self.assertEqual(p.suffix, ".flv")

    def test_mkv_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/x-matroska")
        self.assertEqual(p.suffix, ".mkv")

    def test_ts_mapping(self):
        from web_crawler.core.storage import smart_local_path
        p = smart_local_path("https://example.com/video", Path("/out"),
                             "video/mp2t")
        self.assertEqual(p.suffix, ".ts")


class TestVideoBinaryContentTypes(unittest.TestCase):
    """Test that video content types are in BINARY_CONTENT_TYPES for streaming."""

    def test_video_types_in_binary_set(self):
        from web_crawler.config import BINARY_CONTENT_TYPES
        video_types = [
            "video/mp4", "video/webm", "video/ogg", "video/x-msvideo",
            "video/quicktime", "video/x-flv", "video/x-matroska",
            "video/x-ms-wmv", "video/x-m4v", "video/3gpp", "video/3gpp2",
            "video/mp2t", "video/mpeg", "video/x-f4v", "video/x-ms-asf",
        ]
        for vt in video_types:
            self.assertIn(vt, BINARY_CONTENT_TYPES,
                          f"{vt} should be in BINARY_CONTENT_TYPES")

    def test_audio_types_in_binary_set(self):
        from web_crawler.config import BINARY_CONTENT_TYPES
        audio_types = [
            "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm",
            "audio/flac", "audio/aac", "audio/x-m4a", "audio/mp4",
        ]
        for at in audio_types:
            self.assertIn(at, BINARY_CONTENT_TYPES,
                          f"{at} should be in BINARY_CONTENT_TYPES")


class TestJsonLdVideoExtraction(unittest.TestCase):
    """Test JSON-LD structured data extraction for VideoObject."""

    def test_jsonld_video_object_contenturl(self):
        html = '''<html><head>
        <script type="application/ld+json">
        {"@type": "VideoObject", "contentUrl": "https://cdn.example.net/video.mp4"}
        </script></head></html>'''
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/video.mp4", result)

    def test_jsonld_video_object_embedurl(self):
        html = '''<html><head>
        <script type="application/ld+json">
        {"@type": "VideoObject", "embedUrl": "https://cdn.example.net/embed/123"}
        </script></head></html>'''
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/embed/123", result)

    def test_jsonld_video_object_thumbnailurl(self):
        html = '''<html><head>
        <script type="application/ld+json">
        {"@type": "VideoObject", "thumbnailUrl": "https://cdn.example.net/thumb.jpg"}
        </script></head></html>'''
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/thumb.jpg", result)

    def test_jsonld_nested_graph(self):
        html = '''<html><head>
        <script type="application/ld+json">
        {"@graph": [{"@type": "VideoObject", "contentUrl": "https://cdn.example.net/nested.mp4"}]}
        </script></head></html>'''
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/nested.mp4", result)

    def test_jsonld_invalid_json_ignored(self):
        html = '''<html><head>
        <script type="application/ld+json">not valid json{</script>
        </head></html>'''
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIsInstance(result, set)

    def test_jsonld_relative_url(self):
        html = '''<html><head>
        <script type="application/ld+json">
        {"@type": "VideoObject", "contentUrl": "/videos/local.mp4"}
        </script></head></html>'''
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/local.mp4", result)


class TestVideoDataAttributes(unittest.TestCase):
    """Test additional data-* attributes for video players."""

    def test_video_data_video_src(self):
        html = '<video data-video-src="/videos/player.mp4"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/player.mp4", result)

    def test_video_data_video_url(self):
        html = '<video data-video-url="/videos/player.webm"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/player.webm", result)

    def test_source_data_video_src(self):
        html = '<video><source data-video-src="/videos/source.mp4"></video>'
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://example.com/videos/source.mp4", result)


class TestStreamUrlExtraction(unittest.TestCase):
    """Test HLS/DASH stream URL extraction from JavaScript."""

    def test_hls_stream_in_js(self):
        js = 'var src = "https://cdn.example.net/stream/playlist.m3u8";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://cdn.example.net/stream/playlist.m3u8", result)

    def test_dash_stream_in_js(self):
        js = 'var src = "https://cdn.example.net/stream/manifest.mpd";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://cdn.example.net/stream/manifest.mpd", result)

    def test_mp4_url_in_js(self):
        js = 'player.src("https://cdn.example.net/videos/clip.mp4");'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn("https://cdn.example.net/videos/clip.mp4", result)

    def test_stream_url_with_query_params(self):
        js = 'var src = "https://cdn.example.net/live/stream.m3u8?token=abc123";'
        result = extract_js_paths(js, PAGE, BASE)
        self.assertIn(
            "https://cdn.example.net/live/stream.m3u8?token=abc123", result)

    def test_stream_url_in_html_script(self):
        html = '''<html><script>
        var videoSrc = "https://cdn.example.net/hls/video.m3u8";
        </script></html>'''
        result = extract_links(html, "text/html", PAGE, BASE)
        self.assertIn("https://cdn.example.net/hls/video.m3u8", result)


class TestProbeThresholds(unittest.TestCase):
    """Test that probe thresholds are set to optimized values."""

    def test_probe_404_threshold(self):
        from web_crawler.config import PROBE_404_THRESHOLD
        self.assertEqual(PROBE_404_THRESHOLD, 30)

    def test_probe_dir_404_limit(self):
        from web_crawler.config import PROBE_DIR_404_LIMIT
        self.assertEqual(PROBE_DIR_404_LIMIT, 5)


class TestPageMetadataExtraction(unittest.TestCase):
    """Tests for extract_page_metadata()."""

    def test_og_title_and_description(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        html = """<html><head>
        <meta property="og:title" content="My Video Page">
        <meta property="og:description" content="A cool video page">
        <meta property="og:site_name" content="VideoSite">
        <meta property="og:image" content="https://example.com/thumb.jpg">
        </head></html>"""
        meta = extract_page_metadata(html)
        self.assertEqual(meta["title"], "My Video Page")
        self.assertEqual(meta["description"], "A cool video page")
        self.assertEqual(meta["author"], "VideoSite")
        self.assertEqual(meta["thumbnail"], "https://example.com/thumb.jpg")

    def test_fallback_to_title_tag(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        html = "<html><head><title>Fallback Title</title></head></html>"
        meta = extract_page_metadata(html)
        self.assertEqual(meta["title"], "Fallback Title")

    def test_meta_author(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        html = '<html><head><meta name="author" content="John Doe"></head></html>'
        meta = extract_page_metadata(html)
        self.assertEqual(meta["author"], "John Doe")

    def test_meta_description_fallback(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        html = '<html><head><meta name="description" content="A description"></head></html>'
        meta = extract_page_metadata(html)
        self.assertEqual(meta["description"], "A description")

    def test_empty_html(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        meta = extract_page_metadata("")
        self.assertEqual(meta["title"], "")
        self.assertEqual(meta["description"], "")
        self.assertEqual(meta["author"], "")
        self.assertEqual(meta["thumbnail"], "")

    def test_genre_from_keywords(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        html = '<html><head><meta name="keywords" content="comedy, animation"></head></html>'
        meta = extract_page_metadata(html)
        self.assertEqual(meta["genre"], "comedy, animation")


class TestJsonLdVideoMeta(unittest.TestCase):
    """Tests for extract_jsonld_video_meta()."""

    def test_basic_video_object(self):
        from web_crawler.extraction.html_parser import extract_jsonld_video_meta
        import json
        ld = {
            "@context": "https://schema.org",
            "@type": "VideoObject",
            "name": "Big Buck Bunny",
            "description": "A short animation",
            "contentUrl": "https://example.com/video.mp4",
            "thumbnailUrl": "https://example.com/thumb.jpg",
            "duration": "PT10M",
            "uploadDate": "2024-01-01",
            "genre": "Animation",
            "author": {"@type": "Person", "name": "Blender Foundation"},
        }
        html = f'<html><head><script type="application/ld+json">{json.dumps(ld)}</script></head></html>'
        result = extract_jsonld_video_meta(html)
        self.assertIn("https://example.com/video.mp4", result)
        meta = result["https://example.com/video.mp4"]
        self.assertEqual(meta["title"], "Big Buck Bunny")
        self.assertEqual(meta["description"], "A short animation")
        self.assertEqual(meta["author"], "Blender Foundation")
        self.assertEqual(meta["thumbnail"], "https://example.com/thumb.jpg")
        self.assertEqual(meta["duration"], "PT10M")
        self.assertEqual(meta["upload_date"], "2024-01-01")
        self.assertEqual(meta["genre"], "Animation")

    def test_thumbnail_url_as_list(self):
        from web_crawler.extraction.html_parser import extract_jsonld_video_meta
        import json
        ld = {
            "@type": "VideoObject",
            "name": "Test",
            "contentUrl": "https://example.com/v.mp4",
            "thumbnailUrl": [
                "https://example.com/t1.jpg",
                "https://example.com/t2.jpg",
            ],
        }
        html = f'<html><head><script type="application/ld+json">{json.dumps(ld)}</script></head></html>'
        result = extract_jsonld_video_meta(html)
        self.assertEqual(result["https://example.com/v.mp4"]["thumbnail"],
                         "https://example.com/t1.jpg")

    def test_author_as_string(self):
        from web_crawler.extraction.html_parser import extract_jsonld_video_meta
        import json
        ld = {
            "@type": "VideoObject",
            "name": "Test",
            "contentUrl": "https://example.com/v.mp4",
            "author": "Jane Doe",
        }
        html = f'<html><head><script type="application/ld+json">{json.dumps(ld)}</script></head></html>'
        result = extract_jsonld_video_meta(html)
        self.assertEqual(result["https://example.com/v.mp4"]["author"], "Jane Doe")

    def test_no_video_objects(self):
        from web_crawler.extraction.html_parser import extract_jsonld_video_meta
        html = "<html><head></head></html>"
        result = extract_jsonld_video_meta(html)
        self.assertEqual(result, {})


class TestMicrodataVideoMeta(unittest.TestCase):
    """Tests for extract_microdata_video_meta()."""

    def test_basic_microdata_video(self):
        from web_crawler.extraction.html_parser import extract_microdata_video_meta
        html = '''<html><body>
        <article itemscope itemtype="https://schema.org/VideoObject">
          <meta itemprop="author" content="Super Landia" />
          <meta itemprop="name" content="My Video" />
          <meta itemprop="description" content="A cool video" />
          <meta itemprop="duration" content="PT5M" />
          <meta itemprop="thumbnailUrl" content="https://cdn.example.com/thumb.jpg" />
          <meta itemprop="contentURL" content="https://cdn.example.com/video.mp4" />
          <meta itemprop="uploadDate" content="2026-01-16T23:30:05" />
        </article></body></html>'''
        result = extract_microdata_video_meta(html)
        self.assertIn("https://cdn.example.com/video.mp4", result)
        meta = result["https://cdn.example.com/video.mp4"]
        self.assertEqual(meta["title"], "My Video")
        self.assertEqual(meta["description"], "A cool video")
        self.assertEqual(meta["author"], "Super Landia")
        self.assertEqual(meta["thumbnail"], "https://cdn.example.com/thumb.jpg")
        self.assertEqual(meta["duration"], "PT5M")
        self.assertEqual(meta["upload_date"], "2026-01-16T23:30:05")

    def test_dedup_title_equals_description(self):
        from web_crawler.extraction.html_parser import extract_microdata_video_meta
        html = '''<html><body>
        <article itemscope itemtype="https://schema.org/VideoObject">
          <meta itemprop="name" content="Mommy" />
          <meta itemprop="description" content="Mommy" />
          <meta itemprop="contentURL" content="https://cdn.example.com/v.mp4" />
        </article></body></html>'''
        result = extract_microdata_video_meta(html)
        meta = result["https://cdn.example.com/v.mp4"]
        self.assertEqual(meta["title"], "Mommy")
        self.assertEqual(meta["description"], "")

    def test_no_microdata(self):
        from web_crawler.extraction.html_parser import extract_microdata_video_meta
        html = "<html><body><p>No video here</p></body></html>"
        result = extract_microdata_video_meta(html)
        self.assertEqual(result, {})

    def test_no_content_url(self):
        from web_crawler.extraction.html_parser import extract_microdata_video_meta
        html = '''<html><body>
        <article itemscope itemtype="https://schema.org/VideoObject">
          <meta itemprop="name" content="No URL" />
        </article></body></html>'''
        result = extract_microdata_video_meta(html)
        self.assertEqual(result, {})

    def test_embedurl_fallback(self):
        from web_crawler.extraction.html_parser import extract_microdata_video_meta
        html = '''<html><body>
        <article itemscope itemtype="https://schema.org/VideoObject">
          <meta itemprop="name" content="Embed" />
          <meta itemprop="embedUrl" content="https://cdn.example.com/embed.mp4" />
        </article></body></html>'''
        result = extract_microdata_video_meta(html)
        self.assertIn("https://cdn.example.com/embed.mp4", result)


class TestPageMetadataDedup(unittest.TestCase):
    """Tests for title==description dedup in extract_page_metadata()."""

    def test_title_equals_description_cleared(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        html = '''<html><head>
        <meta property="og:title" content="Mommy">
        <meta property="og:description" content="Mommy">
        </head></html>'''
        meta = extract_page_metadata(html)
        self.assertEqual(meta["title"], "Mommy")
        self.assertEqual(meta["description"], "")

    def test_title_different_from_description_kept(self):
        from web_crawler.extraction.html_parser import extract_page_metadata
        html = '''<html><head>
        <meta property="og:title" content="My Video">
        <meta property="og:description" content="A great video">
        </head></html>'''
        meta = extract_page_metadata(html)
        self.assertEqual(meta["title"], "My Video")
        self.assertEqual(meta["description"], "A great video")


if __name__ == "__main__":
    unittest.main()
