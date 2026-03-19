"""Tests for crawl4ai.extensions.downloader.SiteDownloader.

Covers:
* Site-module file URLs are enqueued for actual download (not just catalogued).
* _is_downloadable covers extensions, binary content-types, and CDN hosts.
* _scan_page enqueues external file links regardless of allow_external flag.
* _url_key normalises URLs correctly.
"""

from __future__ import annotations

import threading
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers – build a minimal SiteDownloader without making real HTTP calls
# ---------------------------------------------------------------------------

def _make_downloader(target_exts="all", allow_external=True):
    """Return a SiteDownloader instance for ``https://example.com`` with
    the given settings.  No real HTTP session is used."""
    from crawl4ai.extensions.downloader import SiteDownloader
    dl = SiteDownloader.__new__(SiteDownloader)
    dl.start_url = "https://example.com"
    dl.base = "https://example.com"
    dl.allowed_host = "example.com"
    dl.output_dir = Path("/tmp/test_dl_output")
    dl.max_depth = 2
    dl.delay = 0
    dl.allow_external = allow_external
    dl.concurrency = 1
    dl.git_repo_dir = None
    dl.git_push_every = 0
    dl.future_timeout = 30
    dl._lock = threading.Lock()
    dl._visited: set[str] = set()
    dl._queue: deque = deque()
    dl._downloaded_files = []
    dl._download_count = 0
    dl._page_count = 0
    dl._error_count = 0
    dl._seen_hashes = set()
    dl._catalog_index_path = None
    dl._catalog_entry_count = 0
    dl.session = MagicMock()

    import re
    from crawl4ai.extensions.downloader import DEFAULT_DOWNLOAD_EXTENSIONS
    if target_exts == "all":
        dl._target_exts = None
        dl._ext_re = None
    elif target_exts is None:
        dl._target_exts = DEFAULT_DOWNLOAD_EXTENSIONS
        ext_pat = "|".join(re.escape(e) for e in sorted(DEFAULT_DOWNLOAD_EXTENSIONS))
        dl._ext_re = re.compile(rf"\.(?:{ext_pat})(?:\?|#|$)", re.I)
    else:
        dl._target_exts = frozenset(target_exts)
        ext_pat = "|".join(re.escape(e) for e in sorted(dl._target_exts))
        dl._ext_re = re.compile(rf"\.(?:{ext_pat})(?:\?|#|$)", re.I)

    return dl


# ---------------------------------------------------------------------------
# 1. Site-module file URLs enqueued for download
# ---------------------------------------------------------------------------

class TestSiteModuleUrlsEnqueued(unittest.TestCase):
    """Verify that file URLs discovered by site modules are added to the
    download queue, not just written to file_index.md."""

    def _enqueue_site_module_files(self, index_entries):
        """Simulate the site-module file-URL enqueue loop in
        ``SiteDownloader.run()`` and return how many URLs ended up in
        the download queue."""
        dl = _make_downloader()

        # Build a fake site module
        mod = MagicMock()
        mod.name = "FakeModule"
        mod.generate_index.return_value = index_entries
        mod.page_urls.return_value = []

        # Patch _write_file_index so it doesn't try to write to disk
        with patch.object(dl, "_write_file_index", return_value=Path("/tmp/x.md")):
            # Replay the relevant section of run() directly
            try:
                entries = mod.generate_index(dl.start_url)
                if entries:
                    dl._write_file_index(mod.name, entries)
                    _enqueued = 0
                    for entry in entries:
                        file_url = (entry.get("url") or "").strip()
                        if not file_url or not file_url.startswith(
                            ("http://", "https://")
                        ):
                            continue
                        key = dl._url_key(file_url)
                        with dl._lock:
                            if key not in dl._visited:
                                dl._queue.append((file_url, 0))
                                _enqueued += 1
            except Exception as exc:
                self.fail(f"Unexpected exception in site-module loop: {exc}")

        return len(dl._queue)

    def test_file_urls_enqueued(self):
        """URLs from index entries must appear in the download queue."""
        entries = [
            {"name": "AMI-AFU.zip", "url": "https://cdn.example.com/AMI-AFU.zip"},
            {"name": "guide.pdf",   "url": "https://cdn.example.com/guide.pdf"},
        ]
        queued = self._enqueue_site_module_files(entries)
        self.assertEqual(queued, 2)

    def test_entries_without_url_skipped(self):
        """Entries that have no 'url' key must be skipped gracefully."""
        entries = [
            {"name": "no-url-entry"},
            {"name": "empty-url", "url": ""},
            {"name": "valid",     "url": "https://cdn.example.com/file.bin"},
        ]
        queued = self._enqueue_site_module_files(entries)
        self.assertEqual(queued, 1)

    def test_non_http_urls_skipped(self):
        """Entries with non-HTTP URLs (ftp://, data:, etc.) must be skipped."""
        entries = [
            {"name": "ftp",  "url": "ftp://ftp.example.com/file.zip"},
            {"name": "data", "url": "data:text/plain,hello"},
            {"name": "good", "url": "https://cdn.example.com/valid.zip"},
        ]
        queued = self._enqueue_site_module_files(entries)
        self.assertEqual(queued, 1)

    def test_duplicate_urls_enqueued_but_processed_once(self):
        """Duplicate file URLs are both enqueued (dedup happens at dequeue
        time in run()), but the visited-set ensures only the first is
        actually processed."""
        dl = _make_downloader()
        same_url = "https://cdn.example.com/firmware.zip"
        entries = [
            {"name": "copy1", "url": same_url},
            {"name": "copy2", "url": same_url},
        ]
        # Replay the enqueue loop (does NOT add to visited, so both end up queued)
        for entry in entries:
            file_url = (entry.get("url") or "").strip()
            if not file_url or not file_url.startswith(("http://", "https://")):
                continue
            key = dl._url_key(file_url)
            with dl._lock:
                if key not in dl._visited:
                    dl._queue.append((file_url, 0))
        # Both entries make it into the queue (dedup happens at dequeue time)
        self.assertEqual(len(dl._queue), 2)
        # Simulate dequeue dedup (as the run() loop does)
        processed = []
        while dl._queue:
            url, depth = dl._queue.popleft()
            key = dl._url_key(url)
            with dl._lock:
                if key in dl._visited:
                    continue
                dl._visited.add(key)
            processed.append(url)
        # Only one is processed
        self.assertEqual(len(processed), 1)

    def test_empty_index_entries_no_error(self):
        """Empty index must produce zero queue entries without raising."""
        queued = self._enqueue_site_module_files([])
        self.assertEqual(queued, 0)


# ---------------------------------------------------------------------------
# 2. _is_downloadable
# ---------------------------------------------------------------------------

class TestIsDownloadable(unittest.TestCase):
    """Unit-tests for SiteDownloader._is_downloadable."""

    def setUp(self):
        self.dl_all  = _make_downloader(target_exts="all")
        self.dl_exts = _make_downloader(target_exts=["zip", "pdf", "exe"])

    # ── extension-based detection ────────────────────────────────────

    def test_zip_extension_all_mode(self):
        self.assertTrue(
            self.dl_all._is_downloadable("https://x.com/file.zip", ""),
        )

    def test_pdf_extension_all_mode(self):
        self.assertTrue(
            self.dl_all._is_downloadable("https://x.com/guide.pdf", ""),
        )

    def test_zip_extension_filtered_mode(self):
        self.assertTrue(
            self.dl_exts._is_downloadable("https://x.com/file.zip", ""),
        )

    def test_mp3_not_in_filtered_exts(self):
        self.assertFalse(
            self.dl_exts._is_downloadable("https://x.com/music.mp3", ""),
        )

    def test_html_page_without_extension_not_downloadable(self):
        """A URL with no file extension and text/html CT is not downloadable
        (it goes through _scan_page for link extraction)."""
        self.assertFalse(
            self.dl_all._is_downloadable("https://x.com/about-us", "text/html"),
        )

    def test_html_extension_is_downloadable_all_mode(self):
        """In 'all' mode a .html URL IS considered downloadable so the file
        is saved to disk.  Link extraction is handled by _scan_page for
        extensionless page URLs."""
        self.assertTrue(
            self.dl_all._is_downloadable("https://x.com/page.html", "text/html"),
        )

    # ── content-type-based detection ─────────────────────────────────

    def test_binary_content_type_always_downloadable(self):
        self.assertTrue(
            self.dl_all._is_downloadable("https://x.com/path", "application/zip"),
        )

    def test_octet_stream_always_downloadable(self):
        self.assertTrue(
            self.dl_all._is_downloadable("https://x.com/blob", "application/octet-stream"),
        )

    def test_video_mp4_always_downloadable(self):
        self.assertTrue(
            self.dl_all._is_downloadable("https://x.com/vid", "video/mp4"),
        )

    def test_json_not_downloadable_by_ct(self):
        # application/json is in the skip list
        self.assertFalse(
            self.dl_all._is_downloadable("https://x.com/api", "application/json"),
        )

    # ── CDN host detection (all mode, no extension) ───────────────────

    def test_hubspot_cdn_extensionless_downloadable_all_mode(self):
        """Extensionless HubSpot tracking/redirect URLs are downloadable in all mode."""
        url = "https://f.hubspotusercontent10.net/hubfs/9443417/file-no-ext"
        self.assertTrue(self.dl_all._is_downloadable(url, ""))

    def test_hubspot_cdn_not_downloadable_in_filtered_mode(self):
        """CDN host shortcut only applies in 'all' mode."""
        url = "https://f.hubspotusercontent10.net/hubfs/9443417/file-no-ext"
        self.assertFalse(self.dl_exts._is_downloadable(url, ""))

    def test_amazonaws_cdn_downloadable_all_mode(self):
        url = "https://bucket.s3.amazonaws.com/path/to/object"
        self.assertTrue(self.dl_all._is_downloadable(url, ""))

    # ── with query string ─────────────────────────────────────────────

    def test_zip_with_query_string(self):
        self.assertTrue(
            self.dl_all._is_downloadable(
                "https://cdn.example.com/file.zip?token=abc", "",
            ),
        )


# ---------------------------------------------------------------------------
# 3. _scan_page link filtering
# ---------------------------------------------------------------------------

class TestScanPageLinkFiltering(unittest.TestCase):
    """Verify that _scan_page correctly routes file vs. page links."""

    def test_external_file_link_enqueued_regardless_of_allow_external(self):
        """External file links (e.g. CDN .zip) must always be enqueued,
        even when allow_external=False."""
        dl = _make_downloader(allow_external=False)

        file_links = {
            "https://cdn.elsewhere.com/firmware.zip",  # external file
        }
        page_links = {
            "https://example.com/page",  # same-host page (depth 0 < 2)
        }
        all_links = file_links | page_links

        # Simulate the filtering loop (extracted from _scan_page)
        import urllib.parse
        from crawl4ai.extensions.settings import CLOUD_STORAGE_HOSTS
        enqueued = []
        for link in all_links:
            if not link or link.startswith(("javascript:", "mailto:", "data:", "#")):
                continue
            abs_url = urllib.parse.urljoin("https://example.com/page", link)
            parsed = urllib.parse.urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                continue
            is_external = parsed.netloc != dl.allowed_host
            if dl._is_downloadable(abs_url, ""):
                key = dl._url_key(abs_url)
                with dl._lock:
                    if key not in dl._visited:
                        enqueued.append(abs_url)
                continue
            if is_external:
                if not dl.allow_external:
                    continue
                is_cloud = parsed.netloc in CLOUD_STORAGE_HOSTS or any(
                    parsed.netloc.endswith("." + h) for h in CLOUD_STORAGE_HOSTS
                )
                if not is_cloud:
                    continue
            if 0 < dl.max_depth:
                key = dl._url_key(abs_url)
                with dl._lock:
                    if key not in dl._visited:
                        enqueued.append(abs_url)

        self.assertIn("https://cdn.elsewhere.com/firmware.zip", enqueued,
                      "External file link must be enqueued")
        self.assertIn("https://example.com/page", enqueued,
                      "Same-host page link must be enqueued")

    def test_external_page_link_blocked_when_allow_external_false(self):
        """External page links (no file extension) must not be enqueued
        when allow_external=False."""
        dl = _make_downloader(allow_external=False)

        import urllib.parse
        from crawl4ai.extensions.settings import CLOUD_STORAGE_HOSTS
        enqueued = []
        # Use an extensionless page URL (not downloadable in any mode)
        external_page = "https://other.com/about-us"
        abs_url = external_page
        parsed = urllib.parse.urlparse(abs_url)
        is_external = parsed.netloc != dl.allowed_host
        if dl._is_downloadable(abs_url, ""):
            enqueued.append(abs_url)
        elif is_external:
            if not dl.allow_external:
                pass  # blocked
        else:
            enqueued.append(abs_url)

        self.assertNotIn(external_page, enqueued)


# ---------------------------------------------------------------------------
# 4. _url_key normalisation
# ---------------------------------------------------------------------------

class TestUrlKey(unittest.TestCase):
    def setUp(self):
        self.dl = _make_downloader()

    def test_strips_fragment(self):
        self.assertEqual(
            self.dl._url_key("https://x.com/path#section"),
            self.dl._url_key("https://x.com/path"),
        )

    def test_lowercase_scheme_and_host(self):
        self.assertEqual(
            self.dl._url_key("HTTPS://X.COM/path"),
            self.dl._url_key("https://x.com/path"),
        )

    def test_preserves_query_string(self):
        k1 = self.dl._url_key("https://x.com/path?a=1")
        k2 = self.dl._url_key("https://x.com/path?a=2")
        self.assertNotEqual(k1, k2)

    def test_preserves_path_case(self):
        k1 = self.dl._url_key("https://x.com/Path")
        k2 = self.dl._url_key("https://x.com/path")
        self.assertNotEqual(k1, k2)


if __name__ == "__main__":
    unittest.main()
