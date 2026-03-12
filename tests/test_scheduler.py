"""Tests for the scheduler and anti-blocking systems."""

import threading
import time
import unittest

from web_crawler.scheduler import CrawlScheduler
from web_crawler.scheduler.worker_pool import URLQueue
from web_crawler.anti_blocking import RateLimiter, BlockDetector


class TestURLQueue(unittest.TestCase):
    def test_push_and_pop(self):
        q = URLQueue(max_size=10)
        q.push("https://example.com/", 0)
        item = q.pop()
        self.assertEqual(item, ("https://example.com/", 0))

    def test_deduplication(self):
        q = URLQueue(max_size=10)
        q.push("https://example.com/", 0)
        q.push("https://example.com/", 1)  # duplicate
        self.assertEqual(len(q), 1)

    def test_empty_pop(self):
        q = URLQueue(max_size=10)
        self.assertIsNone(q.pop())

    def test_bool(self):
        q = URLQueue(max_size=10)
        self.assertFalse(q)
        q.push("https://example.com/", 0)
        self.assertTrue(q)

    def test_max_size(self):
        q = URLQueue(max_size=2)
        self.assertTrue(q.push("https://a.com", 0))
        self.assertTrue(q.push("https://b.com", 0))
        self.assertFalse(q.push("https://c.com", 0))

    def test_priority(self):
        q = URLQueue(max_size=10)
        q.push("https://a.com", 0)
        q.push("https://b.com", 0, priority=True)
        item = q.pop()
        self.assertEqual(item[0], "https://b.com")

    def test_pop_batch(self):
        q = URLQueue(max_size=10)
        for i in range(5):
            q.push(f"https://site{i}.com", 0)
        batch = q.pop_batch(3)
        self.assertEqual(len(batch), 3)
        self.assertEqual(len(q), 2)

    def test_thread_safety(self):
        q = URLQueue(max_size=1000)
        errors = []

        def enqueue_batch(prefix, count):
            for i in range(count):
                try:
                    q.push(f"https://{prefix}-{i}.com", 0)
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=enqueue_batch, args=(f"t{t}", 50))
            for t in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(q), 250)


class TestCrawlScheduler(unittest.TestCase):
    def test_serial_execution(self):
        results = []

        def worker(url, depth):
            results.append((url, depth))

        sched = CrawlScheduler(worker, concurrency=1)
        sched.enqueue("https://a.com", 0)
        sched.enqueue("https://b.com", 1)
        sched.run()
        self.assertEqual(len(results), 2)

    def test_concurrent_execution(self):
        results = []
        lock = threading.Lock()

        def worker(url, depth):
            time.sleep(0.01)
            with lock:
                results.append(url)

        sched = CrawlScheduler(worker, concurrency=4)
        for i in range(10):
            sched.enqueue(f"https://site{i}.com", 0)
        sched.run()
        self.assertEqual(len(results), 10)

    def test_deduplication_in_scheduler(self):
        results = []

        def worker(url, depth):
            results.append(url)

        sched = CrawlScheduler(worker, concurrency=1)
        sched.enqueue("https://example.com", 0)
        sched.enqueue("https://example.com", 1)  # duplicate
        sched.run()
        self.assertEqual(len(results), 1)

    def test_stats(self):
        def worker(url, depth):
            pass

        sched = CrawlScheduler(worker, concurrency=1)
        sched.enqueue("https://a.com", 0)
        sched.run()
        self.assertEqual(sched.stats["processed"], 1)


class TestRateLimiter(unittest.TestCase):
    def test_base_delay(self):
        limiter = RateLimiter(base_delay=0.01)
        self.assertAlmostEqual(limiter.current_delay, 0.01, places=2)

    def test_backoff_on_block(self):
        limiter = RateLimiter(base_delay=0.01, max_delay=1.0)
        initial = limiter.current_delay
        limiter.report_block()
        self.assertGreater(limiter.current_delay, initial)

    def test_recovery_on_success(self):
        limiter = RateLimiter(base_delay=0.01, max_delay=1.0)
        limiter.report_block()
        limiter.report_block()
        high = limiter.current_delay
        limiter.report_success()
        self.assertLessEqual(limiter.current_delay, high)

    def test_max_delay_cap(self):
        limiter = RateLimiter(base_delay=0.01, max_delay=0.1)
        for _ in range(20):
            limiter.report_block()
        self.assertLessEqual(limiter.current_delay, 0.1)


class TestBlockDetector(unittest.TestCase):
    def test_429_is_blocked(self):
        bd = BlockDetector()
        self.assertTrue(bd.is_blocked(429, {}))

    def test_403_is_blocked(self):
        bd = BlockDetector()
        self.assertTrue(bd.is_blocked(403, {}))

    def test_503_is_blocked(self):
        bd = BlockDetector()
        self.assertTrue(bd.is_blocked(503, {}))

    def test_200_not_blocked(self):
        bd = BlockDetector()
        self.assertFalse(bd.is_blocked(200, {}))

    def test_cloudflare_challenge_blocked(self):
        bd = BlockDetector()
        self.assertTrue(bd.is_blocked(200, {"cf-mitigated": "challenge"}))

    def test_retry_after_header(self):
        bd = BlockDetector()
        self.assertTrue(bd.is_blocked(200, {"retry-after": "30"}))


if __name__ == "__main__":
    unittest.main()
