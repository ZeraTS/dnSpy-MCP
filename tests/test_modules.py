#!/usr/bin/env python3
import sys
import tempfile
import time
from pathlib import Path

from caching import CacheManager
from ratelimit import RateLimiter, TokenBucket
from metrics import MetricsCollector
from structured_logging import StructuredLogger

def test_caching():
    print("[1] Testing CacheManager...")
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = CacheManager(Path(tmpdir), ttl_seconds=2)

        cache.set("/path/to/binary", "test_op", {"key": "val"}, {"result": "data"})

        result = cache.get("/path/to/binary", "test_op", {"key": "val"})
        assert result == {"result": "data"}, "Cache set/get failed"

        time.sleep(3)
        result = cache.get("/path/to/binary", "test_op", {"key": "val"})
        assert result is None, "Cache TTL expiration failed"

        print("  ✓ Caching works")

def test_rate_limiting():
    print("[2] Testing RateLimiter...")

    limiter = RateLimiter(default_rpm=60, burst_size=5)

    for i in range(5):
        assert limiter.is_allowed("test_key"), f"Should allow request {i}"

    assert not limiter.is_allowed("test_key"), "Should reject when burst exhausted"

    limiter.set_limit("premium_key", rpm=1000, burst=50)
    assert limiter.is_allowed("premium_key"), "Premium key should have higher limit"

    print("  ✓ Rate limiting works")

def test_token_bucket():
    print("[3] Testing TokenBucket...")

    bucket = TokenBucket(capacity=5, refill_rate=0.0)

    assert bucket.try_consume(3), "Should consume 3 tokens"
    remaining = bucket.get_tokens()
    assert abs(remaining - 2.0) < 0.1, f"Should have ~2 tokens left, got {remaining}"

    assert not bucket.try_consume(5), "Should reject 5 tokens"
    assert bucket.try_consume(2), "Should consume 2 tokens"

    print("  ✓ Token bucket works")

def test_metrics():
    print("[4] Testing MetricsCollector...")

    collector = MetricsCollector()

    collector.record_request("/api/test", 100, 200)
    collector.record_request("/api/test", 150, 200)
    collector.record_worker("decompile", 500, success=True)
    collector.set_active_workers(3, 5)
    collector.record_cache_hit("decompile")
    collector.record_rate_limit("test_key")

    prometheus = collector.to_prometheus()
    assert "dnspy_requests_total" in prometheus, "Prometheus output missing metric"
    assert "dnspy_cache_hits_total" in prometheus, "Prometheus output missing cache metric"

    print("  ✓ Metrics collection works")

def test_structured_logging():
    print("[5] Testing StructuredLogger...")

    logger = StructuredLogger("test", json_output=True)

    correlation_id = logger.request_start("/api/test", "POST")
    assert correlation_id is not None, "Correlation ID should be generated"

    logger.request_end(correlation_id, 200, 50)
    logger.worker_spawn("worker_123", "/path/to/binary")
    logger.worker_complete("worker_123", 1000, success=True)
    logger.cache_hit(correlation_id, "abc123")
    logger.cache_miss(correlation_id, "def456")

    print("  ✓ Structured logging works")

def main():
    tests = [
        test_caching,
        test_rate_limiting,
        test_token_bucket,
        test_metrics,
        test_structured_logging
    ]

    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"  ✗ {test.__name__} failed: {e}")
            return 1
        except Exception as e:
            print(f"  ✗ {test.__name__} error: {e}")
            return 1

    print("\n✓ All tests passed")
    return 0

if __name__ == "__main__":
    sys.exit(main())
