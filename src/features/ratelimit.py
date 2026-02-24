#!/usr/bin/env python3
import time
from collections import defaultdict
from typing import Optional

class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.refill_rate
        )
        self.last_refill = now

    def try_consume(self, tokens: int = 1) -> bool:
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def get_tokens(self) -> float:
        self._refill()
        return self.tokens

class RateLimiter:
    def __init__(self, default_rpm: int = 60, burst_size: int = 10):
        self.default_rpm = default_rpm
        self.burst_size = burst_size
        self.buckets = defaultdict(lambda: TokenBucket(
            capacity=burst_size,
            refill_rate=default_rpm / 60.0
        ))
        self.per_key_limits = {}

    def set_limit(self, key: str, rpm: int, burst: int = None):
        if burst is None:
            burst = max(1, rpm // 6)
        self.per_key_limits[key] = (rpm, burst)
        self.buckets[key] = TokenBucket(
            capacity=burst,
            refill_rate=rpm / 60.0
        )

    def is_allowed(self, key: str, tokens: int = 1) -> bool:
        if key not in self.buckets:
            rpm, burst = self.per_key_limits.get(key, (self.default_rpm, self.burst_size))
            self.buckets[key] = TokenBucket(
                capacity=burst,
                refill_rate=rpm / 60.0
            )

        return self.buckets[key].try_consume(tokens)

    def get_remaining(self, key: str) -> int:
        if key not in self.buckets:
            return self.burst_size
        return int(self.buckets[key].get_tokens())

    def reset(self, key: Optional[str] = None):
        if key is None:
            self.buckets.clear()
        elif key in self.buckets:
            del self.buckets[key]
