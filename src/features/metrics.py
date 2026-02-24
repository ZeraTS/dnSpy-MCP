#!/usr/bin/env python3
import time
from collections import defaultdict
from typing import Dict, List


class Histogram:
    def __init__(self, name: str, buckets: List[float] = None):
        self.name = name
        self.buckets = buckets or [0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
        self.data = defaultdict(lambda: defaultdict(int))
        self.sum = defaultdict(float)
        self.count = defaultdict(int)
    
    def observe(self, value: float, labels: Dict[str, str] = None):
        labels = labels or {}
        label_key = tuple(sorted(labels.items()))
        
        self.sum[label_key] += value
        self.count[label_key] += 1
        
        for bucket in self.buckets:
            if value <= bucket:
                self.data[label_key][bucket] += 1


class Counter:
    def __init__(self, name: str):
        self.name = name
        self.data = defaultdict(int)
    
    def inc(self, value: int = 1, labels: Dict[str, str] = None):
        labels = labels or {}
        label_key = tuple(sorted(labels.items()))
        self.data[label_key] += value


class Gauge:
    def __init__(self, name: str):
        self.name = name
        self.data = {}
    
    def set(self, value: float, labels: Dict[str, str] = None):
        labels = labels or {}
        label_key = tuple(sorted(labels.items()))
        self.data[label_key] = value


class MetricsCollector:
    def __init__(self):
        self.request_duration = Histogram("dnspy_request_duration_seconds")
        self.requests_total = Counter("dnspy_requests_total")
        self.requests_failed = Counter("dnspy_requests_failed")
        self.worker_duration = Histogram("dnspy_worker_duration_seconds")
        self.workers_active = Gauge("dnspy_workers_active")
        self.cache_hits = Counter("dnspy_cache_hits_total")
        self.cache_misses = Counter("dnspy_cache_misses_total")
        self.rate_limit_exceeded = Counter("dnspy_rate_limit_exceeded_total")
    
    def record_request(self, endpoint: str, duration_ms: float, status: int = 200):
        duration_s = duration_ms / 1000.0
        self.request_duration.observe(duration_s, {"endpoint": endpoint, "status": str(status)})
        self.requests_total.inc(labels={"endpoint": endpoint})
        
        if status >= 400:
            self.requests_failed.inc(labels={"endpoint": endpoint, "status": str(status)})
    
    def record_worker(self, operation: str, duration_ms: float, success: bool = True):
        duration_s = duration_ms / 1000.0
        self.worker_duration.observe(duration_s, {"operation": operation, "success": str(success)})
    
    def set_active_workers(self, count: int, pool_size: int):
        self.workers_active.set(count, {"state": "active"})
        self.workers_active.set(pool_size, {"state": "total"})
    
    def record_cache_hit(self, operation: str):
        self.cache_hits.inc(labels={"operation": operation})
    
    def record_cache_miss(self, operation: str):
        self.cache_misses.inc(labels={"operation": operation})
    
    def record_rate_limit(self, api_key: str):
        self.rate_limit_exceeded.inc(labels={"api_key_prefix": api_key[:8]})
    
    def to_prometheus(self) -> str:
        lines = []
        
        lines.append("# HELP dnspy_request_duration_seconds Request duration in seconds")
        lines.append("# TYPE dnspy_request_duration_seconds histogram")
        for labels, count in self.request_duration.count.items():
            label_str = self._format_labels(labels)
            avg = self.request_duration.sum[labels] / count if count > 0 else 0
            lines.append(f'dnspy_request_duration_seconds_sum{label_str} {self.request_duration.sum[labels]:.3f}')
            lines.append(f'dnspy_request_duration_seconds_count{label_str} {count}')
        
        lines.append("# HELP dnspy_requests_total Total requests")
        lines.append("# TYPE dnspy_requests_total counter")
        for labels, count in self.requests_total.data.items():
            label_str = self._format_labels(labels)
            lines.append(f'dnspy_requests_total{label_str} {count}')
        
        lines.append("# HELP dnspy_requests_failed Failed requests")
        lines.append("# TYPE dnspy_requests_failed counter")
        for labels, count in self.requests_failed.data.items():
            label_str = self._format_labels(labels)
            lines.append(f'dnspy_requests_failed{label_str} {count}')
        
        lines.append("# HELP dnspy_workers_active Active workers")
        lines.append("# TYPE dnspy_workers_active gauge")
        for labels, value in self.workers_active.data.items():
            label_str = self._format_labels(labels)
            lines.append(f'dnspy_workers_active{label_str} {value}')
        
        lines.append("# HELP dnspy_cache_hits_total Total cache hits")
        lines.append("# TYPE dnspy_cache_hits_total counter")
        for labels, count in self.cache_hits.data.items():
            label_str = self._format_labels(labels)
            lines.append(f'dnspy_cache_hits_total{label_str} {count}')
        
        lines.append("# HELP dnspy_cache_misses_total Total cache misses")
        lines.append("# TYPE dnspy_cache_misses_total counter")
        for labels, count in self.cache_misses.data.items():
            label_str = self._format_labels(labels)
            lines.append(f'dnspy_cache_misses_total{label_str} {count}')
        
        return "\n".join(lines)
    
    def _format_labels(self, labels: tuple) -> str:
        if not labels:
            return ""
        
        pairs = [f'{k}="{v}"' for k, v in labels]
        return "{" + ",".join(pairs) + "}"
