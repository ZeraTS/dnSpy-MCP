#!/usr/bin/env python3
import json
import logging
import sys
import time
import uuid
from datetime import datetime
from typing import Any, Optional

class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        for key in ["correlation_id", "worker_id", "api_key_hash", "duration_ms", "status_code"]:
            if hasattr(record, key):
                log_obj[key] = getattr(record, key)

        return json.dumps(log_obj)

class StructuredLogger:
    def __init__(self, name: str, json_output: bool = True):
        self.logger = logging.getLogger(name)
        self.json_output = json_output

        handler = logging.StreamHandler(sys.stdout)
        if json_output:
            handler.setFormatter(StructuredFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            ))

        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def _add_context(self, extra: dict):
        record = logging.LogRecord(
            name=self.logger.name,
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="",
            args=(),
            exc_info=None
        )
        for key, val in extra.items():
            setattr(record, key, val)
        return record

    def request_start(self, endpoint: str, method: str, api_key_hash: str = None):
        correlation_id = str(uuid.uuid4())
        extra = {
            "correlation_id": correlation_id,
            "event": "request_start",
            "endpoint": endpoint,
            "method": method,
        }
        if api_key_hash:
            extra["api_key_hash"] = api_key_hash

        self.logger.info(f"Request: {method} {endpoint}", extra=extra)
        return correlation_id

    def request_end(self, correlation_id: str, status_code: int, duration_ms: float):
        extra = {
            "correlation_id": correlation_id,
            "event": "request_end",
            "status_code": status_code,
            "duration_ms": int(duration_ms)
        }
        self.logger.info(f"Response: {status_code}", extra=extra)

    def worker_spawn(self, worker_id: str, binary_path: str):
        extra = {
            "worker_id": worker_id,
            "event": "worker_spawn",
            "binary": binary_path
        }
        self.logger.info(f"Worker spawned: {worker_id}", extra=extra)

    def worker_complete(self, worker_id: str, duration_ms: float, success: bool = True):
        extra = {
            "worker_id": worker_id,
            "event": "worker_complete",
            "duration_ms": int(duration_ms),
            "success": success
        }
        level = logging.INFO if success else logging.ERROR
        self.logger.log(level, f"Worker complete: {worker_id}", extra=extra)

    def cache_hit(self, correlation_id: str, binary_hash: str):
        extra = {
            "correlation_id": correlation_id,
            "event": "cache_hit",
            "binary_hash": binary_hash
        }
        self.logger.info("Cache hit", extra=extra)

    def cache_miss(self, correlation_id: str, binary_hash: str):
        extra = {
            "correlation_id": correlation_id,
            "event": "cache_miss",
            "binary_hash": binary_hash
        }
        self.logger.info("Cache miss", extra=extra)

    def rate_limit_exceeded(self, api_key: str, tokens_requested: int, tokens_available: int):
        extra = {
            "event": "rate_limit_exceeded",
            "api_key_hash": api_key[:8],
            "tokens_requested": tokens_requested,
            "tokens_available": tokens_available
        }
        self.logger.warning("Rate limit exceeded", extra=extra)

    def error(self, message: str, correlation_id: Optional[str] = None, **kwargs):
        extra = {"event": "error"}
        if correlation_id:
            extra["correlation_id"] = correlation_id
        extra.update(kwargs)
        self.logger.error(message, extra=extra)

    def debug(self, message: str, **kwargs):
        extra = kwargs
        self.logger.debug(message, extra=extra)
