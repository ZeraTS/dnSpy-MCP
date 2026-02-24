#!/usr/bin/env python3
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict
from datetime import datetime
import uuid
import hashlib

from aiohttp import web
from pydantic import BaseModel, ValidationError

from daemon_worker import DnsyWorker
from caching import CacheManager
from ratelimit import RateLimiter
from structured_logging import StructuredLogger
from metrics import MetricsCollector
from webhooks import WebhookManager, WebhookEventTypes


class Config:
    def __init__(self):
        self.config_path = Path(os.getenv("DNSPY_CONFIG_PATH", "./config.json"))
        self.config = self._load_config()
        self.logger = StructuredLogger("config", json_output=True)
    
    def _load_config(self) -> dict:
        defaults = {
            "daemon": {
                "port": 9001,
                "host": "127.0.0.1",
                "worker_pool_size": 5,
                "request_timeout_seconds": 120,
                "api_key": "default-insecure-key-change-me"
            },
            "features": {
                "enable_caching": True,
                "enable_rate_limiting": True,
                "enable_metrics": True,
                "enable_structured_logging": True,
                "enable_webhooks": False
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    user_config = json.load(f)
                    for key in defaults:
                        if key in user_config:
                            defaults[key].update(user_config[key])
                    return defaults
            except Exception as e:
                print(f"Failed to load config: {e}, using defaults", file=sys.stderr)
                return defaults
        
        return defaults
    
    def get(self, key: str, default=None):
        keys = key.split(".")
        val = self.config
        for k in keys:
            val = val.get(k, {})
        return val if val else default


config = Config()
logger = StructuredLogger("daemon", json_output=config.get("features.enable_structured_logging", True))

DAEMON_PORT = int(os.getenv("DNSPY_DAEMON_PORT", config.get("daemon.port")))
DNSPY_HOST = os.getenv("DNSPY_HOST", config.get("daemon.host"))
DNSPY_PATH = os.getenv("DNSPY_PATH", config.get("dnspy.path", "/opt/dnspy/dnSpy.exe"))
API_KEY = os.getenv("DNSPY_API_KEY", config.get("daemon.api_key"))
WORKER_POOL_SIZE = int(os.getenv("DNSPY_WORKER_POOL_SIZE", config.get("daemon.worker_pool_size")))

FEATURES = {
    "caching": config.get("features.enable_caching", True),
    "rate_limiting": config.get("features.enable_rate_limiting", True),
    "metrics": config.get("features.enable_metrics", True),
    "webhooks": config.get("features.enable_webhooks", False)
}

TEMP_BASE = Path.home() / ".dnspy-worker"
TEMP_BASE.mkdir(parents=True, exist_ok=True)

workers: Dict[str, DnsyWorker] = {}
cache = CacheManager() if FEATURES["caching"] else None
rate_limiter = RateLimiter() if FEATURES["rate_limiting"] else None
metrics = MetricsCollector() if FEATURES["metrics"] else None
webhook_manager = WebhookManager() if FEATURES["webhooks"] else None

stats = {
    "total_requests": 0,
    "successful_requests": 0,
    "failed_requests": 0,
    "start_time": datetime.utcnow()
}


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:8]


@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.path in ["/health", "/metrics"] and request.method in ["GET"]:
        return await handler(request)
    
    provided_key = request.headers.get("X-API-Key", "")
    if provided_key != API_KEY:
        logger.logger.warning(f"Unauthorized access from {request.remote}")
        stats["failed_requests"] += 1
        return web.json_response(
            {"error": "Unauthorized"},
            status=401
        )
    
    return await handler(request)


@web.middleware
async def metrics_middleware(request: web.Request, handler):
    start_time = time.time()
    correlation_id = logger.request_start(
        endpoint=request.path,
        method=request.method,
        api_key_hash=_hash_api_key(request.headers.get("X-API-Key", ""))
    )
    
    try:
        response = await handler(request)
        duration_ms = (time.time() - start_time) * 1000
        
        logger.request_end(correlation_id, response.status, duration_ms)
        if FEATURES["metrics"]:
            metrics.record_request(request.path, duration_ms, response.status)
        
        response.headers["X-Correlation-ID"] = correlation_id
        return response
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        logger.error(f"Request failed: {str(e)}", correlation_id=correlation_id)
        if FEATURES["metrics"]:
            metrics.record_request(request.path, duration_ms, 500)
        raise


class DecompileRequest(BaseModel):
    binary_path: str
    output_format: str = "vscode"
    extract_classes: list[str] | None = None
    analyze_obfuscation: bool = False
    webhook_url: str | None = None


class BreakpointRequest(BaseModel):
    binary_path: str
    type_name: str
    method_name: str
    il_offset: int | None = None


class BatchRequest(BaseModel):
    binaries: list[str]
    output_format: str = "vscode"
    analyze_obfuscation: bool = False
    webhook_url: str | None = None


async def handle_decompile(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4())[:8])
    
    try:
        data = await request.json()
        req = DecompileRequest(**data)
        
        binary_path = Path(req.binary_path)
        if not binary_path.exists():
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": f"Binary not found"},
                status=400
            )
        
        cache_result = None
        if FEATURES["caching"]:
            cache_result = cache.get(req.binary_path, "decompile", {
                "output_format": req.output_format,
                "analyze_obfuscation": req.analyze_obfuscation
            })
            if cache_result:
                logger.cache_hit(correlation_id, binary_path.name)
                if FEATURES["metrics"]:
                    metrics.record_cache_hit("decompile")
        
        if cache_result:
            stats["successful_requests"] += 1
            return web.json_response({
                "status": "success",
                "cached": True,
                "result": cache_result
            })
        
        if FEATURES["rate_limiting"] and not rate_limiter.is_allowed(API_KEY):
            logger.rate_limit_exceeded(API_KEY, 1, 0)
            if FEATURES["metrics"]:
                metrics.record_rate_limit(API_KEY)
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Rate limit exceeded"},
                status=429
            )
        
        if FEATURES["caching"]:
            logger.cache_miss(correlation_id, binary_path.name)
            if FEATURES["metrics"]:
                metrics.record_cache_miss("decompile")
        
        worker_id = str(uuid.uuid4())[:8]
        logger.worker_spawn(worker_id, req.binary_path)
        
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        worker_start = time.time()
        result = await worker.decompile(
            output_format=req.output_format,
            extract_classes=req.extract_classes or [],
            analyze_obfuscation=req.analyze_obfuscation
        )
        worker_duration = (time.time() - worker_start) * 1000
        
        await worker.cleanup()
        del workers[worker_id]
        
        logger.worker_complete(worker_id, worker_duration, success=True)
        if FEATURES["metrics"]:
            metrics.record_worker("decompile", worker_duration, success=True)
        
        if FEATURES["caching"]:
            cache.set(req.binary_path, "decompile", {
                "output_format": req.output_format,
                "analyze_obfuscation": req.analyze_obfuscation
            }, result)
        
        if FEATURES["webhooks"] and req.webhook_url:
            asyncio.create_task(webhook_manager.send_async(
                req.webhook_url,
                WebhookEventTypes.DECOMPILE_COMPLETE,
                {"worker_id": worker_id, "status": "success"}
            ))
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "cached": False,
            "result": result
        })
    
    except ValidationError as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Decompile error: {e}", correlation_id=correlation_id)
        return web.json_response({"error": str(e)}, status=500)


async def handle_analyze_obfuscation(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4())[:8])
    
    try:
        data = await request.json()
        
        if "binary_path" not in data:
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "binary_path required"},
                status=400
            )
        
        binary_path = Path(data["binary_path"])
        if not binary_path.exists():
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Binary not found"},
                status=400
            )
        
        if FEATURES["rate_limiting"] and not rate_limiter.is_allowed(API_KEY):
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Rate limit exceeded"},
                status=429
            )
        
        worker_id = str(uuid.uuid4())[:8]
        logger.worker_spawn(worker_id, data["binary_path"])
        
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        worker_start = time.time()
        result = await worker.analyze_obfuscation()
        worker_duration = (time.time() - worker_start) * 1000
        
        await worker.cleanup()
        del workers[worker_id]
        
        logger.worker_complete(worker_id, worker_duration, success=True)
        if FEATURES["metrics"]:
            metrics.record_worker("analyze_obfuscation", worker_duration, success=True)
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "obfuscation_analysis": result
        })
    
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Analysis error: {e}", correlation_id=correlation_id)
        return web.json_response({"error": str(e)}, status=500)


async def handle_extract_class(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4())[:8])
    
    try:
        data = await request.json()
        
        required = ["binary_path", "class_name"]
        if not all(k in data for k in required):
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": f"Required: {required}"},
                status=400
            )
        
        binary_path = Path(data["binary_path"])
        if not binary_path.exists():
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Binary not found"},
                status=400
            )
        
        if FEATURES["rate_limiting"] and not rate_limiter.is_allowed(API_KEY):
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Rate limit exceeded"},
                status=429
            )
        
        worker_id = str(uuid.uuid4())[:8]
        logger.worker_spawn(worker_id, data["binary_path"])
        
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        worker_start = time.time()
        result = await worker.extract_class(data["class_name"])
        worker_duration = (time.time() - worker_start) * 1000
        
        await worker.cleanup()
        del workers[worker_id]
        
        logger.worker_complete(worker_id, worker_duration, success=True)
        if FEATURES["metrics"]:
            metrics.record_worker("extract_class", worker_duration, success=True)
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "class_source": result
        })
    
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Extract error: {e}", correlation_id=correlation_id)
        return web.json_response({"error": str(e)}, status=500)


async def handle_set_breakpoint(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4())[:8])
    
    try:
        data = await request.json()
        req = BreakpointRequest(**data)
        
        binary_path = Path(req.binary_path)
        if not binary_path.exists():
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Binary not found"},
                status=400
            )
        
        if FEATURES["rate_limiting"] and not rate_limiter.is_allowed(API_KEY):
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Rate limit exceeded"},
                status=429
            )
        
        worker_id = str(uuid.uuid4())[:8]
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(req.binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        worker_start = time.time()
        result = await worker.set_breakpoint(
            type_name=req.type_name,
            method_name=req.method_name,
            il_offset=req.il_offset
        )
        worker_duration = (time.time() - worker_start) * 1000
        
        await worker.cleanup()
        del workers[worker_id]
        
        logger.worker_complete(worker_id, worker_duration, success=True)
        if FEATURES["metrics"]:
            metrics.record_worker("set_breakpoint", worker_duration, success=True)
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "breakpoint": result
        })
    
    except ValidationError as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Breakpoint error: {e}", correlation_id=correlation_id)
        return web.json_response({"error": str(e)}, status=500)


async def handle_batch_dump(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4())[:8])
    
    try:
        data = await request.json()
        req = BatchRequest(**data)
        
        if FEATURES["rate_limiting"] and not rate_limiter.is_allowed(API_KEY, len(req.binaries)):
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Rate limit exceeded"},
                status=429
            )
        
        results = {}
        for binary_path in req.binaries:
            bp = Path(binary_path)
            if not bp.exists():
                results[binary_path] = {"error": "Binary not found"}
                continue
            
            worker_id = str(uuid.uuid4())[:8]
            try:
                logger.worker_spawn(worker_id, binary_path)
                
                worker = DnsyWorker(
                    worker_id=worker_id,
                    dnspy_path=DNSPY_PATH,
                    binary_path=binary_path,
                    temp_dir=TEMP_BASE
                )
                workers[worker_id] = worker
                
                worker_start = time.time()
                decompile_result = await worker.decompile(
                    output_format=req.output_format,
                    analyze_obfuscation=req.analyze_obfuscation
                )
                worker_duration = (time.time() - worker_start) * 1000
                
                results[binary_path] = {
                    "status": "success",
                    "result": decompile_result
                }
                
                await worker.cleanup()
                del workers[worker_id]
                
                logger.worker_complete(worker_id, worker_duration, success=True)
                if FEATURES["metrics"]:
                    metrics.record_worker("batch_decompile", worker_duration, success=True)
            
            except Exception as e:
                logger.error(f"Batch error for {binary_path}: {e}", correlation_id=correlation_id)
                results[binary_path] = {"error": str(e)}
        
        if FEATURES["webhooks"] and req.webhook_url:
            asyncio.create_task(webhook_manager.send_async(
                req.webhook_url,
                WebhookEventTypes.BATCH_COMPLETE,
                {"total": len(req.binaries), "completed": len([r for r in results.values() if r.get("status") == "success"])}
            ))
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "batch_results": results
        })
    
    except ValidationError as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Batch error: {e}", correlation_id=correlation_id)
        return web.json_response({"error": str(e)}, status=500)


async def handle_health(request: web.Request) -> web.Response:
    uptime = (datetime.utcnow() - stats["start_time"]).total_seconds()
    success_rate = (
        (stats["successful_requests"] / stats["total_requests"] * 100)
        if stats["total_requests"] > 0
        else 0
    )
    
    if FEATURES["metrics"]:
        metrics.set_active_workers(len(workers), WORKER_POOL_SIZE)
    
    return web.json_response({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": uptime,
        "active_workers": len(workers),
        "worker_pool_size": WORKER_POOL_SIZE,
        "stats": {
            "total_requests": stats["total_requests"],
            "successful_requests": stats["successful_requests"],
            "failed_requests": stats["failed_requests"],
            "success_rate_percent": round(success_rate, 2)
        },
        "features": FEATURES,
        "config": {
            "dnspy_path": DNSPY_PATH,
            "host": DNSPY_HOST,
            "port": DAEMON_PORT
        }
    })


async def handle_metrics(request: web.Request) -> web.Response:
    if not FEATURES["metrics"]:
        return web.Response(text="Metrics disabled", status=404)
    
    prometheus_output = metrics.to_prometheus()
    return web.Response(text=prometheus_output, content_type="text/plain")


async def handle_cleanup_all(request: web.Request) -> web.Response:
    count = len(workers)
    for worker in workers.values():
        await worker.cleanup()
    workers.clear()
    
    logger.logger.info(f"Cleaned up {count} workers")
    return web.json_response({
        "status": "success",
        "cleaned_up": count
    })


def create_app() -> web.Application:
    app = web.Application(middlewares=[metrics_middleware, auth_middleware])
    
    app.router.add_post("/api/decompile", handle_decompile)
    app.router.add_post("/api/analyze-obfuscation", handle_analyze_obfuscation)
    app.router.add_post("/api/extract-class", handle_extract_class)
    app.router.add_post("/api/set-breakpoint", handle_set_breakpoint)
    app.router.add_post("/api/batch-dump", handle_batch_dump)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/metrics", handle_metrics)
    app.router.add_post("/cleanup", handle_cleanup_all)
    
    return app


async def main():
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    
    site = web.TCPSite(runner, DNSPY_HOST, DAEMON_PORT)
    await site.start()
    
    logger.logger.info(f"dnspy MCP daemon on {DNSPY_HOST}:{DAEMON_PORT}")
    logger.logger.info(f"Features: {FEATURES}")
    
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.logger.info("Shutting down")
        for worker in workers.values():
            await worker.cleanup()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
