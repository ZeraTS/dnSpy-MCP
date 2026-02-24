#!/usr/bin/env python3
import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Dict
from datetime import datetime
import uuid

from aiohttp import web
from pydantic import BaseModel, ValidationError

from src.core.daemon_worker import DnsyWorker

class Config:
    def __init__(self):
        self.config_path = Path(os.getenv("DNSPY_CONFIG_PATH", "./config.json"))
        self.config = self._load_config()
        self._setup_logging()
    
    def _load_config(self) -> dict:
        defaults = {
            "daemon": {
                "port": 9001,
                "host": "127.0.0.1",
                "worker_pool_size": 5,
                "request_timeout_seconds": 120,
                "api_key": "default-insecure-key-change-me"
            },
            "dnspy": {
                "path": "/opt/dnspy/dnSpy.exe",
                "timeout_seconds": 60
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
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
                logging.warning(f"Failed to load config: {e}, using defaults")
                return defaults
        
        return defaults
    
    def _setup_logging(self):
        log_config = self.config.get("logging", {})
        logging.basicConfig(
            level=getattr(logging, log_config.get("level", "INFO")),
            format=log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
    
    def get(self, key: str, default=None):
        keys = key.split(".")
        val = self.config
        for k in keys:
            val = val.get(k, {})
        return val if val else default


config = Config()
logger = logging.getLogger(__name__)

DAEMON_PORT = int(os.getenv("DNSPY_DAEMON_PORT", config.get("daemon.port")))
DNSPY_HOST = os.getenv("DNSPY_HOST", config.get("daemon.host"))
DNSPY_PATH = os.getenv("DNSPY_PATH", config.get("dnspy.path"))
API_KEY = os.getenv("DNSPY_API_KEY", config.get("daemon.api_key"))
WORKER_POOL_SIZE = int(os.getenv("DNSPY_WORKER_POOL_SIZE", config.get("daemon.worker_pool_size")))

TEMP_BASE = Path.home() / ".dnspy-worker"
TEMP_BASE.mkdir(parents=True, exist_ok=True)

workers: Dict[str, DnsyWorker] = {}
stats = {
    "total_requests": 0,
    "successful_requests": 0,
    "failed_requests": 0,
    "start_time": datetime.utcnow()
}


@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.path == "/health" and request.method == "GET":
        return await handler(request)
    
    provided_key = request.headers.get("X-API-Key", "")
    if provided_key != API_KEY:
        logger.warning(f"Unauthorized access from {request.remote}")
        stats["failed_requests"] += 1
        return web.json_response(
            {"error": "Unauthorized. Set X-API-Key header."},
            status=401
        )
    
    return await handler(request)


class DecompileRequest(BaseModel):
    binary_path: str
    output_format: str = "vscode"
    extract_classes: list[str] | None = None
    analyze_obfuscation: bool = False


class BreakpointRequest(BaseModel):
    binary_path: str
    type_name: str
    method_name: str
    il_offset: int | None = None


class BatchRequest(BaseModel):
    binaries: list[str]
    output_format: str = "vscode"
    analyze_obfuscation: bool = False


async def handle_decompile(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        req = DecompileRequest(**data)
        
        worker_id = str(uuid.uuid4())[:8]
        binary_path = Path(req.binary_path)
        
        if not binary_path.exists():
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": f"Binary not found: {req.binary_path}"},
                status=400
            )
        
        logger.info(f"[{worker_id}] Decompiling {binary_path}")
        
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        result = await worker.decompile(
            output_format=req.output_format,
            extract_classes=req.extract_classes or [],
            analyze_obfuscation=req.analyze_obfuscation
        )
        
        await worker.cleanup()
        del workers[worker_id]
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "worker_id": worker_id,
            "result": result
        })
    
    except ValidationError as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Decompile error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def handle_analyze_obfuscation(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
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
        
        worker_id = str(uuid.uuid4())[:8]
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        logger.info(f"[{worker_id}] Analyzing obfuscation")
        result = await worker.analyze_obfuscation()
        
        await worker.cleanup()
        del workers[worker_id]
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "obfuscation_analysis": result
        })
    
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Analysis error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def handle_extract_class(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
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
        class_name = data["class_name"]
        
        if not binary_path.exists():
            stats["failed_requests"] += 1
            return web.json_response(
                {"error": "Binary not found"},
                status=400
            )
        
        worker_id = str(uuid.uuid4())[:8]
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        logger.info(f"[{worker_id}] Extracting class {class_name}")
        result = await worker.extract_class(class_name)
        
        await worker.cleanup()
        del workers[worker_id]
        
        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "class_source": result
        })
    
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"Extract error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def handle_set_breakpoint(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
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
        
        worker_id = str(uuid.uuid4())[:8]
        worker = DnsyWorker(
            worker_id=worker_id,
            dnspy_path=DNSPY_PATH,
            binary_path=str(req.binary_path),
            temp_dir=TEMP_BASE
        )
        workers[worker_id] = worker
        
        logger.info(f"[{worker_id}] Breakpoint: {req.type_name}.{req.method_name}")
        result = await worker.set_breakpoint(
            type_name=req.type_name,
            method_name=req.method_name,
            il_offset=req.il_offset
        )
        
        await worker.cleanup()
        del workers[worker_id]
        
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
        logger.error(f"Breakpoint error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def handle_batch_dump(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        req = BatchRequest(**data)
        
        results = {}
        for binary_path in req.binaries:
            bp = Path(binary_path)
            if not bp.exists():
                results[binary_path] = {"error": "Binary not found"}
                continue
            
            worker_id = str(uuid.uuid4())[:8]
            try:
                worker = DnsyWorker(
                    worker_id=worker_id,
                    dnspy_path=DNSPY_PATH,
                    binary_path=binary_path,
                    temp_dir=TEMP_BASE
                )
                workers[worker_id] = worker
                
                logger.info(f"[{worker_id}] Batch: {binary_path}")
                
                decompile_result = await worker.decompile(
                    output_format=req.output_format,
                    analyze_obfuscation=req.analyze_obfuscation
                )
                
                results[binary_path] = {
                    "status": "success",
                    "result": decompile_result
                }
                
                await worker.cleanup()
                del workers[worker_id]
            
            except Exception as e:
                logger.error(f"Batch error for {binary_path}: {e}")
                results[binary_path] = {"error": str(e)}
        
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
        logger.error(f"Batch error: {e}", exc_info=True)
        return web.json_response({"error": str(e)}, status=500)


async def handle_health(request: web.Request) -> web.Response:
    uptime = (datetime.utcnow() - stats["start_time"]).total_seconds()
    success_rate = (
        (stats["successful_requests"] / stats["total_requests"] * 100)
        if stats["total_requests"] > 0
        else 0
    )
    
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
        "config": {
            "dnspy_path": DNSPY_PATH,
            "host": DNSPY_HOST,
            "port": DAEMON_PORT
        }
    })


async def handle_cleanup_all(request: web.Request) -> web.Response:
    count = len(workers)
    for worker in workers.values():
        await worker.cleanup()
    workers.clear()
    
    logger.info(f"Cleaned up {count} workers")
    return web.json_response({
        "status": "success",
        "cleaned_up": count
    })


def create_app() -> web.Application:
    app = web.Application(middlewares=[auth_middleware])
    
    app.router.add_post("/api/decompile", handle_decompile)
    app.router.add_post("/api/analyze-obfuscation", handle_analyze_obfuscation)
    app.router.add_post("/api/extract-class", handle_extract_class)
    app.router.add_post("/api/set-breakpoint", handle_set_breakpoint)
    app.router.add_post("/api/batch-dump", handle_batch_dump)
    app.router.add_get("/health", handle_health)
    app.router.add_post("/cleanup", handle_cleanup_all)
    
    return app


async def main():
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    
    site = web.TCPSite(runner, DNSPY_HOST, DAEMON_PORT)
    await site.start()
    
    logger.info(f"dnspy MCP daemon on {DNSPY_HOST}:{DAEMON_PORT}")
    logger.info(f"dnspy path: {DNSPY_PATH}")
    logger.info(f"worker pool size: {WORKER_POOL_SIZE}")
    logger.info("API authentication required (X-API-Key header)")
    
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        for worker in workers.values():
            await worker.cleanup()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
