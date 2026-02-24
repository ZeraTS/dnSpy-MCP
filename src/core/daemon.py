#!/usr/bin/env python3
"""
dnspy-mcp Daemon

MCP-compatible HTTP server exposing .NET decompilation and analysis via
ICSharpCode.Decompiler (dnSpyEx engine). All endpoints are protected by
X-API-Key authentication. No target assembly is ever executed.

Security model:
  - All endpoints require X-API-Key header (except /health when
    DNSPY_HEALTH_PUBLIC=false, which is the default)
  - Configurable host binding (set DNSPY_HOST=0.0.0.0 for network access
    on a hardened/firewalled host)
  - Binary paths are validated against an optional allowlist
  - Worker processes are isolated and cleaned up on completion
"""
import asyncio
import json
import os
import sys
import time
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from aiohttp import web
from pydantic import BaseModel, ValidationError

from src.core.daemon_worker import DnsyWorker
from src.features.caching import CacheManager
from src.features.ratelimit import RateLimiter
from src.utils.structured_logging import StructuredLogger
from src.features.metrics import MetricsCollector
from src.features.webhooks import WebhookManager, WebhookEventTypes


# ─── Configuration ────────────────────────────────────────────────────────────

class Config:
    def __init__(self):
        self.config_path = Path(os.getenv("DNSPY_CONFIG_PATH", "./config.json"))
        self.config = self._load_config()

    def _load_config(self) -> dict:
        defaults = {
            "daemon": {
                "port": 9001,
                "host": "0.0.0.0",          # bind all interfaces on hardened host
                "worker_pool_size": 5,
                "request_timeout_seconds": 120,
                "api_key": None,             # MUST be set via env or config; no insecure default
                "health_public": False,      # require API key on /health and /metrics
                "allowed_binary_dirs": [],   # if non-empty, restrict binary paths to these dirs
            },
            "features": {
                "enable_caching": True,
                "enable_rate_limiting": True,
                "enable_metrics": True,
                "enable_structured_logging": True,
                "enable_webhooks": False,
            },
        }

        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    user_config = json.load(f)
                    for key in defaults:
                        if key in user_config:
                            defaults[key].update(user_config[key])
            except Exception as e:
                print(f"Failed to load config: {e}, using defaults", file=sys.stderr)

        return defaults

    def get(self, key: str, default=None):
        keys = key.split(".")
        val = self.config
        for k in keys:
            if not isinstance(val, dict):
                return default
            val = val.get(k)
            if val is None:
                return default
        return val


config = Config()
logger = StructuredLogger(
    "daemon",
    json_output=config.get("features.enable_structured_logging", True)
)

# ─── Runtime config (env overrides config file) ───────────────────────────────

DAEMON_PORT = int(os.getenv("DNSPY_DAEMON_PORT", config.get("daemon.port", 9001)))
DNSPY_HOST  = os.getenv("DNSPY_HOST", config.get("daemon.host", "0.0.0.0"))
DNSPY_PATH  = os.getenv("DNSPY_PATH", config.get("dnspy.path", "/opt/dnspy/dnSpy.exe"))
WORKER_POOL_SIZE = int(os.getenv("DNSPY_WORKER_POOL_SIZE", config.get("daemon.worker_pool_size", 5)))
HEALTH_PUBLIC = os.getenv("DNSPY_HEALTH_PUBLIC", str(config.get("daemon.health_public", False))).lower() == "true"
ALLOWED_DIRS = [
    Path(d) for d in (
        os.getenv("DNSPY_ALLOWED_DIRS", "").split(":")
        + (config.get("daemon.allowed_binary_dirs") or [])
    ) if d
]

# API key — required; no hardcoded default accepted
API_KEY: Optional[str] = os.getenv("DNSPY_API_KEY") or config.get("daemon.api_key")

FEATURES = {
    "caching":       config.get("features.enable_caching", True),
    "rate_limiting": config.get("features.enable_rate_limiting", True),
    "metrics":       config.get("features.enable_metrics", True),
    "webhooks":      config.get("features.enable_webhooks", False),
}

TEMP_BASE = Path.home() / ".dnspy-worker"
TEMP_BASE.mkdir(parents=True, exist_ok=True)

workers: Dict[str, DnsyWorker] = {}
cache        = CacheManager()     if FEATURES["caching"]       else None
rate_limiter = RateLimiter()      if FEATURES["rate_limiting"]  else None
metrics      = MetricsCollector() if FEATURES["metrics"]        else None
webhook_mgr  = WebhookManager()   if FEATURES["webhooks"]       else None

stats = {
    "total_requests": 0,
    "successful_requests": 0,
    "failed_requests": 0,
    "start_time": datetime.utcnow(),
}


# ─── Startup validation ───────────────────────────────────────────────────────

def _validate_startup():
    if not API_KEY:
        print(
            "FATAL: No API key configured.\n"
            "  Set DNSPY_API_KEY environment variable or add 'api_key' to config.json.\n"
            "  Example: export DNSPY_API_KEY=$(python3 -c \"import secrets; print(secrets.token_hex(32))\")",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(API_KEY) < 16:
        print(
            "WARNING: API key is very short (<16 chars). Use a strong random key.",
            file=sys.stderr,
        )

    logger.logger.info(f"Binding to {DNSPY_HOST}:{DAEMON_PORT}")
    logger.logger.info(f"Health endpoint: {'public' if HEALTH_PUBLIC else 'auth-required'}")
    if ALLOWED_DIRS:
        logger.logger.info(f"Allowed binary dirs: {[str(d) for d in ALLOWED_DIRS]}")
    logger.logger.info(f"Features: {FEATURES}")


# ─── Path validation ──────────────────────────────────────────────────────────

def _validate_binary_path(binary_path: str) -> tuple[Optional[Path], Optional[str]]:
    """
    Validate a binary path: must exist and (if configured) be within an allowed dir.
    Returns (Path, None) on success or (None, error_message) on failure.
    """
    try:
        p = Path(binary_path).resolve()
    except Exception:
        return None, f"Invalid path: {binary_path}"

    if not p.exists():
        return None, f"Binary not found: {binary_path}"

    if not p.is_file():
        return None, f"Not a file: {binary_path}"

    # Extension check — only .dll and .exe
    if p.suffix.lower() not in {".dll", ".exe"}:
        return None, f"Unsupported file type: {p.suffix} (expected .dll or .exe)"

    # Allowed dirs check (path traversal protection)
    if ALLOWED_DIRS:
        if not any(str(p).startswith(str(d)) for d in ALLOWED_DIRS):
            return None, (
                f"Binary is outside allowed directories. "
                f"Configure DNSPY_ALLOWED_DIRS to permit this path."
            )

    return p, None


# ─── Middleware ───────────────────────────────────────────────────────────────

def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:8]


@web.middleware
async def auth_middleware(request: web.Request, handler):
    # Public health/metrics (when configured)
    if HEALTH_PUBLIC and request.path in ("/health", "/metrics") and request.method == "GET":
        return await handler(request)

    provided_key = request.headers.get("X-API-Key", "")
    if provided_key != API_KEY:
        stats["failed_requests"] += 1
        logger.logger.warning(
            f"Unauthorized: {request.method} {request.path} from {request.remote}"
        )
        return web.json_response({"error": "Unauthorized"}, status=401)

    return await handler(request)


@web.middleware
async def metrics_middleware(request: web.Request, handler):
    start = time.time()
    correlation_id = logger.request_start(
        endpoint=request.path,
        method=request.method,
        api_key_hash=_hash_api_key(request.headers.get("X-API-Key", "")),
    )
    try:
        response = await handler(request)
        duration_ms = (time.time() - start) * 1000
        logger.request_end(correlation_id, response.status, duration_ms)
        if FEATURES["metrics"]:
            metrics.record_request(request.path, duration_ms, response.status)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
    except Exception as e:
        duration_ms = (time.time() - start) * 1000
        logger.error(f"Unhandled exception: {e}", correlation_id=correlation_id)
        if FEATURES["metrics"]:
            metrics.record_request(request.path, duration_ms, 500)
        raise


# ─── Request models ───────────────────────────────────────────────────────────

class BinaryRequest(BaseModel):
    binary_path: str

class DecompileRequest(BaseModel):
    binary_path: str
    output_format: str = "json"
    extract_classes: list[str] | None = None
    analyze_obfuscation: bool = False
    webhook_url: str | None = None

class TypeRequest(BaseModel):
    binary_path: str
    type_name: str
    include_source: bool = False

class MethodRequest(BaseModel):
    binary_path: str
    type_name: str
    method_name: str
    include_il: bool = False

class BreakpointRequest(BaseModel):
    binary_path: str
    type_name: str
    method_name: str
    il_offset: int | None = None

class SearchRequest(BaseModel):
    binary_path: str
    pattern: str
    kind: str = "string"    # "string" | "member"
    use_regex: bool = False

class TokenRequest(BaseModel):
    binary_path: str
    token: str              # e.g. "0x06000001"

class BatchRequest(BaseModel):
    binaries: list[str]
    output_format: str = "json"
    analyze_obfuscation: bool = False
    webhook_url: str | None = None


# ─── Worker factory helper ────────────────────────────────────────────────────

def _make_worker(binary_path: Path) -> DnsyWorker:
    worker_id = str(uuid.uuid4())[:8]
    worker = DnsyWorker(
        worker_id=worker_id,
        dnspy_path=DNSPY_PATH,
        binary_path=str(binary_path),
        temp_dir=TEMP_BASE,
    )
    workers[worker_id] = worker
    logger.worker_spawn(worker_id, str(binary_path))
    return worker


async def _finish_worker(worker: DnsyWorker, start: float, operation: str):
    await worker.cleanup()
    workers.pop(worker.worker_id, None)
    duration_ms = (time.time() - start) * 1000
    logger.worker_complete(worker.worker_id, duration_ms, success=True)
    if FEATURES["metrics"]:
        metrics.record_worker(operation, duration_ms, success=True)


def _rate_check() -> bool:
    return not (FEATURES["rate_limiting"] and not rate_limiter.is_allowed(API_KEY))


def _cache_get(key: str, op: str, params: dict):
    if not FEATURES["caching"]:
        return None
    return cache.get(key, op, params)


def _cache_set(key: str, op: str, params: dict, value):
    if FEATURES["caching"]:
        cache.set(key, op, params, value)


# ─── Endpoint handlers ────────────────────────────────────────────────────────

async def handle_decompile(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = DecompileRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        cached = _cache_get(str(binary), "decompile", {"format": req.output_format})
        if cached:
            stats["successful_requests"] += 1
            return web.json_response({"status": "success", "cached": True, "result": cached})

        if not _rate_check():
            stats["failed_requests"] += 1
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.decompile(
            output_format=req.output_format,
            extract_classes=req.extract_classes or [],
            analyze_obfuscation=req.analyze_obfuscation,
        )
        await _finish_worker(worker, t0, "decompile")
        _cache_set(str(binary), "decompile", {"format": req.output_format}, result)

        if FEATURES["webhooks"] and req.webhook_url:
            asyncio.create_task(webhook_mgr.send_async(
                req.webhook_url, WebhookEventTypes.DECOMPILE_COMPLETE,
                {"worker_id": worker.worker_id, "status": "success"}
            ))

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "cached": False, "result": result})

    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        logger.error(f"/api/decompile: {e}")
        return web.json_response({"error": str(e)}, status=500)


async def handle_decompile_type(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = TypeRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.decompile_type(req.type_name)
        await _finish_worker(worker, t0, "decompile_type")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "type_name": req.type_name, "result": result})
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_decompile_method(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = MethodRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.decompile_method(req.type_name, req.method_name)
        await _finish_worker(worker, t0, "decompile_method")

        stats["successful_requests"] += 1
        return web.json_response({
            "status": "success",
            "type_name": req.type_name,
            "method_name": req.method_name,
            "result": result,
        })
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_dump_il(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.dump_il(
            type_name=data.get("type_name"),
            method_name=data.get("method_name"),
        )
        await _finish_worker(worker, t0, "dump_il")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "result": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_list_types(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        cached = _cache_get(str(binary), "list_types", {})
        if cached:
            stats["successful_requests"] += 1
            return web.json_response({"status": "success", "cached": True, "types": cached})

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.list_types()
        await _finish_worker(worker, t0, "list_types")
        _cache_set(str(binary), "list_types", {}, result)

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "cached": False, "types": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_list_methods(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.list_methods(type_name=data.get("type_name"))
        await _finish_worker(worker, t0, "list_methods")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "methods": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_inspect_type(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = TypeRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.inspect_type(req.type_name, req.include_source)
        await _finish_worker(worker, t0, "inspect_type")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "result": result})
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_inspect_method(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = MethodRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.inspect_method(req.type_name, req.method_name, req.include_il)
        await _finish_worker(worker, t0, "inspect_method")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "result": result})
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_search(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = SearchRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        if req.kind == "string":
            result = await worker.search_strings(req.pattern, req.use_regex)
        elif req.kind == "member":
            result = await worker.search_members(req.pattern)
        else:
            return web.json_response({"error": f"Unknown search kind: {req.kind}"}, status=400)
        await _finish_worker(worker, t0, f"search_{req.kind}")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "kind": req.kind, "results": result})
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_pe_info(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        cached = _cache_get(str(binary), "pe_info", {})
        if cached:
            stats["successful_requests"] += 1
            return web.json_response({"status": "success", "cached": True, "pe_info": cached})

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.get_pe_info()
        await _finish_worker(worker, t0, "pe_info")
        _cache_set(str(binary), "pe_info", {}, result)

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "cached": False, "pe_info": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_get_resources(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.get_resources()
        await _finish_worker(worker, t0, "get_resources")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "resources": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_analyze_obfuscation(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.analyze_obfuscation()
        await _finish_worker(worker, t0, "analyze_obfuscation")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "obfuscation_analysis": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_extract_class(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        class_name = data.get("class_name")
        if not class_name:
            return web.json_response({"error": "class_name required"}, status=400)

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.extract_class(class_name)
        await _finish_worker(worker, t0, "extract_class")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "class_source": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_list_pinvokes(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.list_pinvokes()
        await _finish_worker(worker, t0, "list_pinvokes")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "pinvokes": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_find_attributes(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        data = await request.json()
        binary, err = _validate_binary_path(data.get("binary_path", ""))
        if err:
            return web.json_response({"error": err}, status=400)

        attr_name = data.get("attribute_name")
        if not attr_name:
            return web.json_response({"error": "attribute_name required"}, status=400)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.find_attributes(attr_name)
        await _finish_worker(worker, t0, "find_attributes")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "attribute_name": attr_name, "matches": result})
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_resolve_token(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = TokenRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.resolve_token(req.token)
        await _finish_worker(worker, t0, "resolve_token")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "token": req.token, "result": result})
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_set_breakpoint(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = BreakpointRequest(**(await request.json()))
        binary, err = _validate_binary_path(req.binary_path)
        if err:
            return web.json_response({"error": err}, status=400)

        worker = _make_worker(binary)
        t0 = time.time()
        result = await worker.set_breakpoint(req.type_name, req.method_name, req.il_offset)
        await _finish_worker(worker, t0, "set_breakpoint")

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "breakpoint": result})
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_batch_dump(request: web.Request) -> web.Response:
    stats["total_requests"] += 1
    try:
        req = BatchRequest(**(await request.json()))

        if not _rate_check():
            return web.json_response({"error": "Rate limit exceeded"}, status=429)

        results = {}
        for bp_str in req.binaries:
            binary, err = _validate_binary_path(bp_str)
            if err:
                results[bp_str] = {"error": err}
                continue
            try:
                worker = _make_worker(binary)
                t0 = time.time()
                res = await worker.decompile(
                    output_format=req.output_format,
                    analyze_obfuscation=req.analyze_obfuscation,
                )
                await _finish_worker(worker, t0, "batch_decompile")
                results[bp_str] = {"status": "success", "result": res}
            except Exception as e:
                results[bp_str] = {"error": str(e)}

        if FEATURES["webhooks"] and req.webhook_url:
            asyncio.create_task(webhook_mgr.send_async(
                req.webhook_url, WebhookEventTypes.BATCH_COMPLETE,
                {"total": len(req.binaries),
                 "completed": sum(1 for r in results.values() if r.get("status") == "success")}
            ))

        stats["successful_requests"] += 1
        return web.json_response({"status": "success", "batch_results": results})
    except (ValidationError, json.JSONDecodeError) as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=400)
    except Exception as e:
        stats["failed_requests"] += 1
        return web.json_response({"error": str(e)}, status=500)


async def handle_health(request: web.Request) -> web.Response:
    uptime = (datetime.utcnow() - stats["start_time"]).total_seconds()
    total = stats["total_requests"]
    success_rate = (stats["successful_requests"] / total * 100) if total > 0 else 0.0

    if FEATURES["metrics"]:
        metrics.set_active_workers(len(workers), WORKER_POOL_SIZE)

    return web.json_response({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": round(uptime, 1),
        "active_workers": len(workers),
        "worker_pool_size": WORKER_POOL_SIZE,
        "stats": {
            "total_requests": total,
            "successful_requests": stats["successful_requests"],
            "failed_requests": stats["failed_requests"],
            "success_rate_percent": round(success_rate, 2),
        },
        "features": FEATURES,
        "config": {
            "host": DNSPY_HOST,
            "port": DAEMON_PORT,
            "health_public": HEALTH_PUBLIC,
            "allowed_dirs_configured": bool(ALLOWED_DIRS),
        },
    })


async def handle_metrics(request: web.Request) -> web.Response:
    if not FEATURES["metrics"]:
        return web.Response(text="# Metrics disabled\n", content_type="text/plain")
    return web.Response(text=metrics.to_prometheus(), content_type="text/plain")


async def handle_cleanup_all(request: web.Request) -> web.Response:
    count = len(workers)
    for worker in list(workers.values()):
        await worker.cleanup()
    workers.clear()
    logger.logger.info(f"Cleaned up {count} workers")
    return web.json_response({"status": "success", "cleaned_up": count})


# ─── App factory ──────────────────────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application(middlewares=[metrics_middleware, auth_middleware])

    # Original endpoints
    app.router.add_post("/api/decompile",            handle_decompile)
    app.router.add_post("/api/analyze-obfuscation",  handle_analyze_obfuscation)
    app.router.add_post("/api/extract-class",        handle_extract_class)
    app.router.add_post("/api/set-breakpoint",       handle_set_breakpoint)
    app.router.add_post("/api/batch-dump",           handle_batch_dump)

    # New endpoints
    app.router.add_post("/api/decompile-type",       handle_decompile_type)
    app.router.add_post("/api/decompile-method",     handle_decompile_method)
    app.router.add_post("/api/dump-il",              handle_dump_il)
    app.router.add_post("/api/list-types",           handle_list_types)
    app.router.add_post("/api/list-methods",         handle_list_methods)
    app.router.add_post("/api/inspect-type",         handle_inspect_type)
    app.router.add_post("/api/inspect-method",       handle_inspect_method)
    app.router.add_post("/api/search",               handle_search)
    app.router.add_post("/api/pe-info",              handle_pe_info)
    app.router.add_post("/api/get-resources",        handle_get_resources)
    app.router.add_post("/api/list-pinvokes",        handle_list_pinvokes)
    app.router.add_post("/api/find-attributes",      handle_find_attributes)
    app.router.add_post("/api/resolve-token",        handle_resolve_token)

    # Infrastructure
    app.router.add_get("/health",   handle_health)
    app.router.add_get("/metrics",  handle_metrics)
    app.router.add_post("/cleanup", handle_cleanup_all)

    return app


async def main():
    _validate_startup()
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, DNSPY_HOST, DAEMON_PORT)
    await site.start()

    logger.logger.info(f"dnspy-mcp daemon listening on {DNSPY_HOST}:{DAEMON_PORT}")

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.logger.info("Shutting down")
        for worker in list(workers.values()):
            await worker.cleanup()
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
