#!/usr/bin/env python3
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional


class CacheManager:
    def __init__(self, cache_dir: Path = None, ttl_seconds: int = 3600):
        self.cache_dir = cache_dir or Path.home() / ".dnspy-cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_seconds
        self.memory_cache = {}
    
    def _get_binary_hash(self, binary_path: str) -> str:
        hasher = hashlib.sha256()
        hasher.update(binary_path.encode())
        return hasher.hexdigest()
    
    def _get_cache_key(self, binary_hash: str, operation: str, params: dict) -> str:
        key_data = f"{binary_hash}:{operation}:{json.dumps(params, sort_keys=True)}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get(self, binary_path: str, operation: str, params: dict = None) -> Optional[dict]:
        binary_hash = self._get_binary_hash(binary_path)
        if not binary_hash:
            return None
        
        params = params or {}
        cache_key = self._get_cache_key(binary_hash, operation, params)
        
        if cache_key in self.memory_cache:
            entry = self.memory_cache[cache_key]
            if time.time() - entry["timestamp"] < self.ttl:
                return entry["data"]
            else:
                del self.memory_cache[cache_key]
        
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    entry = json.load(f)
                
                if time.time() - entry["timestamp"] < self.ttl:
                    self.memory_cache[cache_key] = entry
                    return entry["data"]
                else:
                    cache_file.unlink()
            except Exception:
                cache_file.unlink()
        
        return None
    
    def set(self, binary_path: str, operation: str, params: dict, data: dict):
        binary_hash = self._get_binary_hash(binary_path)
        if not binary_hash:
            return
        
        params = params or {}
        cache_key = self._get_cache_key(binary_hash, operation, params)
        
        entry = {
            "timestamp": time.time(),
            "binary_hash": binary_hash,
            "operation": operation,
            "params": params,
            "data": data
        }
        
        self.memory_cache[cache_key] = entry
        
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(entry, f)
        except Exception:
            pass
    
    def clear(self):
        self.memory_cache.clear()
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
            except Exception:
                pass
    
    def get_stats(self) -> dict:
        return {
            "memory_entries": len(self.memory_cache),
            "cache_dir": str(self.cache_dir),
            "ttl_seconds": self.ttl
        }
