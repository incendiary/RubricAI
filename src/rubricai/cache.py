"""Simple file-backed JSON cache with per-entry TTL."""

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "rubricai"


class FileCache:
    def __init__(self, cache_dir: str | Path = _DEFAULT_CACHE_DIR):
        self._dir = Path(cache_dir)

    @staticmethod
    def _sanitize_namespace(namespace: str) -> str:
        """Strip path separators and traversal sequences from namespace."""
        # Remove any path separator or traversal attempt
        sanitized = namespace.replace("/", "_").replace("\\", "_").replace("..", "")
        sanitized = sanitized.replace("\x00", "")  # null bytes
        if not sanitized:
            raise ValueError("Cache namespace cannot be empty after sanitization")
        return sanitized

    def _path(self, namespace: str) -> Path:
        safe_ns = self._sanitize_namespace(namespace)
        return self._dir / f"{safe_ns}.json"

    def _load(self, namespace: str) -> dict:
        p = self._path(namespace)
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, namespace: str, data: dict) -> None:
        # Write-then-rename so a crash never leaves a truncated cache file.
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._path(namespace)
        fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(data, default=str))
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def get(self, namespace: str, key: str) -> Any | None:
        store = self._load(namespace)
        entry = store.get(key)
        if entry is None:
            return None
        if time.time() > entry["expires_at"]:
            return None
        return entry["value"]

    def set(self, namespace: str, key: str, value: Any, ttl_hours: float = 24) -> None:
        store = self._load(namespace)
        # Lazy eviction: prune expired entries on every write
        # to prevent unbounded growth
        now = time.time()
        store = {k: v for k, v in store.items() if v.get("expires_at", 0) > now}
        store[key] = {
            "value": value,
            "expires_at": now + ttl_hours * 3600,
        }
        self._save(namespace, store)
