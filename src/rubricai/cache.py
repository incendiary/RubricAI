"""Simple file-backed JSON cache with per-entry TTL."""

import json
import time
from pathlib import Path
from typing import Any


class FileCache:
    def __init__(self, cache_dir: str | Path = ".cache"):
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str) -> Path:
        return self._dir / f"{namespace}.json"

    def _load(self, namespace: str) -> dict:
        p = self._path(namespace)
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, namespace: str, data: dict) -> None:
        self._path(namespace).write_text(json.dumps(data, default=str))

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
        store[key] = {
            "value": value,
            "expires_at": time.time() + ttl_hours * 3600,
        }
        self._save(namespace, store)
