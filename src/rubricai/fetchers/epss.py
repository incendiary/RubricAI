"""FIRST EPSS score fetcher."""

import logging
import os

import httpx

from ..cache import FileCache

_API_URL = "https://api.first.org/data/v1/epss"
_NS = "epss"
_TTL_HOURS = 24
_logger = logging.getLogger(__name__)


def _timeout() -> int:
    try:
        return int(os.getenv("RUBRICAI_HTTP_TIMEOUT", "30"))
    except (ValueError, TypeError):
        return 30


_cache = FileCache()


async def fetch(cve_id: str) -> dict | None:
    """Return EPSS data for *cve_id*, or ``None`` if not found."""
    cached = _cache.get(_NS, cve_id.upper())
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            resp = await client.get(_API_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        _logger.warning("EPSS fetch failed for %s: HTTP %d", cve_id, exc.response.status_code)
        return None
    except httpx.HTTPError as exc:
        _logger.warning("EPSS fetch error for %s: %s", cve_id, type(exc).__name__)
        return None

    items = data.get("data", [])
    if not items:
        return None

    item = items[0]
    result = {
        "score": float(item.get("epss", 0)),
        "percentile": float(item.get("percentile", 0)),
        "date": item.get("date"),
    }
    _cache.set(_NS, cve_id.upper(), result, ttl_hours=_TTL_HOURS)
    return result
