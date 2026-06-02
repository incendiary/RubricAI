"""FIRST EPSS score fetcher."""

import httpx

from ..cache import FileCache

_API_URL = "https://api.first.org/data/v1/epss"
_NS = "epss"
_TTL_HOURS = 24

_cache = FileCache()


async def fetch(cve_id: str) -> dict | None:
    """Return EPSS data for *cve_id*, or ``None`` if not found."""
    cached = _cache.get(_NS, cve_id.upper())
    if cached is not None:
        return cached

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(_API_URL, params={"cve": cve_id})
        resp.raise_for_status()
        data = resp.json()

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
