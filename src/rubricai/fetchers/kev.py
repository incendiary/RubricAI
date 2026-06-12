"""CISA Known Exploited Vulnerabilities catalog fetcher.

Downloads the full catalog once per TTL window and indexes it by CVE ID.
"""

import logging
import os

import httpx

from ..cache import FileCache

_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NS = "kev"
_CATALOG_KEY = "catalog"
_TTL_HOURS = 24
_logger = logging.getLogger(__name__)


def _timeout() -> int:
    try:
        return int(os.getenv("RUBRICAI_HTTP_TIMEOUT", "30"))
    except (ValueError, TypeError):
        return 30


_cache = FileCache()


async def fetch(cve_id: str) -> dict:
    """Return KEV entry for *cve_id*, or ``{"listed": False}`` if not present."""
    index = _cache.get(_NS, _CATALOG_KEY)
    if index is None:
        index = await _download_and_index()
        if index is None:
            return {"listed": False}
        _cache.set(_NS, _CATALOG_KEY, index, ttl_hours=_TTL_HOURS)

    entry = index.get(cve_id.upper())
    if entry is None:
        return {"listed": False}
    return {
        "listed": True,
        "due_date": entry.get("dueDate"),
        "notes": entry.get("shortDescription"),
    }


async def _download_and_index() -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            resp = await client.get(_CATALOG_URL)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        _logger.warning("KEV download failed: HTTP %d", exc.response.status_code)
        return None
    except httpx.HTTPError as exc:
        _logger.warning("KEV download error: %s", type(exc).__name__)
        return None

    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
