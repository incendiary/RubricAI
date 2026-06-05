"""NVD CVE API fetcher for CVSS data and reference list."""

import os

import httpx

from ..cache import FileCache

_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NS = "nvd"
_TTL_HOURS = 24
_HTTP_TIMEOUT = int(os.getenv("RUBRICAI_HTTP_TIMEOUT", "30"))

_cache = FileCache()


def _headers() -> dict:
    key = os.getenv("NVD_API_KEY")
    return {"apiKey": key} if key else {}


async def fetch(cve_id: str) -> dict | None:
    """Return raw NVD CVE record for *cve_id*, or ``None`` if not found."""
    cached = _cache.get(_NS, cve_id.upper())
    if cached is not None:
        return cached

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        resp = await client.get(
            _API_URL,
            params={"cveId": cve_id},
            headers=_headers(),
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    result = vulns[0].get("cve", {})
    _cache.set(_NS, cve_id.upper(), result, ttl_hours=_TTL_HOURS)
    return result


async def fetch_cvss(cve_id: str) -> dict | None:
    """Extract CVSS info from an NVD record."""
    record = await fetch(cve_id)
    if not record:
        return None

    metrics = record.get("metrics", {})
    # Prefer CVSSv3.1 → 3.0 → 2.0 in that order
    for key, version in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]:
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "base": data.get("baseScore"),
                "vector": data.get("vectorString"),
                "version": version,
            }
    return None
