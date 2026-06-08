"""NVD CVE API fetcher for CVSS data and reference list."""

import logging
import os
from datetime import UTC, datetime, timedelta

import httpx

from ..cache import FileCache

_logger = logging.getLogger(__name__)

_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NS = "nvd"
_TTL_HOURS = 24
_SEARCH_TTL_HOURS = 4  # BOM checks are "what's new" — shorter TTL
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


async def search(
    keyword: str, days_back: int = 7, max_results: int = 200
) -> list[dict]:
    """Search NVD for CVEs matching *keyword* modified in the last *days_back* days.

    Uses the NVD ``keywordSearch`` + ``lastModStartDate`` + ``lastModEndDate``
    parameters. Both date params are required by the NVD v2 API — omitting
    ``lastModEndDate`` returns a 404 regardless of keyword or range.
    Results are cached for ``_SEARCH_TTL_HOURS`` hours.

    Args:
        keyword: Product name to search for (name-only, no version string).
        days_back: Lookback window in days.
        max_results: Cap on total CVEs returned (prevents runaway pagination
            for broad keywords like "ubuntu" with large lookback windows).

    Returns a list of dicts, each with keys:
        id, description, cvss_base, cvss_version, published, last_modified
    """
    cache_key = f"{keyword.lower()}:{days_back}:{max_results}"
    cached = _cache.get(f"{_NS}_search", cache_key)
    if cached is not None:
        return cached

    now = datetime.now(tz=UTC)
    _fmt = "%Y-%m-%dT%H:%M:%S.000"
    start_date = (now - timedelta(days=days_back)).strftime(_fmt)
    end_date = now.strftime(_fmt)

    _logger.debug(
        "NVD search: keyword=%r days_back=%d start=%s end=%s max_results=%d",
        keyword,
        days_back,
        start_date,
        end_date,
        max_results,
    )

    results: list[dict] = []
    start_index = 0
    page_size = 100

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        while True:
            resp = await client.get(
                _API_URL,
                params={
                    "keywordSearch": keyword,
                    "lastModStartDate": start_date,
                    "lastModEndDate": end_date,
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                },
                headers=_headers(),
            )
            _logger.debug(
                "NVD search response: keyword=%r startIndex=%d status=%d",
                keyword,
                start_index,
                resp.status_code,
            )
            if resp.status_code == 404:
                _logger.debug("NVD search 404 for keyword=%r — no results", keyword)
                break  # NVD returns 404 for zero-result keyword queries — no results
            resp.raise_for_status()
            data = resp.json()

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                description = next(
                    (
                        d["value"]
                        for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"
                    ),
                    "",
                )
                # Extract best available CVSS score
                cvss_base = None
                cvss_version = None
                metrics = cve.get("metrics", {})
                for key, ver in [
                    ("cvssMetricV31", "3.1"),
                    ("cvssMetricV30", "3.0"),
                    ("cvssMetricV2", "2.0"),
                ]:
                    entries = metrics.get(key, [])
                    if entries:
                        cvss_base = entries[0].get("cvssData", {}).get("baseScore")
                        cvss_version = ver
                        break

                results.append(
                    {
                        "id": cve_id,
                        "description": description[:300],  # truncate for storage
                        "cvss_base": cvss_base,
                        "cvss_version": cvss_version,
                        "published": cve.get("published", ""),
                        "last_modified": cve.get("lastModified", ""),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                )

            total = data.get("totalResults", 0)
            start_index += page_size
            if start_index >= total or len(results) >= max_results:
                break

    results = results[:max_results]
    _logger.info(
        "NVD search complete: keyword=%r results=%d days_back=%d",
        keyword,
        len(results),
        days_back,
    )
    _cache.set(f"{_NS}_search", cache_key, results, ttl_hours=_SEARCH_TTL_HOURS)
    return results


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
