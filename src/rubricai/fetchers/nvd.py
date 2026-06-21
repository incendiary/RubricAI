"""NVD CVE API fetcher for CVSS data and reference list."""

import logging
import os
import re
from datetime import UTC, datetime, timedelta

import httpx  # noqa: F401 — required by tests for AsyncClient mocking

from ..cache import FileCache
from .retry import fetch_with_timeout_escalation

_logger = logging.getLogger(__name__)

_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NS = "nvd"
_TTL_HOURS = 24
_SEARCH_TTL_HOURS = 4  # BOM checks are "what's new" — shorter TTL


def _timeout() -> int:
    try:
        return int(os.getenv("RUBRICAI_HTTP_TIMEOUT", "30"))
    except (ValueError, TypeError):
        return 30


_cache = FileCache()


def _headers() -> dict:
    key = os.getenv("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _process_cve(cve: dict) -> dict:
    """Normalise a raw NVD CVE record to the standard search result shape."""
    cve_id = cve.get("id", "")
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
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
    return {
        "id": cve_id,
        "description": description[:300],
        "cvss_base": cvss_base,
        "cvss_version": cvss_version,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _normalize_keywords(name: str, vendor: str | None = None) -> list[str]:
    """Expand a BOM component name into NVD keyword search candidates.

    NVD uses vendor/product names from the CPE dictionary, which often differ from
    package-manager artifact IDs. This function generates plausible variations so that
    at least one is likely to match NVD's keyword index.

    Examples::

        "log4j-core"          → ["log4j-core", "log4j"]
        "libcurl"             → ["libcurl", "curl"]
        "spring-boot-starter" → ["spring-boot-starter", "spring-boot", "spring"]
        "python3-requests"    → ["python3-requests", "requests"]
        vendor="apache"       → ["apache httpd", "httpd"]  (for name="httpd")

    Returns candidates in descending specificity (most specific first).
    Caller tries each candidate and merges results by CVE ID.
    """
    candidates: list[str] = []

    # 1. Vendor + name (most specific when vendor is known)
    if vendor:
        candidates.append(f"{vendor} {name}")

    # 2. Name as-is
    candidates.append(name)

    # 3. Strip common packaging suffixes NVD doesn't use
    stripped = re.sub(
        r"[-_](core|lib|api|client|server|common|impl|runtime|base|all|full|util|utils)$",
        "",
        name,
        flags=re.IGNORECASE,
    )
    if stripped != name:
        candidates.append(stripped)

    # 4. Strip OS packaging prefixes (python3-requests → requests, libcurl → curl)
    unprefixed = re.sub(
        r"^(lib|python3?-|perl-|ruby-|php-|node(?:js)?-)",
        "",
        name,
        flags=re.IGNORECASE,
    )
    if unprefixed not in candidates:
        candidates.append(unprefixed)

    # 5. First hyphen/underscore segment ("log4j-core" → "log4j")
    parts = re.split(r"[-_]", name)
    if len(parts) > 1 and parts[0] not in candidates:
        candidates.append(parts[0])

    # Deduplicate preserving order, drop empty strings
    seen: set[str] = set()
    result: list[str] = []
    for c in candidates:
        c = c.strip()
        if c and c not in seen:
            seen.add(c)
            result.append(c)
    return result


async def _search_single(
    keyword: str,
    start_date: str,
    end_date: str,
    max_results: int,
) -> list[dict]:
    """Single-keyword NVD CVE search; returns raw normalised dicts."""
    results: list[dict] = []
    start_index = 0
    page_size = 100

    while True:
        resp = await fetch_with_timeout_escalation(
            "GET",
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
            results.append(_process_cve(vuln.get("cve", {})))

        total = data.get("totalResults", 0)
        start_index += page_size
        if start_index >= total or len(results) >= max_results:
            break

    return results


async def fetch(cve_id: str) -> dict | None:
    """Return raw NVD CVE record for *cve_id*, or ``None`` if not found."""
    cached = _cache.get(_NS, cve_id.upper())
    if cached is not None:
        return cached

    resp = await fetch_with_timeout_escalation(
        "GET",
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
    keyword: str,
    days_back: int = 7,
    max_results: int = 200,
    vendor: str | None = None,
) -> list[dict]:
    """Search NVD for CVEs matching *keyword* modified in the last *days_back* days.

    Expands *keyword* into multiple NVD search candidates via ``_normalize_keywords``
    (strips packaging suffixes, tries split-on-hyphen variants, etc.) and merges
    results by CVE ID. This handles cases where developer-facing names like
    ``"log4j-core"`` don't match NVD's ``"log4j"`` exactly.

    Uses ``keywordSearch`` + ``lastModStartDate`` + ``lastModEndDate``. Both date
    params are required by the NVD v2 API — omitting ``lastModEndDate`` returns 404.
    Results are cached for ``_SEARCH_TTL_HOURS`` hours (keyed on original keyword,
    normalised vendor, lookback window, and result cap).

    Args:
        keyword: Component name (name-only, no version string).
        days_back: Lookback window in days.
        max_results: Cap on total CVEs returned (prevents runaway pagination for
            broad keywords like ``"ubuntu"`` with large lookback windows).
        vendor: Optional vendor hint passed to ``_normalize_keywords`` to prepend a
            ``"vendor name"`` candidate (e.g. ``"apache httpd"``).

    Returns a list of dicts, each with keys:
        id, description, cvss_base, cvss_version, published, last_modified, url
    """
    cache_key = f"{keyword.lower()}:{(vendor or '').lower()}:{days_back}:{max_results}"
    cached = _cache.get(f"{_NS}_search", cache_key)
    if cached is not None:
        return cached

    now = datetime.now(tz=UTC)
    _fmt = "%Y-%m-%dT%H:%M:%S.000"
    start_date = (now - timedelta(days=days_back)).strftime(_fmt)
    end_date = now.strftime(_fmt)

    keywords = _normalize_keywords(keyword, vendor)
    _logger.debug(
        "NVD search: keyword=%r candidates=%r days_back=%d max_results=%d",
        keyword,
        keywords,
        days_back,
        max_results,
    )

    seen_ids: set[str] = set()
    results: list[dict] = []

    for kw in keywords:
        if len(results) >= max_results:
            break
        for cve in await _search_single(kw, start_date, end_date, max_results):
            if cve["id"] and cve["id"] not in seen_ids:
                seen_ids.add(cve["id"])
                results.append(cve)
        if len(results) >= max_results:
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


def extract_automatable(nvd_record: dict) -> bool | None:
    """Determine whether exploitation can be fully automated from an NVD record.

    Resolution order:
    1. CISA Vulnrichment fields at the CVE top-level (added by CISA advisory program).
    2. CVSS vector heuristic: AV:N + AC:L + PR:N + UI:N → automatable.
    3. None if neither source is available.
    """
    # 1. Vulnrichment advisory data — CISA adds these top-level fields to CVE records
    for field in ("automatable", "Automatable", "cisa_automatable"):
        val = nvd_record.get(field)
        if val is not None:
            return str(val).lower() in ("yes", "true", "1")

    # 2. CVSS vector derivation: fully automated = no user interaction, network-
    #    accessible, low complexity, no privileges required
    metrics = nvd_record.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            vector = entries[0].get("cvssData", {}).get("vectorString", "")
            if vector:
                return (
                    "AV:N" in vector
                    and "AC:L" in vector
                    and "PR:N" in vector
                    and "UI:N" in vector
                )

    return None


def extract_technical_impact(nvd_record: dict) -> str | None:
    """Derive BOD 26-04 technical impact (``"total"`` or ``"partial"``) from CVSS.

    ``"total"`` = Scope Changed, OR both Confidentiality:High and Integrity:High.
    ``"partial"`` = all other cases where CVSS data is present.
    """
    metrics = nvd_record.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            vector = entries[0].get("cvssData", {}).get("vectorString", "")
            if not vector:
                return "partial"
            scope_changed = "S:C" in vector
            conf_high = "C:H" in vector
            integ_high = "I:H" in vector
            if scope_changed or (conf_high and integ_high):
                return "total"
            return "partial"
    return None
