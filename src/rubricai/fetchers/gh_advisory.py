"""GitHub Advisory Database fetcher — ecosystem-native vulnerability intelligence.

GitHub Advisory Database is faster and more responsive than NVD for most package
ecosystems (npm, PyPI, Maven, Go, RubyGems, NuGet). It uses package-manager-native
names and supports version-specific queries.

Query flow:
  1. GET /advisories with filters: cve_id, ecosystem, package_name, affected_versions
  2. Normalise responses to match NVD output shape
  3. Prepend to intel results when available

Rate limit: 60 req/hr unauthenticated, 5000 req/hr with GITHUB_TOKEN env var.
Fallback: OSV / NVD when GitHub Advisory returns 404 or rate limit exceeded.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

import httpx

from ..cache import FileCache
from .retry import fetch_with_timeout_escalation

_logger = logging.getLogger(__name__)

_API_URL = "https://api.github.com/advisories"
_NS = "gh_advisory"
_TTL_HOURS = 24
_SEARCH_TTL_HOURS = 4
_HTTP_TIMEOUT = int(os.getenv("RUBRICAI_HTTP_TIMEOUT", "30"))

_cache = FileCache()


def _headers() -> dict:
    """Build GitHub API headers with optional auth token."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def fetch(cve_id: str) -> dict | None:
    """Fetch a single CVE from GitHub Advisory Database by CVE ID.

    Returns a normalised dict matching NVD shape:
    {id, description, cvss_base, cvss_version, published, last_modified, url, source}

    Returns None if not found or on HTTP errors.
    """
    cached = _cache.get(_NS, cve_id.upper())
    if cached is not None:
        return cached

    try:
        resp = await fetch_with_timeout_escalation(
            "GET",
            _API_URL,
            params={"cve_id": cve_id.upper()},
            headers=_headers(),
        )

        if resp.status_code == 404:
            return None
        if resp.status_code == 403:
            _logger.warning(
                "GitHub Advisory rate limit exceeded (403); "
                "use GITHUB_TOKEN for higher rate limit"
            )
            return None
        if resp.status_code >= 400:
            _logger.warning(
                "GitHub Advisory fetch failed for %s: HTTP %d", cve_id, resp.status_code
            )
            return None

        data = resp.json()

        # GitHub returns a paginated list; we want the first (and usually only) match
        advisories = data.get("advisories", [])
        if not advisories:
            return None

        result = _normalize_advisory(advisories[0])
        _cache.set(_NS, cve_id.upper(), result, ttl_hours=_TTL_HOURS)
        return result

    except httpx.HTTPError as exc:
        _logger.warning("GitHub Advisory fetch failed for %s: %s", cve_id, exc)
        return None


async def search(
    keyword: str,
    ecosystem: str | None = None,
    days_back: int = 7,
    max_results: int = 200,
) -> list[dict]:
    """Search GitHub Advisory Database by package name and optional ecosystem.

    GitHub Advisory uses package-manager-native names (Maven artifact IDs, PyPI
    package names, npm module names, etc.) and can filter by ecosystem.

    Args:
        keyword: Package name (e.g. "log4j-core", "requests", "express")
        ecosystem: Package ecosystem ("maven", "pip", "npm", "nuget", "rubygems", "go")
            If None, searches across all ecosystems.
        days_back: Lookback window in days (filters by modified_at).
        max_results: Cap on total advisories returned.

    Returns:
        List of normalised dicts matching NVD shape, tagged with source: "github"
    """
    cache_key = (
        f"{keyword.lower()}:{(ecosystem or '').lower()}:{days_back}:{max_results}"
    )
    cached = _cache.get(f"{_NS}_search", cache_key)
    if cached is not None:
        return cached

    try:
        params: dict = {"package_name": keyword}
        if ecosystem:
            params["ecosystem"] = ecosystem.lower()

        resp = await fetch_with_timeout_escalation(
            "GET",
            _API_URL,
            params=params,
            headers=_headers(),
        )

        if resp.status_code == 403:
            _logger.warning(
                "GitHub Advisory rate limit exceeded (403); "
                "use GITHUB_TOKEN for higher rate limit"
            )
            return []
        if resp.status_code >= 400:
            _logger.warning(
                "GitHub Advisory search failed for %s/%s: HTTP %d",
                ecosystem or "any",
                keyword,
                resp.status_code,
            )
            return []

        data = resp.json()
        advisories = data.get("advisories", [])

        # Filter by days_back on modified_at
        cutoff = (datetime.now(tz=UTC) - timedelta(days=days_back)).isoformat()

        results: list[dict] = []
        for advisory in advisories:
            if len(results) >= max_results:
                break

            modified = advisory.get("updated_at", "")
            if modified < cutoff:
                continue

            result = _normalize_advisory(advisory)
            results.append(result)

        _logger.info(
            "GitHub Advisory search complete: package=%r ecosystem=%s results=%d",
            keyword,
            ecosystem or "any",
            len(results),
        )
        _cache.set(f"{_NS}_search", cache_key, results, ttl_hours=_SEARCH_TTL_HOURS)
        return results

    except httpx.HTTPError as exc:
        _logger.warning("GitHub Advisory search failed for %s: %s", keyword, exc)
        return []


def _normalize_advisory(advisory: dict) -> dict:
    """Normalise a GitHub Advisory record to match NVD output shape."""
    # GitHub uses CVE IDs directly or generates GHSA IDs; prefer CVE if available
    cve_id = advisory.get("cve_id") or advisory.get("ghsa_id") or "UNKNOWN"

    # GitHub severity (CRITICAL, HIGH, MODERATE, LOW) → extract CVSS if available
    severity_text = advisory.get("severity", "").upper()
    cvss_base = None
    cvss_version = None

    # Some advisories include CVSS scores; fallback to severity guess
    if "cvss_score" in advisory:
        cvss_base = advisory.get("cvss_score")
        cvss_version = advisory.get("cvss_version", "3.1")

    # Description from summary or details
    description = (advisory.get("summary") or advisory.get("description") or "")[:300]

    # Timestamps
    published = advisory.get("published_at", "")
    last_modified = advisory.get("updated_at", "")

    # Package ecosystem (for context)
    ecosystem = advisory.get("package", {}).get("ecosystem", "")
    pkg_name = advisory.get("package", {}).get("name", "")

    return {
        "id": cve_id,
        "description": description,
        "cvss_base": cvss_base,
        "cvss_version": cvss_version,
        "published": published,
        "last_modified": last_modified,
        "url": f"https://github.com/advisories/{advisory.get('ghsa_id', cve_id)}",
        "source": "github",
        "ecosystem": ecosystem,
        "package": pkg_name,
        "severity": severity_text,
    }
