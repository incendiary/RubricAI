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
import re
import time

import httpx

from ..cache import FileCache
from .retry import fetch_with_timeout_escalation

_logger = logging.getLogger(__name__)

_API_URL = "https://api.github.com/advisories"
_NS = "gh_advisory"
_TTL_HOURS = 24
_NEGATIVE_TTL_HOURS = 1
_NO_ADVISORY = "none"  # cached marker for a confirmed "no advisory" answer

_cache = FileCache()
_blocked_until = 0.0  # epoch seconds; fetch is skipped until this time passes


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
    global _blocked_until
    key = cve_id.upper()
    cached = _cache.get(_NS, key)
    if cached is not None:
        return None if cached == _NO_ADVISORY else cached
    if time.time() < _blocked_until:
        return None

    try:
        resp = await fetch_with_timeout_escalation(
            "GET",
            _API_URL,
            params={"cve_id": key},
            headers=_headers(),
        )

        if resp.status_code == 404:
            _cache.set(_NS, key, _NO_ADVISORY, ttl_hours=_NEGATIVE_TTL_HOURS)
            return None
        if resp.status_code == 403:
            reset = resp.headers.get("x-ratelimit-reset")
            if resp.headers.get("x-ratelimit-remaining") == "0" and reset:
                _blocked_until = float(reset)
                _logger.warning(
                    "GitHub Advisory rate limit exhausted; skipping until epoch %s "
                    "(set GITHUB_TOKEN for a higher limit)",
                    reset,
                )
            else:
                _logger.warning("GitHub Advisory fetch forbidden (403) for %s", cve_id)
            return None
        if resp.status_code >= 400:
            _logger.warning(
                "GitHub Advisory fetch failed for %s: HTTP %d", cve_id, resp.status_code
            )
            return None

        advisories = resp.json()
        if not advisories:
            _cache.set(_NS, key, _NO_ADVISORY, ttl_hours=_NEGATIVE_TTL_HOURS)
            return None

        result = _normalize_advisory(advisories[0])
        _cache.set(_NS, key, result, ttl_hours=_TTL_HOURS)
        return result

    except httpx.HTTPError as exc:
        _logger.warning("GitHub Advisory fetch failed for %s: %s", cve_id, exc)
        return None


def _normalize_advisory(advisory: dict) -> dict:
    """Reduce a GitHub Advisory record to the keys intel_lookup reads."""
    # GitHub uses CVE IDs directly or generates GHSA IDs; prefer CVE if available
    cve_id = advisory.get("cve_id") or advisory.get("ghsa_id") or "UNKNOWN"

    # GitHub returns cvss: {score, vector_string}; score 0 with no vector = unscored
    cvss = advisory.get("cvss") or {}
    cvss_base = cvss.get("score") or None
    cvss_vector = cvss.get("vector_string")
    cvss_version = None
    if cvss_vector:
        match = re.match(r"CVSS:(\d\.\d)/", cvss_vector)
        cvss_version = match.group(1) if match else "unknown"

    description = (advisory.get("summary") or advisory.get("description") or "")[:300]

    return {
        "id": cve_id,
        "description": description,
        "cvss_base": cvss_base,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
    }
