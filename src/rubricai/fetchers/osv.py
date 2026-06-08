"""OSV (osv.dev) vulnerability fetcher — ecosystem-native package name resolution.

OSV speaks package-manager language: Maven artifact IDs, PyPI package names, npm
module names, etc. It acts as a translation layer between what developers call their
dependencies and what NVD calls the CVEs.

Query flow:
  1. POST /v1/query with {package: {name, ecosystem}, version}
  2. Filter vulns to those with at least one CVE alias
  3. Return normalised dicts matching nvd.search() output shape

Returned CVE IDs can be passed directly to intel_lookup for full NVD enrichment
(CVSS, KEV, EPSS). cvss_base is not populated here — no cvss parsing lib is added.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

import httpx

from ..cache import FileCache

_logger = logging.getLogger(__name__)

_API_URL = "https://api.osv.dev/v1/query"
_NS = "osv_search"
_SEARCH_TTL_HOURS = 4
_HTTP_TIMEOUT = int(os.getenv("RUBRICAI_HTTP_TIMEOUT", "30"))

_cache = FileCache()

# Canonical OSV ecosystem names and common developer shorthand aliases.
# Keys are lower-cased before lookup.
ECOSYSTEM_ALIASES: dict[str, str] = {
    # Java / JVM
    "maven": "Maven",
    "java": "Maven",
    "jar": "Maven",
    # Python
    "pypi": "PyPI",
    "python": "PyPI",
    "pip": "PyPI",
    # JavaScript / Node
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "js": "npm",
    # .NET
    "nuget": "NuGet",
    "dotnet": "NuGet",
    "csharp": "NuGet",
    "net": "NuGet",
    # Ruby
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "gem": "RubyGems",
    # Go
    "go": "Go",
    "golang": "Go",
    # Rust
    "cargo": "crates.io",
    "rust": "crates.io",
    # OS / Linux distros
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
    "rocky": "Rocky Linux",
    "rockylinux": "Rocky Linux",
    "rhel": "Red Hat",
    "redhat": "Red Hat",
    "suse": "openSUSE",
    "opensuse": "openSUSE",
}


def _resolve_ecosystem(raw: str) -> str:
    """Normalise a developer shorthand or canonical ecosystem name for OSV."""
    return ECOSYSTEM_ALIASES.get(raw.lower(), raw)


async def search(
    name: str,
    ecosystem: str,
    version: str | None = None,
    days_back: int | None = None,
) -> list[dict]:
    """Query OSV for vulnerabilities affecting *name* in *ecosystem*.

    OSV uses package-manager-native names (Maven artifact IDs, PyPI package names,
    npm module names, etc.) so no NVD naming knowledge is required from the caller.

    Args:
        name: Package name as it appears in the package manager (e.g. ``"log4j-core"``).
        ecosystem: Package ecosystem. Shorthand accepted: ``"maven"``, ``"pypi"``,
            ``"npm"``, ``"go"``, ``"nuget"``, ``"ruby"``, ``"rust"``, ``"debian"``,
            ``"ubuntu"``, ``"alpine"``, etc. Full list in ``ECOSYSTEM_ALIASES``.
        version: Installed version string. When provided, OSV filters to vulns that
            affect this specific version.
        days_back: If set, filter to vulns modified within this many days. ``None``
            returns all known vulns (useful for first-time BOM checks).

    Returns:
        List of dicts matching ``nvd.search()`` output shape:
        ``{id, description, cvss_base, cvss_version, published, last_modified, url}``.
        ``cvss_base`` / ``cvss_version`` are always ``None`` — OSV severity uses CVSS
        vector strings, not base scores. Use ``intel_lookup`` for full scoring.
        Only entries with at least one ``CVE-*`` alias are returned.
    """
    canonical = _resolve_ecosystem(ecosystem)
    cache_key = f"{name.lower()}:{canonical.lower()}:{version or ''}:{days_back or 0}"
    cached = _cache.get(_NS, cache_key)
    if cached is not None:
        return cached

    payload: dict = {"package": {"name": name, "ecosystem": canonical}}
    if version:
        payload["version"] = version

    _logger.debug(
        "OSV search: name=%r ecosystem=%r version=%r days_back=%s",
        name,
        canonical,
        version,
        days_back,
    )

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(_API_URL, json=payload)
            if resp.status_code >= 400:
                _logger.warning(
                    "OSV search HTTP %d for name=%r ecosystem=%r",
                    resp.status_code,
                    name,
                    canonical,
                )
                return []
            data = resp.json()
    except httpx.HTTPError as exc:
        _logger.warning("OSV search request failed for name=%r: %s", name, exc)
        return []

    cutoff: datetime | None = None
    if days_back is not None:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days_back)

    results: list[dict] = []
    for vuln in data.get("vulns", []):
        # Only include entries that carry a CVE alias so we can enrich from NVD.
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.upper().startswith("CVE-")), None)
        if not cve_id:
            continue

        # Apply days_back filter on OSV's modified timestamp.
        if cutoff is not None:
            modified_raw = vuln.get("modified", "")
            if modified_raw:
                try:
                    modified_dt = datetime.fromisoformat(
                        modified_raw.replace("Z", "+00:00")
                    )
                    if modified_dt < cutoff:
                        continue
                except ValueError:
                    pass  # unparseable timestamp — include the vuln

        # Extract description from OSV details (truncated to match NVD shape).
        description = (vuln.get("summary") or vuln.get("details") or "")[:300]

        # Extract published / modified timestamps.
        published = vuln.get("published", "")
        last_modified = vuln.get("modified", "")

        results.append(
            {
                "id": cve_id.upper(),
                "description": description,
                "cvss_base": None,  # OSV severity is a vector string — not parsed here
                "cvss_version": None,
                "published": published,
                "last_modified": last_modified,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}",
                "source": "osv",
            }
        )

    _logger.info(
        "OSV search complete: name=%r ecosystem=%r results=%d",
        name,
        canonical,
        len(results),
    )
    _cache.set(_NS, cache_key, results, ttl_hours=_SEARCH_TTL_HOURS)
    return results
