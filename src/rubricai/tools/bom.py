"""bom_update / bom_check MCP tools — Bill of Materials CVE monitoring."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from ..fetchers import nvd as nvd_fetcher
from ..fetchers import osv as osv_fetcher
from ..fetchers.osv import ECOSYSTEM_ALIASES
from ..schemas.environment import BomEntry, EnvironmentState
from .environment import _env_dir, _write_next_version

_logger = logging.getLogger(__name__)


def _resolve_ecosystem(ecosystem: str | None, type_: str | None) -> str | None:
    """Return a canonical OSV ecosystem string from BomEntry hints.

    Checks ``ecosystem`` first, then falls back to ``type``. Both fields accept the
    same developer shorthand (``"maven"``, ``"pypi"``, ``"npm"``, etc.).
    Returns ``None`` if neither maps to a known OSV ecosystem — caller uses NVD.
    """
    hint = (ecosystem or type_ or "").lower()
    return ECOSYSTEM_ALIASES.get(hint)


def _load_state(environment_name: str) -> EnvironmentState:
    env_dir = _env_dir(environment_name)
    latest = env_dir / "state_latest.json"
    if latest.exists():
        data = json.loads(latest.read_text(encoding="utf-8"))
        return EnvironmentState.model_validate(data)
    return EnvironmentState()


def bom_update(
    components: list[dict[str, Any]], environment_name: str
) -> dict[str, Any]:
    """Store or replace the Bill of Materials for a named environment.

    Args:
        components: List of component dicts. Each requires ``name`` and
                    ``version``; optional: ``type``, ``vendor``, ``notes``.
        environment_name: Target environment (must exist or be created via env_read).

    Returns:
        Dict with ``stored`` (count), ``saved_to``, ``bom``, and ``environment_name``.
    """
    entries = [BomEntry.model_validate(c) for c in components]
    _, path = _write_next_version(
        _env_dir(environment_name),
        lambda: {
            **_load_state(environment_name).model_dump(mode="json"),
            "bom": entries,
        },
    )
    return {
        "stored": len(entries),
        "saved_to": str(path),
        "environment_name": environment_name,
        "bom": [e.model_dump(mode="json") for e in entries],
    }


async def bom_check(environment_name: str, days_back: int = 7) -> dict[str, Any]:
    """Check BOM components for CVEs published or modified in the last N days.

    Args:
        environment_name: Environment whose BOM to check.
        days_back: How many days back to search (default: 7).

    Returns:
        Dict with ``findings`` (grouped by component), ``total_cves``, and ``summary``.
    """
    state = _load_state(environment_name)

    if not state.bom:
        return {
            "checked_at": datetime.now(tz=UTC).isoformat(),
            "days_back": days_back,
            "environment_name": environment_name,
            "findings": {},
            "total_cves": 0,
            "message": "BOM is empty. Use bom_update to store your component list.",
        }

    findings: dict[str, list[dict]] = {}
    now = datetime.now(tz=UTC).isoformat()

    async def _lookup(entry: BomEntry) -> list[dict]:
        osv_ecosystem = _resolve_ecosystem(entry.ecosystem, entry.type)

        # Maven packages in OSV require full groupId:artifactId coordinates
        # (e.g. "org.apache.logging.log4j:log4j-core"). A bare artifact ID like
        # "log4j-core" returns 0 results — fall back to NVD normalization instead,
        # which strips the "-core" suffix and tries "log4j" as the keyword.
        if osv_ecosystem == "Maven" and ":" not in entry.name:
            _logger.info(
                "BOM check: %s %s — Maven bare artifact ID → NVD fallback"
                " (tip: use groupId:artifactId for OSV precision)",
                entry.name,
                entry.version,
            )
            osv_ecosystem = None

        if osv_ecosystem:
            # OSV knows package-manager-native names (Maven artifact IDs, PyPI names,
            # npm modules, etc.) — no NVD naming knowledge required from the user.
            _logger.info(
                "BOM check: %s %s → OSV ecosystem=%r days_back=%s",
                entry.name,
                entry.version,
                osv_ecosystem,
                days_back,
            )
            cves = await osv_fetcher.search(
                entry.name,
                osv_ecosystem,
                version=entry.version,
                days_back=days_back,
            )
        else:
            # No ecosystem hint — fall back to NVD keyword search with name
            # normalisation (strips "-core"/"-lib" suffixes, tries split variants, etc.)
            _logger.info(
                "BOM check: %s %s → NVD keyword days_back=%d",
                entry.name,
                entry.version,
                days_back,
            )
            cves = await nvd_fetcher.search(
                entry.name, days_back=days_back, vendor=entry.vendor
            )

        _logger.info(
            "BOM check: %s %s → %d CVE(s)",
            entry.name,
            entry.version,
            len(cves),
        )
        return cves

    # NVD allows 5 requests per 30s unauthenticated; stay below that.
    sem = asyncio.Semaphore(3)

    async def _bounded(entry: BomEntry) -> list[dict]:
        async with sem:
            return await _lookup(entry)

    # gather preserves input order, so findings follow BOM order.
    results = await asyncio.gather(*(_bounded(e) for e in state.bom))
    for entry, cves in zip(state.bom, results, strict=True):
        if cves:
            findings[f"{entry.name} {entry.version}"] = cves

    checked = {(e.name, e.version) for e in state.bom}

    def _merge_timestamps() -> dict[str, Any]:
        # Re-read under the lock: apply only last_checked, never the stale BOM.
        latest = _load_state(environment_name)
        for e in latest.bom:
            if (e.name, e.version) in checked:
                e.last_checked = now
        return latest.model_dump(mode="json")

    _write_next_version(_env_dir(environment_name), _merge_timestamps)

    total = sum(len(v) for v in findings.values())
    return {
        "checked_at": now,
        "days_back": days_back,
        "environment_name": environment_name,
        "findings": findings,
        "total_cves": total,
        "summary": (
            f"Found {total} CVE(s) across {len(findings)} component(s) "
            f"in the last {days_back} day(s)."
            if total
            else f"No new CVEs found for any BOM component in the last {days_back} day(s)."  # noqa: E501
        ),
    }
