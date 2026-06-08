"""bom_update / bom_check MCP tools — Bill of Materials CVE monitoring."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from ..fetchers import nvd as nvd_fetcher
from ..schemas.environment import BomEntry, EnvironmentState
from .environment import _env_dir

_logger = logging.getLogger(__name__)


def _load_state(environment_name: str) -> EnvironmentState:
    env_dir = _env_dir(environment_name)
    latest = env_dir / "state_latest.json"
    if latest.exists():
        data = json.loads(latest.read_text(encoding="utf-8"))
        return EnvironmentState.model_validate(data)
    return EnvironmentState()


def _save_state(state: EnvironmentState, environment_name: str) -> str:
    env_dir = _env_dir(environment_name)

    def _current_version() -> int:
        versions = []
        for f in env_dir.glob("state_v*.json"):
            m = re.fullmatch(r"state_v(\d+)\.json", f.name)
            if m:
                versions.append(int(m.group(1)))
        return max(versions, default=0)

    next_ver = _current_version() + 1
    state.version = next_ver
    state.updated_at = datetime.now(tz=UTC).isoformat()

    content = json.dumps(state.model_dump(mode="json"), indent=2)
    versioned = env_dir / f"state_v{next_ver:03d}.json"
    versioned.write_text(content, encoding="utf-8")
    (env_dir / "state_latest.json").write_text(content, encoding="utf-8")
    return str(versioned)


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
    state = _load_state(environment_name)
    state.bom = entries
    path = _save_state(state, environment_name)
    return {
        "stored": len(entries),
        "saved_to": path,
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

    for entry in state.bom:
        # NVD keywordSearch uses AND logic across all words — a compound
        # "Log4j-core 2.14.0" query won't match CVE descriptions that say
        # "Apache Log4j2 2.0–2.14.1". Search by name only; the engineer
        # confirms version applicability during triage.
        keyword = entry.name
        _logger.info(
            "BOM check: %s %s → keyword=%r days_back=%d",
            entry.name,
            entry.version,
            keyword,
            days_back,
        )
        cves = await nvd_fetcher.search(keyword, days_back=days_back)
        _logger.info(
            "BOM check: %s %s → %d CVE(s)",
            entry.name,
            entry.version,
            len(cves),
        )
        entry.last_checked = now
        if cves:
            findings[f"{entry.name} {entry.version}"] = cves

    _save_state(state, environment_name)

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
