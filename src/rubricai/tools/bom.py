"""bom_update / bom_check MCP tools — Bill of Materials CVE monitoring."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..fetchers import nvd as nvd_fetcher
from ..schemas.environment import BomEntry, EnvironmentState
from .environment import _env_dir


def _load_state() -> EnvironmentState:
    """Load current environment state, returning empty state if none exists."""
    env_dir = _env_dir()
    latest = env_dir / "state_latest.json"
    if latest.exists():
        import json

        data = json.loads(latest.read_text(encoding="utf-8"))
        return EnvironmentState.model_validate(data)
    return EnvironmentState()


def _save_state(state: EnvironmentState) -> str:
    """Persist updated state; returns path written."""
    import json
    import re

    env_dir = _env_dir()

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


def bom_update(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Store or replace the Bill of Materials in the environment state.

    Args:
        components: List of component dicts. Each requires ``name`` and
                    ``version``; optional fields: ``type``, ``vendor``, ``notes``.

    Returns:
        Dict with ``stored`` (count), ``saved_to`` (path), and ``bom`` (list).
    """
    entries = [BomEntry.model_validate(c) for c in components]
    state = _load_state()
    state.bom = entries
    path = _save_state(state)
    return {
        "stored": len(entries),
        "saved_to": path,
        "bom": [e.model_dump(mode="json") for e in entries],
    }


async def bom_check(days_back: int = 7) -> dict[str, Any]:
    """Check all BOM components for CVEs published or modified in the last N days.

    Reads the BOM from the current environment state and queries NVD for each
    component. Updates ``last_checked`` timestamps on each BOM entry.

    Args:
        days_back: How many days back to search (default: 7).

    Returns:
        Dict with ``checked_at``, ``days_back``, ``findings`` (grouped by
        component), and ``total_cves`` count.
    """
    state = _load_state()

    if not state.bom:
        return {
            "checked_at": datetime.now(tz=UTC).isoformat(),
            "days_back": days_back,
            "findings": {},
            "total_cves": 0,
            "message": "BOM is empty. Use bom_update to store your component list.",
        }

    findings: dict[str, list[dict]] = {}
    now = datetime.now(tz=UTC).isoformat()

    for entry in state.bom:
        keyword = f"{entry.name} {entry.version}"
        cves = await nvd_fetcher.search(keyword, days_back=days_back)
        entry.last_checked = now
        if cves:
            findings[f"{entry.name} {entry.version}"] = cves

    # Persist updated last_checked timestamps
    _save_state(state)

    total = sum(len(v) for v in findings.values())
    return {
        "checked_at": now,
        "days_back": days_back,
        "findings": findings,
        "total_cves": total,
        "summary": (
            f"Found {total} CVE(s) across {len(findings)} component(s) "
            f"in the last {days_back} day(s)."
            if total
            else f"No new CVEs found for any BOM component in the last {days_back} day(s)."  # noqa: E501
        ),
    }
