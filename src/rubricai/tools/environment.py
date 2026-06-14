"""env_list / env_read / env_write MCP tools — multi-environment versioned state."""

import fcntl  # Unix only — Windows deployments must use Docker (Linux container)
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..schemas.environment import EnvironmentState

_DEFAULT_BASE_DIR = Path.home() / ".local" / "share" / "rubricai"
_ENV_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$")


def _base_dir() -> Path:
    p = Path(os.getenv("RUBRICAI_ENV_DIR", str(_DEFAULT_BASE_DIR)))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _environments_dir() -> Path:
    d = _base_dir() / "environments"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _validate_env_name(name: str) -> str:
    """Normalise and validate an environment name. Raises ValueError on bad input."""
    name = name.strip().lower().replace(" ", "-").replace("_", "-")
    if not _ENV_NAME_RE.match(name):
        raise ValueError(
            f"Invalid environment name '{name}'. "
            "Use lowercase letters, numbers, and hyphens only."
        )
    return name


def _env_dir(environment_name: str) -> Path:
    """Return the directory for a named environment, creating it if needed.

    Always validates the name to prevent path traversal, regardless of caller.
    """
    safe_name = _validate_env_name(environment_name)
    d = _environments_dir() / safe_name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _current_version(env_dir: Path) -> int:
    versions = []
    for f in env_dir.glob("state_v*.json"):
        m = re.fullmatch(r"state_v(\d+)\.json", f.name)
        if m:
            versions.append(int(m.group(1)))
    return max(versions, default=0)


def _legacy_state_files() -> list[Path]:
    """Return any state files at the old flat root location (pre-v0.8 layout)."""
    base = _base_dir()
    return sorted(base.glob("state_v*.json"))


def env_list() -> dict[str, Any]:
    """List all named environments on disk.

    Returns a dict with:
        environments  list[str]  — sorted environment names
        count         int        — number of environments
        needs_migration bool     — True if legacy flat state files exist at root
        legacy_files  int        — count of legacy state files (if any)
    """
    envs_dir = _environments_dir()
    names = sorted(d.name for d in envs_dir.iterdir() if d.is_dir())
    legacy = _legacy_state_files()
    return {
        "environments": names,
        "count": len(names),
        "needs_migration": len(legacy) > 0,
        "legacy_files": len(legacy),
    }


def env_read(environment_name: str) -> dict[str, Any]:
    """Read the current state for a named environment.

    Creates the environment directory if it does not exist yet and returns
    an empty state template on first read.

    Args:
        environment_name: Name of the environment (e.g. ``"production-dmz"``).
            Use ``env_list()`` to see available names.

    Returns:
        Environment state dict, plus ``"environment_name"`` key.
    """
    name = _validate_env_name(environment_name)
    d = _env_dir(name)

    latest = d / "state_latest.json"
    if latest.exists():
        state = json.loads(latest.read_text(encoding="utf-8"))
        state["environment_name"] = name
        return state

    current = _current_version(d)
    if current:
        path = d / f"state_v{current:03d}.json"
        state = json.loads(path.read_text(encoding="utf-8"))
        state["environment_name"] = name
        return state

    # First read for this environment — return empty template
    empty = EnvironmentState().model_dump(mode="json")
    empty["environment_name"] = name
    return empty


def env_write(state: dict[str, Any], environment_name: str) -> dict[str, Any]:
    """Write a new versioned state for a named environment.

    Never overwrites existing files. Increments the version counter and
    writes ``state_vNNN.json``, then copies to ``state_latest.json``.

    Args:
        state: Environment state dict.
        environment_name: Target environment name.

    Returns:
        Dict with ``version``, ``saved_to``, and ``environment_name``.
    """
    name = _validate_env_name(environment_name)
    d = _env_dir(name)

    # Exclusive file lock prevents TOCTOU race on concurrent version increment
    lock_path = d / ".write.lock"
    lock_path.touch(exist_ok=True)
    with open(lock_path) as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            next_ver = _current_version(d) + 1

            validated = EnvironmentState.model_validate(
                {
                    **{k: v for k, v in state.items() if k != "environment_name"},
                    "version": next_ver,
                    "updated_at": datetime.now(tz=UTC).isoformat(),
                }
            )

            versioned_path = d / f"state_v{next_ver:03d}.json"
            content = json.dumps(validated.model_dump(mode="json"), indent=2)
            versioned_path.write_text(content, encoding="utf-8")
            (d / "state_latest.json").write_text(content, encoding="utf-8")
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)

    return {
        "version": next_ver,
        "saved_to": str(versioned_path),
        "environment_name": name,
    }


def env_migrate_legacy(environment_name: str) -> dict[str, Any]:
    """Migrate flat root-level state files into a named environment.

    Moves all ``state_v*.json`` and ``state_latest.json`` from the old flat
    layout into ``environments/<environment_name>/``. Safe to call once;
    no-ops if no legacy files exist.

    Args:
        environment_name: Name to assign to the migrated environment.

    Returns:
        Dict with ``migrated`` (count), ``environment_name``, and ``destination``.
    """
    name = _validate_env_name(environment_name)
    legacy = _legacy_state_files()
    if not legacy:
        return {"migrated": 0, "environment_name": name, "destination": None}

    dest = _env_dir(name)
    moved = 0
    for src in legacy:
        target = dest / src.name
        if not target.exists():
            src.rename(target)
            moved += 1

    # Also move state_latest.json if it exists at root
    root_latest = _base_dir() / "state_latest.json"
    if root_latest.exists():
        target = dest / "state_latest.json"
        if not target.exists():
            root_latest.rename(target)
        else:
            root_latest.unlink()

    return {
        "migrated": moved,
        "environment_name": name,
        "destination": str(dest),
    }
