"""env_list / env_read / env_write MCP tools — multi-environment versioned state."""

import fcntl  # Unix only — Windows deployments must use Docker (Linux container)
import json
import os
import re
from collections.abc import Callable
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


def _env_dir(environment_name: str, *, create: bool = True) -> Path:
    """Return the directory for a named environment, creating it if needed.

    Always validates the name to prevent path traversal, regardless of caller.
    Read-only callers pass ``create=False`` so a mistyped name leaves no directory.
    """
    safe_name = _validate_env_name(environment_name)
    d = _environments_dir() / safe_name
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def _current_version(env_dir: Path) -> int:
    versions = []
    for f in env_dir.glob("state_v*.json"):
        m = re.fullmatch(r"state_v(\d+)\.json", f.name)
        if m:
            versions.append(int(m.group(1)))
    return max(versions, default=0)


def _write_next_version(
    env_dir: Path, build: Callable[[], dict[str, Any]]
) -> tuple[int, Path]:
    """Allocate the next version and write ``state_vNNN.json`` + ``state_latest.json``.

    ``build`` runs inside the exclusive lock, so it may read the latest state and
    return a modified copy without losing concurrent writes.
    """
    # Exclusive file lock prevents TOCTOU race on concurrent version increment
    lock_path = env_dir / ".write.lock"
    lock_path.touch(exist_ok=True)
    with open(lock_path) as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            next_ver = _current_version(env_dir) + 1

            validated = EnvironmentState.model_validate(
                {
                    **build(),
                    "version": next_ver,
                    "updated_at": datetime.now(tz=UTC).isoformat(),
                }
            )

            versioned_path = env_dir / f"state_v{next_ver:03d}.json"
            content = json.dumps(validated.model_dump(mode="json"), indent=2)
            versioned_path.write_text(content, encoding="utf-8")
            (env_dir / "state_latest.json").write_text(content, encoding="utf-8")
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    return next_ver, versioned_path


def env_list() -> dict[str, Any]:
    """List all named environments on disk.

    Returns a dict with:
        environments  list[str]  — sorted environment names
        count         int        — number of environments
    """
    envs_dir = _environments_dir()
    names = sorted(d.name for d in envs_dir.iterdir() if d.is_dir())
    return {
        "environments": names,
        "count": len(names),
    }


def env_read(environment_name: str) -> dict[str, Any]:
    """Read the current state for a named environment.

    Does not create the environment directory: an unknown name returns an
    empty state template and leaves no trace in ``env_list()``.

    Args:
        environment_name: Name of the environment (e.g. ``"production-dmz"``).
            Use ``env_list()`` to see available names.

    Returns:
        Environment state dict, plus ``"environment_name"`` key.
    """
    name = _validate_env_name(environment_name)
    d = _env_dir(name, create=False)

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

    next_ver, versioned_path = _write_next_version(
        d, lambda: {k: v for k, v in state.items() if k != "environment_name"}
    )

    return {
        "version": next_ver,
        "saved_to": str(versioned_path),
        "environment_name": name,
    }
