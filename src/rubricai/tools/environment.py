"""env_read / env_write MCP tools — versioned environment state."""

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..schemas.environment import EnvironmentState

_DEFAULT_ENV_DIR = Path.home() / ".local" / "share" / "rubricai"


def _env_dir() -> Path:
    p = Path(os.getenv("RUBRICAI_ENV_DIR", str(_DEFAULT_ENV_DIR)))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _current_version(env_dir: Path) -> int:
    """Return the highest version number present, or 0 if none."""
    versions = []
    for f in env_dir.glob("state_v*.json"):
        m = re.fullmatch(r"state_v(\d+)\.json", f.name)
        if m:
            versions.append(int(m.group(1)))
    return max(versions, default=0)


def env_read() -> dict[str, Any]:
    """Read the current environment state.

    Looks for ``state_latest.json`` in ``RUBRICAI_ENV_DIR`` (default
    ``./environment/``). Falls back to the highest-numbered version file.
    Returns an empty state template if no files are found.
    """
    env_dir = _env_dir()

    latest = env_dir / "state_latest.json"
    if latest.exists():
        return json.loads(latest.read_text(encoding="utf-8"))

    current = _current_version(env_dir)
    if current:
        path = env_dir / f"state_v{current:03d}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    # No state on disk — return an empty template so the AI knows the schema
    return EnvironmentState().model_dump(mode="json")


def env_write(state: dict[str, Any]) -> dict[str, Any]:
    """Write a new version of the environment state.

    Never overwrites existing files. Increments the version number, writes
    ``state_vNNN.json``, then copies to ``state_latest.json``.

    Args:
        state: Environment state dict. ``version`` and ``updated_at`` are
               set automatically.

    Returns:
        Dict with ``version`` (int) and ``saved_to`` (path string).
    """
    env_dir = _env_dir()
    next_ver = _current_version(env_dir) + 1

    validated = EnvironmentState.model_validate(
        {
            **state,
            "version": next_ver,
            "updated_at": datetime.now(tz=UTC).isoformat(),
        }
    )

    versioned_path = env_dir / f"state_v{next_ver:03d}.json"
    content = json.dumps(validated.model_dump(mode="json"), indent=2)
    versioned_path.write_text(content, encoding="utf-8")

    latest_path = env_dir / "state_latest.json"
    latest_path.write_text(content, encoding="utf-8")

    return {"version": next_ver, "saved_to": str(versioned_path)}
