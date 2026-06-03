"""Version consistency checks.

test_version_is_valid_semver — always runs, validates the format of the version
string in pyproject.toml.

test_version_not_behind_latest_tag — runs when git tags are reachable (i.e. on
main after a release, or locally). Skipped automatically in shallow PR clones
where no tags are fetched. The check is one-directional: pyproject.toml version
must be >= the latest tag. Being ahead is fine (version bumped for an upcoming
release); being behind means a release was cut without updating pyproject.toml.
"""

import subprocess
import tomllib
from pathlib import Path

import pytest

_PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


def _read_version() -> str:
    with open(_PYPROJECT, "rb") as f:
        return tomllib.load(f)["project"]["version"]


def _parse(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def test_version_is_valid_semver():
    """pyproject.toml version must be a three-part numeric semver string."""
    version = _read_version()
    parts = version.split(".")
    assert len(parts) == 3, f"Expected X.Y.Z semver, got {version!r}"
    assert all(p.isdigit() for p in parts), f"Non-numeric component in {version!r}"


def test_version_not_behind_latest_tag():
    """pyproject.toml version must not be older than the latest git tag.

    Skipped when no tags are reachable (shallow clone, fresh repo, or PR CI
    without fetch-tags). The CI test job fetches tags on pushes to main so the
    check runs at the point it matters most.
    """
    result = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        capture_output=True,
        text=True,
        cwd=_PYPROJECT.parent,
    )
    if result.returncode != 0:
        pytest.skip("No git tags reachable — skipping version sync check")

    tag = result.stdout.strip().lstrip("v")
    version = _read_version()

    assert _parse(version) >= _parse(tag), (
        f"pyproject.toml version {version!r} is behind the latest git tag v{tag}. "
        f"Update version in pyproject.toml to at least {tag!r}."
    )
