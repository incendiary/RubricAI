"""FastMCP server — registers all RubricAI tools."""

import logging
import os
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP

from .tools.bom import bom_check as _bom_check
from .tools.bom import bom_update as _bom_update
from .tools.environment import env_list as _env_list
from .tools.environment import env_migrate_legacy as _env_migrate_legacy
from .tools.environment import env_read as _env_read
from .tools.environment import env_write as _env_write
from .tools.intel import lookup as _intel_lookup
from .tools.policy import policy_get as _policy_get
from .tools.report import report_generate as _report_generate
from .tools.scoring import score_evaluate as _score_evaluate

# Load .env before reading any env vars. No-ops if file absent.
# Does not override vars already set in the process environment.
load_dotenv()

# Configure logging at server startup.
# Level: RUBRICAI_LOG_LEVEL env var (default INFO).
# Output: ~/.local/share/rubricai/rubricai.log + stderr.
_log_level = os.getenv("RUBRICAI_LOG_LEVEL", "INFO").upper()
_log_path = (
    Path(os.getenv("RUBRICAI_LOG_DIR", str(Path.home() / ".local/share/rubricai")))
    / "rubricai.log"
)
_log_path.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(_log_path), logging.StreamHandler()],
    force=True,  # override any root logger config set by FastMCP
)

mcp = FastMCP("RubricAI")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAX_CVE_LIST_SIZE = 50


@mcp.tool()
async def intel_lookup(
    cves: list[str], include: list[str] | None = None
) -> dict[str, Any]:
    """Fetch public intel signals (KEV, EPSS, CVSS, PoC, vendor) for one or more CVEs.

    Args:
        cves: List of CVE IDs, e.g. ["CVE-2024-1234"]. Max 50 per request.
        include: Subset of signal types to fetch. Options: kev, epss, cvss, poc, vendor.
                 Omit to fetch all.
    """
    if len(cves) > _MAX_CVE_LIST_SIZE:
        raise ValueError(
            f"Too many CVEs ({len(cves)}). Maximum is {_MAX_CVE_LIST_SIZE} per request."
        )
    invalid = [c for c in cves if not _CVE_RE.match(c)]
    if invalid:
        raise ValueError(
            f"Invalid CVE ID format: {invalid[:5]}. Expected CVE-YYYY-NNNNN."
        )
    return await _intel_lookup(cves, include)


@mcp.tool()
def score_evaluate(
    finding: dict[str, Any],
    intel: dict[str, Any],
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Apply the CHML scoring policy to produce a lane, target, and rationale.

    Args:
        finding: Finding object (engineer-provided context).
        intel: IntelResult object (output of intel_lookup).
        policy_version: Policy version string. Defaults to current version.
    """
    return _score_evaluate(finding, intel, policy_version)


@mcp.tool()
def report_generate(
    finding: dict[str, Any],
    intel: dict[str, Any],
    assessment: dict[str, Any],
    formats: list[str] | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a standardised report card (markdown + JSON) and persist to disk.

    Args:
        finding: Finding object (engineer-provided context).
        intel: IntelResult object (output of intel_lookup).
        assessment: Assessment object (output of score_evaluate).
        formats: Options: markdown, json, pdf. Defaults to markdown + json.
                 Add "pdf" to also generate a single-page landscape PDF card.
        evidence: Optional list of evidence items. Each item should have:
                  claim (str), type (str), content (str|null),
                  analyst_note (str|null), verified (bool).
    """
    return _report_generate(finding, intel, assessment, formats, evidence)


@mcp.tool()
def env_list() -> dict[str, Any]:
    """List all named environments stored on disk.

    Call this at the very start of every session — before any other tool —
    to determine which environment the engineer is working in.

    Returns:
        Dict with ``environments`` (list of names), ``count``, and
        ``needs_migration`` (True if legacy flat state files exist from
        a pre-v0.8 install — prompt the engineer to name them).
    """
    return _env_list()


@mcp.tool()
def env_read(environment_name: str) -> dict[str, Any]:
    """Read the current state for a named environment.

    Returns the latest versioned state, or an empty template if the
    environment has not been used before. The returned dict includes
    ``environment_name`` so downstream tools know the active context.

    Args:
        environment_name: Environment to read (e.g. ``"production-dmz"``).
            Use ``env_list()`` to see available names.
    """
    return _env_read(environment_name)


@mcp.tool()
def env_write(state: dict[str, Any], environment_name: str) -> dict[str, Any]:
    """Write an updated state for a named environment.

    Increments the version counter and writes ``state_vNNN.json``.
    Call at the end of every session with the full updated state and
    a session_log entry summarising what was assessed.

    Args:
        state: Full environment state dict.
        environment_name: Target environment (same as used in env_read).
    """
    return _env_write(state, environment_name)


@mcp.tool()
def env_migrate_legacy(environment_name: str) -> dict[str, Any]:
    """Migrate pre-v0.8 flat state files into a named environment.

    Only needed once after upgrading from v0.7 or earlier. If
    ``env_list()`` returns ``needs_migration: true``, ask the engineer
    what to call the existing environment and call this tool.

    Args:
        environment_name: Name to assign to the migrated environment.
    """
    return _env_migrate_legacy(environment_name)


@mcp.tool()
def policy_get(policy_version: str | None = None) -> dict[str, Any]:
    """Return the current CHML policy definition for transparency and auditability.

    Args:
        policy_version: Version to retrieve. Currently only chml-v0.1 exists.
    """
    return _policy_get(policy_version)


@mcp.tool()
def bom_update(
    components: list[dict[str, Any]], environment_name: str
) -> dict[str, Any]:
    """Store or replace the Bill of Materials for a named environment.

    Call this when an engineer supplies their component list. The BOM is
    persisted to the environment state and used by ``bom_check`` to monitor
    for new CVEs.

    Args:
        components: List of component dicts. Each requires ``name`` (str) and
                    ``version`` (str). Optional: ``type``, ``vendor``, ``notes``.
        environment_name: Target environment (same as used in env_read).

    The ``type`` field doubles as an ecosystem hint for the CVE lookup engine.
    Setting ``type`` to a package-manager name routes lookups through OSV, which
    uses developer-native package names. Without an ecosystem hint the lookup falls
    back to NVD keyword search with automatic name normalisation.

    **Ecosystem hints** (``type`` or ``ecosystem`` field): ``"maven"``, ``"pypi"``,
    ``"npm"``, ``"nuget"``, ``"go"``, ``"ruby"``, ``"rust"``, ``"debian"``,
    ``"ubuntu"``, ``"alpine"``, etc.

    **Maven note**: OSV requires the full ``groupId:artifactId`` coordinate.
    Use ``"org.apache.logging.log4j:log4j-core"`` not ``"log4j-core"`` for Maven
    packages. Bare artifact IDs automatically fall back to NVD normalisation.

    Example::

        bom_update([
            # Maven — full coordinate (groupId:artifactId) for OSV precision
            {
                "name": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.0",
                "type": "maven",
            },
            # PyPI / npm / Go — just the package name works
            {"name": "requests",  "version": "2.28.0", "type": "pypi"},
            {"name": "express",   "version": "4.18.0", "type": "npm"},
            # No ecosystem hint → NVD keyword search with name normalisation
            {"name": "openssl",   "version": "3.1.4"},
            {"name": "nginx",     "version": "1.24.0"},
        ])
    """
    return _bom_update(components, environment_name)


@mcp.tool()
async def bom_check(environment_name: str, days_back: int = 7) -> dict[str, Any]:
    """Check all BOM components for CVEs published or modified recently.

    Queries NVD for each stored BOM component and returns any matching CVEs.
    Useful for a daily/weekly "are there any new CVEs I need to look at?"
    workflow.

    Args:
        environment_name: Environment whose BOM to check.
        days_back: How far back to search (default: 7 days).

    Returns:
        Dict with ``findings`` (grouped by component), ``total_cves``, and
        a human-readable ``summary``.
    """
    return await _bom_check(environment_name, days_back)
