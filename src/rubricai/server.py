"""FastMCP server — registers all RubricAI tools."""

from typing import Any

from fastmcp import FastMCP

from .tools.environment import env_read as _env_read
from .tools.environment import env_write as _env_write
from .tools.intel import lookup as _intel_lookup
from .tools.policy import policy_get as _policy_get
from .tools.report import report_generate as _report_generate
from .tools.scoring import score_evaluate as _score_evaluate

mcp = FastMCP("RubricAI")


@mcp.tool()
async def intel_lookup(
    cves: list[str], include: list[str] | None = None
) -> dict[str, Any]:
    """Fetch public intel signals (KEV, EPSS, CVSS, PoC, vendor) for one or more CVEs.

    Args:
        cves: List of CVE IDs, e.g. ["CVE-2024-1234"].
        include: Subset of signal types to fetch. Options: kev, epss, cvss, poc, vendor.
                 Omit to fetch all.
    """
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
def env_read() -> dict[str, Any]:
    """Read the current environment state from disk.

    Returns the latest versioned state file from ``RUBRICAI_ENV_DIR``
    (default ``./environment/``), or an empty state template if no file
    exists yet. Call this at the start of every session to surface
    previously captured context.
    """
    return _env_read()


@mcp.tool()
def env_write(state: dict[str, Any]) -> dict[str, Any]:
    """Write an updated environment state to disk.

    Increments the version number and writes a new ``state_vNNN.json``
    file — existing versions are never overwritten. Also updates
    ``state_latest.json``. Call this at the end of every session with
    the full updated state including a session_log entry summarising
    what was assessed and any new context learned.

    Args:
        state: Full environment state dict (see env_read for schema).
    """
    return _env_write(state)


@mcp.tool()
def policy_get(policy_version: str | None = None) -> dict[str, Any]:
    """Return the current CHML policy definition for transparency and auditability.

    Args:
        policy_version: Version to retrieve. Currently only chml-v0.1 exists.
    """
    return _policy_get(policy_version)
