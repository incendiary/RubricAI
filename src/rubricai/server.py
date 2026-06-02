"""FastMCP server — registers all RubricAI tools."""

from typing import Any

from fastmcp import FastMCP

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
) -> dict[str, Any]:
    """Generate a standardised report card (markdown + JSON) and persist to disk.

    Args:
        finding: Finding object (engineer-provided context).
        intel: IntelResult object (output of intel_lookup).
        assessment: Assessment object (output of score_evaluate).
        formats: Output formats to produce. Options: markdown, json. Defaults to both.
    """
    return _report_generate(finding, intel, assessment, formats)


@mcp.tool()
def policy_get(policy_version: str | None = None) -> dict[str, Any]:
    """Return the current CHML policy definition for transparency and auditability.

    Args:
        policy_version: Version to retrieve. Currently only chml-v0.1 exists.
    """
    return _policy_get(policy_version)
