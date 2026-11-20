"""score.evaluate and score.compare MCP tools — apply scoring policies."""

from typing import Any

from ..policy.definitions import POLICY_VERSION
from ..policy.registry import AVAILABLE_POLICIES, get_evaluator
from ..schemas.finding import Finding
from ..schemas.intel import IntelResult
from ..validation import validate_model


def validate_intel(intel: dict[str, Any]) -> IntelResult:
    """Validate intel_lookup output, dropping its AI-use ``derived_finding_context``."""
    intel_clean = {k: v for k, v in intel.items() if k != "derived_finding_context"}
    return validate_model(IntelResult, intel_clean, "intel")


def score_evaluate(
    finding: dict[str, Any],
    intel: dict[str, Any],
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Apply a scoring policy and return an Assessment dict.

    Args:
        finding: Validated Finding data (as dict).
        intel: IntelResult data (as dict, from intel.lookup output).
        policy_version: Policy to apply. One of: ``chml-v0.2`` (default), ``epss-v5``,
            ``bod-26-04``. Defaults to ``chml-v0.2``.

    Returns:
        Assessment as a serialisable dict.
    """
    f = validate_model(Finding, finding, "finding")
    i = validate_intel(intel)
    version = policy_version or POLICY_VERSION

    evaluator = get_evaluator(version)
    assessment = evaluator(f, i, policy_version=version)
    return assessment.model_dump(mode="json")


def score_compare(
    finding: dict[str, Any],
    intel: dict[str, Any],
) -> dict[str, Any]:
    """Score a finding under all registered policies and return a comparison.

    Args:
        finding: Validated Finding data (as dict).
        intel: IntelResult data (as dict, from intel.lookup output).

    Returns:
        Dict with:
          - ``results``: mapping of policy_name → Assessment dict
          - ``summary``: one row per policy (policy, lane, sla_days, basis)
          - ``consensus``: ``"agree"`` if all policies agree on lane,
            else ``"diverge"``
    """
    f = validate_model(Finding, finding, "finding")
    i = validate_intel(intel)

    results: dict[str, Any] = {}
    summary: list[dict[str, Any]] = []

    for policy_name in AVAILABLE_POLICIES:
        assessment = get_evaluator(policy_name)(f, i, policy_version=policy_name)
        results[policy_name] = assessment.model_dump(mode="json")
        summary.append(
            {
                "policy": policy_name,
                "lane": assessment.lane,
                "sla_days": assessment.target.days,
                "basis": assessment.target.basis,
            }
        )

    lanes = {row["lane"] for row in summary}
    consensus = "agree" if len(lanes) == 1 else "diverge"

    return {"results": results, "summary": summary, "consensus": consensus}
