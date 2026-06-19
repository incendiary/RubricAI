"""score_compare MCP tool — runs all registered policies, returns a comparison."""

from typing import Any

from ..policy.registry import _POLICIES
from ..schemas.finding import Finding
from ..schemas.intel import IntelResult


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
    f = Finding.model_validate(finding)
    intel_clean = {k: v for k, v in intel.items() if k != "derived_finding_context"}
    i = IntelResult.model_validate(intel_clean)

    results: dict[str, Any] = {}
    summary: list[dict[str, Any]] = []

    for policy_name, evaluator in _POLICIES.items():
        assessment = evaluator(f, i, policy_version=policy_name)
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
