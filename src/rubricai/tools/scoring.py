"""score.evaluate MCP tool — dispatches to the requested scoring policy."""

from typing import Any

from ..policy.registry import DEFAULT_POLICY, get_evaluator
from ..schemas.finding import Finding
from ..schemas.intel import IntelResult


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
    f = Finding.model_validate(finding)
    # Strip AI-use fields added by intel_lookup that are not in IntelResult schema
    intel_clean = {k: v for k, v in intel.items() if k != "derived_finding_context"}
    i = IntelResult.model_validate(intel_clean)
    version = policy_version or DEFAULT_POLICY

    evaluator = get_evaluator(version)
    assessment = evaluator(f, i, policy_version=version)
    return assessment.model_dump(mode="json")
