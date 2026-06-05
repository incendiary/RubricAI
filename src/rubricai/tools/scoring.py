"""score.evaluate MCP tool — applies CHML policy to finding + intel."""

from typing import Any

from ..policy.chml import evaluate
from ..schemas.finding import Finding
from ..schemas.intel import IntelResult


def score_evaluate(
    finding: dict[str, Any],
    intel: dict[str, Any],
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Apply the CHML scoring policy and return an Assessment dict.

    Args:
        finding: Validated Finding data (as dict).
        intel: IntelResult data (as dict, from intel.lookup output).
        policy_version: Optional policy version string. Defaults to current version.

    Returns:
        Assessment as a serialisable dict.
    """
    from ..policy.definitions import POLICY_VERSION

    f = Finding.model_validate(finding)
    # Strip AI-use fields added by intel_lookup that are not in IntelResult schema
    intel_clean = {k: v for k, v in intel.items() if k != "derived_finding_context"}
    i = IntelResult.model_validate(intel_clean)
    version = policy_version or POLICY_VERSION

    assessment = evaluate(f, i, policy_version=version)
    return assessment.model_dump(mode="json")
