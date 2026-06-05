"""policy.get MCP tool — returns the current CHML policy definition."""

from ..policy.definitions import (
    EPSS_HIGH_THRESHOLD,
    HIGH_UTILITY_TYPES,
    LANE_BASES,
    POLICY_VERSION,
    STRONG_MITIGATION_TYPES,
    get_lane_targets,
)


def policy_get(policy_version: str | None = None) -> dict:
    """Return the CHML policy definition for auditability.

    Args:
        policy_version: Version to retrieve. Currently only ``chml-v0.2`` exists.

    Returns:
        Policy definition as a serialisable dict.
    """
    targets = get_lane_targets()
    return {
        "policy_version": POLICY_VERSION,
        "lanes": {
            lane: {
                "target_days": targets[lane],
                "patch_train": targets[lane] is None,
                "basis": LANE_BASES[lane],
            }
            for lane in targets
        },
        "thresholds": {
            "epss_high": EPSS_HIGH_THRESHOLD,
        },
        "high_utility_types": sorted(HIGH_UTILITY_TYPES),
        "strong_mitigation_types": sorted(STRONG_MITIGATION_TYPES),
        "guardrails": [
            "External intel (KEV, high EPSS) may escalate urgency but cannot "
            "downgrade without strong evidence that the exploit path is blocked. "
            "PoC availability is not used as a scoring signal; absence of public "
            "PoC does not reduce lane assignment.",
            "Mitigations must be exploit-relevant. 'EDR exists' does not mitigate "
            "an IDOR vulnerability.",
            "Scoring is deterministic — lane decisions are made by server rules, "
            "not by AI freehand.",
        ],
    }
