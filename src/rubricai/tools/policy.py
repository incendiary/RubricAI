"""policy.get MCP tool — returns the current CHML policy definition."""

from ..policy.definitions import (
    EPSS_HIGH_THRESHOLD,
    HIGH_UTILITY_TYPES,
    LANE_BASES,
    LANE_TARGETS,
    POLICY_VERSION,
    STRONG_MITIGATION_TYPES,
)


def policy_get(policy_version: str | None = None) -> dict:
    """Return the CHML policy definition for auditability.

    Args:
        policy_version: Version to retrieve. Currently only ``chml-v0.1`` exists.

    Returns:
        Policy definition as a serialisable dict.
    """
    return {
        "policy_version": POLICY_VERSION,
        "lanes": {
            lane: {"target_days": days, "basis": LANE_BASES[lane]}
            for lane, days in LANE_TARGETS.items()
        },
        "thresholds": {
            "epss_high": EPSS_HIGH_THRESHOLD,
        },
        "high_utility_types": sorted(HIGH_UTILITY_TYPES),
        "strong_mitigation_types": sorted(STRONG_MITIGATION_TYPES),
        "guardrails": [
            "External intel (KEV, high EPSS, PoC) may escalate urgency but cannot "
            "downgrade without strong evidence that the exploit path is blocked.",
            "Mitigations must be exploit-relevant. 'EDR exists' does not mitigate "
            "an IDOR vulnerability.",
            "Scoring is deterministic — lane decisions are made by server rules, "
            "not by AI freehand.",
        ],
    }
