"""policy.get MCP tool — returns a policy definition for auditability."""

from ..policy.definitions import (
    EPSS_HIGH_THRESHOLD,
    EPSS_V5_CRITICAL_THRESHOLD,
    EPSS_V5_HIGH_THRESHOLD,
    EPSS_V5_LANE_BASES,
    EPSS_V5_LANE_TARGETS,
    EPSS_V5_MEDIUM_THRESHOLD,
    HIGH_UTILITY_TYPES,
    LANE_BASES,
    POLICY_VERSION,
    STRONG_MITIGATION_TYPES,
    get_lane_targets,
)
from ..policy.registry import AVAILABLE_POLICIES


def policy_get(policy_version: str | None = None) -> dict:
    """Return the policy definition for auditability.

    Args:
        policy_version: Policy to describe. One of: ``chml-v0.2`` (default),
            ``epss-v5``, ``bod-26-04``. Omit to get the default policy.
            Pass ``"list"`` to retrieve all available policy names.

    Returns:
        Policy definition as a serialisable dict, or a list of available policies.
    """
    if policy_version == "list":
        return {"available_policies": AVAILABLE_POLICIES, "default": POLICY_VERSION}

    version = policy_version or POLICY_VERSION

    if version == "epss-v5":
        return _epss_v5_definition()

    # Default: chml-v0.2 (and any unrecognised version falls through to chml)
    return _chml_definition()


def _chml_definition() -> dict:
    targets = get_lane_targets()
    return {
        "policy_version": POLICY_VERSION,
        "display_name": "Default Test (CHML v0.2)",
        "description": (
            "Deterministic CHML scoring. KEV + internet-exposure + high attacker utility "
            "drives Critical. EPSS is a secondary escalation signal."
        ),
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


def _epss_v5_definition() -> dict:
    return {
        "policy_version": "epss-v5",
        "display_name": "Default EPSS v5",
        "description": (
            "EPSS-primary scoring using FIRST EPSS v5 (released 2026-06-15). "
            "EPSS probability drives lane assignment directly; reachability is a modifier. "
            "KEV escalates internet-exposed findings to High regardless of EPSS score."
        ),
        "lanes": {
            lane: {
                "target_days": EPSS_V5_LANE_TARGETS[lane],
                "patch_train": EPSS_V5_LANE_TARGETS[lane] is None,
                "basis": EPSS_V5_LANE_BASES[lane],
            }
            for lane in EPSS_V5_LANE_TARGETS
        },
        "thresholds": {
            "epss_critical": EPSS_V5_CRITICAL_THRESHOLD,
            "epss_high": EPSS_V5_HIGH_THRESHOLD,
            "epss_medium": EPSS_V5_MEDIUM_THRESHOLD,
        },
        "strong_mitigation_types": sorted(STRONG_MITIGATION_TYPES),
        "guardrails": [
            f"EPSS score >= {EPSS_V5_CRITICAL_THRESHOLD} on an internet-exposed asset "
            "is treated as Critical regardless of KEV status.",
            "KEV escalates internet-exposed findings to High even when EPSS is below "
            f"the High threshold ({EPSS_V5_HIGH_THRESHOLD}).",
            "EPSS is a 30-day exploitation probability estimate — it does not measure "
            "attacker utility or impact. Review findings for severity context.",
            "Scoring is deterministic — lane decisions are made by server rules, "
            "not by AI freehand.",
        ],
    }
