import os

POLICY_VERSION = "chml-v0.1"

# Utility types considered "high impact" for lane escalation
HIGH_UTILITY_TYPES: frozenset[str] = frozenset(
    {"rce", "auth_bypass", "priv_esc", "data_access"}
)

# EPSS score threshold for "high exploitation probability"
EPSS_HIGH_THRESHOLD = 0.5

# Mitigation types that can meaningfully break an exploit chain
STRONG_MITIGATION_TYPES: frozenset[str] = frozenset(
    {
        "waf_rule",
        "acl_segmentation",
        "disable_feature",
        "vendor_workaround",
        "virtual_patching",
    }
)

# Default remediation targets (days). None means "patch train" — no fixed SLA.
# Critical and High have explicit SLAs; Medium and Low default to patch train.
LANE_TARGETS: dict[str, int | None] = {
    "critical": 3,  # 72 hours
    "high": 7,
    "medium": None,  # patch train
    "low": None,  # patch train
}

LANE_BASES: dict[str, str] = {
    "critical": "kev_listed + internet_exposed + high_utility",
    "high": "internet_exposed + high_epss_or_poc + high_utility",
    "medium": "constrained_or_internal_reachability_or_lower_impact",
    "low": "low_utility_and_reachability_or_strong_mitigations",
}


def _parse_days(env_var: str, default: int | None) -> int | None:
    val = os.getenv(env_var, "").strip().lower()
    if not val:
        return default
    if val == "patch_train":
        return None
    try:
        return int(val)
    except ValueError:
        return default


def get_lane_targets() -> dict[str, int | None]:
    """Return effective lane targets, applying any env-var overrides.

    Each lane can be overridden via:
        RUBRICAI_CRITICAL_DAYS, RUBRICAI_HIGH_DAYS,
        RUBRICAI_MEDIUM_DAYS, RUBRICAI_LOW_DAYS

    Set a lane to an integer (days) for a fixed SLA, or to "patch_train"
    to remove the fixed SLA and route to the patch cycle.
    """
    return {
        "critical": _parse_days("RUBRICAI_CRITICAL_DAYS", LANE_TARGETS["critical"]),
        "high": _parse_days("RUBRICAI_HIGH_DAYS", LANE_TARGETS["high"]),
        "medium": _parse_days("RUBRICAI_MEDIUM_DAYS", LANE_TARGETS["medium"]),
        "low": _parse_days("RUBRICAI_LOW_DAYS", LANE_TARGETS["low"]),
    }
