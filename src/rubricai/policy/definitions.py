import os

POLICY_VERSION = "chml-v0.2"
EPSS_V5_POLICY_VERSION = "epss-v5"

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
        "vendor_patch",
        "virtual_patching",
    }
)


def is_patched_and_verified(mitigations: list) -> bool:
    """Return True if a vendor_patch mitigation with a causal_claim exists.

    When True, all policies short-circuit to lane='low' with a Remediated rationale
    rather than running the normal signal-based lane decision tree.
    """
    return any(m.type == "vendor_patch" and bool(m.causal_claim) for m in mitigations)


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
    "high": "internet_exposed + high_utility_or_epss",
    "medium": "constrained_or_internal_reachability_or_lower_impact",
    "low": "low_utility_and_reachability_or_strong_mitigations",
}


# --- EPSS v5 policy thresholds (env-var overridable) ---
# EPSS is the primary lane driver; thresholds chosen based on v5 score distribution.
EPSS_V5_CRITICAL_THRESHOLD: float = float(
    os.getenv("RUBRICAI_EPSS_V5_CRITICAL_THRESHOLD", "0.7")
)
EPSS_V5_HIGH_THRESHOLD: float = float(
    os.getenv("RUBRICAI_EPSS_V5_HIGH_THRESHOLD", "0.4")
)
EPSS_V5_MEDIUM_THRESHOLD: float = float(
    os.getenv("RUBRICAI_EPSS_V5_MEDIUM_THRESHOLD", "0.1")
)

EPSS_V5_LANE_TARGETS: dict[str, int | None] = {
    "critical": 3,  # 72 hours
    "high": 7,
    "medium": 30,  # explicit SLA — EPSS-primary policy sets a fixed Medium window
    "low": None,  # patch train
}

EPSS_V5_LANE_BASES: dict[str, str] = {
    "critical": "epss_score>=0.7 + internet_exposed",
    "high": "epss_score>=0.4 or (kev_listed + internet_exposed)",
    "medium": "epss_score>=0.1",
    "low": "epss_score<0.1 and no_kev_internet_escalation",
}


# --- BOD 26-04 policy (CISA, issued 2026-06-10) ---
# 4 binary signals → 4 remediation bands; signal count drives lane assignment.
BOD_26_04_POLICY_VERSION = "bod-26-04"

BOD_26_04_LANE_TARGETS: dict[str, int | None] = {
    "critical": 3,  # All 4 signals — 72 hours + forensic triage
    "high": 14,  # 3 of 4 signals
    "medium": 60,  # 2 of 4 signals
    "low": None,  # 0–1 signals — fix at next scheduled upgrade
}

BOD_26_04_LANE_BASES: dict[str, str] = {
    "critical": "all_4_signals: internet_exposed + kev_listed + automatable + total_impact",
    "high": "3_of_4_signals",
    "medium": "2_of_4_signals",
    "low": "0_or_1_signals",
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
