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

# Remediation target windows in days
LANE_TARGETS: dict[str, int] = {
    "critical": 3,  # 72 hours
    "high": 7,
    "medium": 30,
    "low": 120,  # patch train default; max is 240
}

LANE_BASES: dict[str, str] = {
    "critical": "kev_listed + internet_exposed + high_utility",
    "high": "internet_exposed + high_epss_or_poc + high_utility",
    "medium": "constrained_or_internal_reachability_or_lower_impact",
    "low": "low_utility_and_reachability_or_strong_mitigations",
}
