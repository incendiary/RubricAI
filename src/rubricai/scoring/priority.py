"""RubricAI Priority Score (RPS).

Additive 0–10 score across all contextual signals. CVSS base is one weighted
input (max 40% contribution); the remaining 60% comes from environment-specific
signals collected during the engineer interview.

Purpose: differentiate within a lane. Two Critical findings both carry a 72-hour
SLA; the Priority Score tells you which to patch first.

Formula:
    priority_score = clamp(
        cvss_base * 0.4           # 0–4.0  (intrinsic severity input)
      + reachability_points        # internet=2.5, constrained=1.5, internal=0.5, local=0
      + intel_points               # kev=1.5; epss>=0.5=+1.0, epss>=0.1=+0.5 (additive)
      + utility_bonus              # high_utility=+0.5
      - mitigation_penalty         # strong=1.5, partial=0.5, none=0
    , 0.0, 10.0)
"""

from __future__ import annotations

from ..schemas.finding import Finding
from ..schemas.intel import IntelResult

# Mirrored from policy.definitions — kept here to avoid circular imports
# (scoring module must not depend on policy module)
_HIGH_UTILITY_TYPES = frozenset({"rce", "auth_bypass", "priv_esc", "data_access"})
_STRONG_MITIGATION_TYPES = frozenset(
    {"waf_rule", "acl_segmentation", "disable_feature", "vendor_workaround", "virtual_patching"}
)
_EPSS_HIGH_THRESHOLD = 0.5
_EPSS_MID_THRESHOLD = 0.1

_REACHABILITY_POINTS: dict[str, float] = {
    "internet_exposed": 2.5,
    "constrained_external": 1.5,
    "internal": 0.5,
    "local_only": 0.0,
}

def compute_priority_score(
    finding: Finding,
    intel: IntelResult,
) -> tuple[float, dict]:
    """Compute the RubricAI Priority Score.

    Args:
        finding: Engineer-provided finding context.
        intel: Public intel result (KEV, EPSS, CVSS).

    Returns:
        ``(score, breakdown)`` where ``score`` is 0.0–10.0 and
        ``breakdown`` is a dict of each component's contribution.
    """
    # --- Component: CVSS base (input factor, not output) ---
    cvss_component = 0.0
    if intel.cvss is not None and intel.cvss.base is not None:
        cvss_component = round(intel.cvss.base * 0.4, 2)

    # --- Component: reachability ---
    reachability_pts = _REACHABILITY_POINTS.get(finding.reachability, 0.0)

    # --- Component: intel signals (additive) ---
    intel_pts = 0.0
    kev_listed = intel.kev is not None and intel.kev.listed
    if kev_listed:
        intel_pts += 1.5
    if intel.epss is not None:
        if intel.epss.score >= _EPSS_HIGH_THRESHOLD:
            intel_pts += 1.0
        elif intel.epss.score >= _EPSS_MID_THRESHOLD:
            intel_pts += 0.5

    # --- Component: utility bonus ---
    utility = list(finding.attacker_utility)
    utility_bonus = 0.5 if bool(set(utility) & _HIGH_UTILITY_TYPES) else 0.0

    # --- Component: mitigation penalty ---
    mitigations = finding.mitigations
    penalty = 0.0
    if mitigations:
        has_strong = any(
            m.type in _STRONG_MITIGATION_TYPES and m.causal_claim for m in mitigations
        )
        penalty = 1.5 if has_strong else 0.5

    raw = cvss_component + reachability_pts + intel_pts + utility_bonus - penalty
    score = round(max(0.0, min(10.0, raw)), 1)

    breakdown = {
        "cvss": cvss_component,
        "reachability": reachability_pts,
        "intel": round(intel_pts, 1),
        "utility": utility_bonus,
        "mitigation_penalty": -penalty,
        "total": score,
    }

    return score, breakdown
