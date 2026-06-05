from ..schemas.assessment import Assessment, RemediationTarget, ScoreBreakdown
from ..schemas.finding import Finding, Mitigation
from ..schemas.intel import IntelResult
from ..scoring.environmental import compute_environmental_score
from .definitions import (
    EPSS_HIGH_THRESHOLD,
    HIGH_UTILITY_TYPES,
    LANE_BASES,
    POLICY_VERSION,
    STRONG_MITIGATION_TYPES,
    get_lane_targets,
)


def _mitigation_effect(mitigations: list[Mitigation]) -> str:
    if not mitigations:
        return "none"
    strong = any(
        m.type in STRONG_MITIGATION_TYPES and m.causal_claim for m in mitigations
    )
    return "strong" if strong else "partial"


def _is_high_utility(attacker_utility: list[str]) -> bool:
    return bool(set(attacker_utility) & HIGH_UTILITY_TYPES)


def evaluate(
    finding: Finding,
    intel: IntelResult,
    policy_version: str = POLICY_VERSION,
) -> Assessment:
    mit_effect = _mitigation_effect(finding.mitigations)
    high_utility = _is_high_utility(list(finding.attacker_utility))

    kev_listed = intel.kev is not None and intel.kev.listed
    epss_high = intel.epss is not None and intel.epss.score >= EPSS_HIGH_THRESHOLD

    intel_escalation: list[str] = []
    if kev_listed:
        intel_escalation.append("kev_listed")
    if epss_high:
        intel_escalation.append("epss_high")

    rationale: list[str] = []
    actions: list[str] = []
    evidence_gaps: list[str] = []

    # --- Lane determination (evaluated top-to-bottom; first match wins) ---

    if kev_listed and finding.reachability == "internet_exposed" and high_utility:
        lane = "critical"
        rationale.append(
            "CVE is on CISA KEV with an internet-exposed exploit path and high attacker utility."
        )

    elif (
        not kev_listed
        and finding.reachability == "internet_exposed"
        and (high_utility or epss_high)
        and mit_effect != "strong"
    ):
        lane = "high"
        if high_utility:
            rationale.append(
                "Internet-exposed with high attacker utility (RCE / auth bypass / priv-esc / data access)."
            )
        if epss_high:
            rationale.append(
                "High EPSS score indicates elevated exploitation probability in the wild."
            )

    elif finding.reachability == "local_only" and not high_utility:
        # local_only + low utility is the clearest Low case; check before medium
        lane = "low"
        rationale.append(
            "Local-only reachability combined with low attacker utility — patch train eligible."
        )

    elif (
        finding.reachability in ("constrained_external", "internal")
        or not high_utility
        or mit_effect == "strong"
    ):
        lane = "medium"
        if finding.reachability in ("constrained_external", "internal"):
            rationale.append(
                f"Reachability is '{finding.reachability}'; constrained attack surface reduces urgency."
            )
        if not high_utility:
            rationale.append(
                "Attacker utility does not include high-impact primitives "
                "(RCE / auth bypass / priv-esc / data access)."
            )
        if mit_effect == "strong":
            rationale.append(
                "Strong exploit-relevant mitigations evidenced with causal claims."
            )

    else:
        lane = "low"
        rationale.append(
            "Low attacker utility and/or low reachability with no escalating intel signals."
        )

    # --- Mitigation notes (applied after lane, not to change it here) ---
    if mit_effect == "partial":
        rationale.append(
            "Mitigations are present but do not fully break the exploit chain."
        )
        actions.append(
            "Strengthen mitigations with causal claims or escalate to patching."
        )

    # --- Remediation action ---
    targets = get_lane_targets()
    target_days = targets[lane]
    if target_days is None:
        actions.append("Schedule on next patch train.")
    elif lane == "critical":
        actions.append(
            f"Remediate within {target_days * 24} hours or apply immediate compensating controls."
        )
    else:
        actions.append(f"Remediate within {target_days} days.")

    # --- Evidence gaps ---
    if lane in ("critical", "high"):
        if not finding.mitigations:
            evidence_gaps.append(
                "No mitigations documented — patch or apply compensating controls immediately."
            )
        else:
            for m in finding.mitigations:
                if not m.causal_claim:
                    evidence_gaps.append(
                        f"Mitigation '{m.type}' lacks a causal_claim — "
                        "confirm it breaks the exploit chain."
                    )
                if not m.evidence:
                    evidence_gaps.append(
                        f"Mitigation '{m.type}' has no evidence pointers."
                    )

    if kev_listed and mit_effect in ("partial", "none") and lane == "critical":
        evidence_gaps.append(
            "KEV-listed CVE with no strong mitigations — patch is the only safe resolution."
        )

    env_result = compute_environmental_score(finding, intel)
    numeric_score = env_result[0] if env_result else None
    numeric_score_basis = env_result[2] if env_result else None

    return Assessment(
        policy_version=policy_version,
        lane=lane,
        target=RemediationTarget(
            days=targets[lane],
            basis=LANE_BASES[lane],
        ),
        score_breakdown=ScoreBreakdown(
            intel_escalation=intel_escalation,
            reachability=finding.reachability,
            utility="high" if high_utility else "low",
            mitigation_effect=mit_effect,
        ),
        rationale=rationale,
        actions=actions,
        evidence_gaps=evidence_gaps,
        numeric_score=numeric_score,
        numeric_score_basis=numeric_score_basis,
    )
