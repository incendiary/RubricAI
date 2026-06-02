from ..schemas.assessment import Assessment, RemediationTarget, ScoreBreakdown
from ..schemas.finding import Finding, Mitigation
from ..schemas.intel import IntelResult
from .definitions import (
    EPSS_HIGH_THRESHOLD,
    HIGH_UTILITY_TYPES,
    LANE_BASES,
    LANE_TARGETS,
    POLICY_VERSION,
    STRONG_MITIGATION_TYPES,
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
    poc_available = intel.poc is not None and intel.poc.available

    intel_escalation: list[str] = []
    if kev_listed:
        intel_escalation.append("kev_listed")
    if epss_high:
        intel_escalation.append("epss_high")
    if poc_available:
        intel_escalation.append("poc_present")

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
        and (epss_high or poc_available)
        and high_utility
    ):
        lane = "high"
        rationale.append(
            "Internet-exposed with high exploitation likelihood signals (EPSS/PoC) and high attacker utility."
        )
        rationale.append(
            "Not on CISA KEV; external intel signals indicate high exploitation probability."
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
    if lane == "critical":
        actions.append(
            "Remediate within 72 hours or apply immediate compensating controls."
        )
    elif lane == "high":
        actions.append("Remediate within 7 days.")
    elif lane == "medium":
        actions.append("Remediate within 30 days.")
    else:
        actions.append("Schedule on next patch train (target 120 days, max 240 days).")

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

    return Assessment(
        policy_version=policy_version,
        lane=lane,
        target=RemediationTarget(
            days=LANE_TARGETS[lane],
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
    )
