"""EPSS v5 scoring policy — EPSS probability as the primary lane driver.

EPSS v5 (released 2026-06-15) delivers a 23% improvement over v4. The same
api.first.org/data/v1/epss endpoint is used; no fetcher changes are needed.

Policy differences from chml-v0.2:
- EPSS score drives lane assignment directly; reachability is a modifier, not a gate.
- KEV escalates internet-exposed findings to High even when EPSS is below threshold.
- Medium lane has an explicit 30-day SLA (vs. patch train in chml-v0.2).
"""

from ..schemas.assessment import Assessment, RemediationTarget, ScoreBreakdown
from ..schemas.finding import Finding, Mitigation
from ..schemas.intel import IntelResult
from ..scoring.priority import compute_priority_score
from .definitions import (
    EPSS_V5_CRITICAL_THRESHOLD,
    EPSS_V5_HIGH_THRESHOLD,
    EPSS_V5_LANE_BASES,
    EPSS_V5_LANE_TARGETS,
    EPSS_V5_MEDIUM_THRESHOLD,
    STRONG_MITIGATION_TYPES,
)


def _mitigation_effect(mitigations: list[Mitigation]) -> str:
    if not mitigations:
        return "none"
    strong = any(
        m.type in STRONG_MITIGATION_TYPES and m.causal_claim for m in mitigations
    )
    return "strong" if strong else "partial"


def evaluate(
    finding: Finding,
    intel: IntelResult,
    policy_version: str = "epss-v5",
) -> Assessment:
    mit_effect = _mitigation_effect(finding.mitigations)

    kev_listed = intel.kev is not None and intel.kev.listed
    epss_score = intel.epss.score if intel.epss is not None else None
    internet_exposed = finding.reachability == "internet_exposed"

    intel_escalation: list[str] = []
    if kev_listed:
        intel_escalation.append("kev_listed")
    if epss_score is not None and epss_score >= EPSS_V5_HIGH_THRESHOLD:
        intel_escalation.append("epss_high")

    rationale: list[str] = []
    actions: list[str] = []
    evidence_gaps: list[str] = []

    # --- Lane determination ---

    if (
        epss_score is not None
        and epss_score >= EPSS_V5_CRITICAL_THRESHOLD
        and internet_exposed
    ):
        lane = "critical"
        rationale.append(
            f"EPSS score {epss_score:.3f} meets the critical threshold "
            f"({EPSS_V5_CRITICAL_THRESHOLD}) on an internet-exposed asset."
        )

    elif (epss_score is not None and epss_score >= EPSS_V5_HIGH_THRESHOLD) or (
        kev_listed and internet_exposed
    ):
        lane = "high"
        if epss_score is not None and epss_score >= EPSS_V5_HIGH_THRESHOLD:
            rationale.append(
                f"EPSS score {epss_score:.3f} exceeds the High threshold "
                f"({EPSS_V5_HIGH_THRESHOLD}) — elevated exploitation probability."
            )
        if kev_listed and internet_exposed:
            rationale.append(
                "CVE is on CISA KEV with an internet-exposed asset — KEV escalation."
            )

    elif epss_score is not None and epss_score >= EPSS_V5_MEDIUM_THRESHOLD:
        lane = "medium"
        rationale.append(
            f"EPSS score {epss_score:.3f} indicates moderate exploitation probability "
            f"(Medium threshold: {EPSS_V5_MEDIUM_THRESHOLD})."
        )

    elif epss_score is None and kev_listed:
        # No EPSS data — KEV without internet exposure goes to High conservatively
        lane = "high" if internet_exposed else "medium"
        rationale.append("No EPSS data available; KEV status used as primary signal.")

    else:
        lane = "low"
        score_str = f"{epss_score:.3f}" if epss_score is not None else "unavailable"
        rationale.append(
            f"EPSS score {score_str} is below the Medium threshold "
            f"({EPSS_V5_MEDIUM_THRESHOLD}) with no KEV escalation."
        )

    # Strong mitigations can shift Medium → Low (same guardrail as chml-v0.2)
    if lane == "medium" and mit_effect == "strong":
        lane = "low"
        rationale.append(
            "Strong exploit-relevant mitigations evidenced — downgraded from Medium to Low."
        )

    # --- Mitigation notes ---
    if mit_effect == "partial":
        rationale.append(
            "Mitigations are present but do not fully break the exploit chain."
        )
        actions.append(
            "Strengthen mitigations with causal claims or escalate to patching."
        )

    # --- Remediation action ---
    targets = EPSS_V5_LANE_TARGETS
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

    priority_score, priority_breakdown = compute_priority_score(finding, intel)

    return Assessment(
        policy_version=policy_version,
        lane=lane,
        target=RemediationTarget(
            days=targets[lane],
            basis=EPSS_V5_LANE_BASES[lane],
        ),
        score_breakdown=ScoreBreakdown(
            intel_escalation=intel_escalation,
            reachability=finding.reachability,
            utility="high" if bool(finding.attacker_utility) else "low",
            mitigation_effect=mit_effect,
        ),
        rationale=rationale,
        actions=actions,
        evidence_gaps=evidence_gaps,
        priority_score=priority_score,
        priority_score_breakdown=priority_breakdown,
    )
