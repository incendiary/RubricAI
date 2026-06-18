"""BOD 26-04 scoring policy — CISA Binding Operational Directive, issued 2026-06-10.

Replaces CVSS-centric prioritisation with 4 binary signals evaluated per
vulnerability per asset. Signal count maps to 4 remediation bands.

Signals:
    internet_exposed   - Is the affected asset reachable from the internet?
    kev_listed         - Is the CVE on CISA's Known Exploited Vulnerabilities list?
    automatable        - Can an adversary automate the full exploitation chain?
                         Sourced from CISA Vulnrichment or derived from CVSS vector.
    technical_impact   - Does exploitation yield total control (vs partial)?
                         Derived from CVSS scope + confidentiality/integrity impact.

Remediation bands (Table 1 approximation):
    4 signals → Critical — 3 calendar days + mandatory forensic triage
    3 signals → High     — 14 calendar days
    2 signals → Medium   — 60 calendar days
    0–1 signals → Low    — fix at next scheduled major system upgrade

Finding.automatable overrides the intel-derived value when provided by the engineer.
"""

from ..schemas.assessment import Assessment, RemediationTarget, ScoreBreakdown
from ..schemas.finding import Finding, Mitigation
from ..schemas.intel import IntelResult
from ..scoring.priority import compute_priority_score
from .definitions import (
    BOD_26_04_LANE_BASES,
    BOD_26_04_LANE_TARGETS,
    STRONG_MITIGATION_TYPES,
)


def _mitigation_effect(mitigations: list[Mitigation]) -> str:
    if not mitigations:
        return "none"
    strong = any(
        m.type in STRONG_MITIGATION_TYPES and m.causal_claim for m in mitigations
    )
    return "strong" if strong else "partial"


def _resolve_automatable(finding: Finding, intel: IntelResult) -> bool | None:
    """Finding override takes precedence over intel-derived value."""
    if finding.automatable is not None:
        return finding.automatable
    return intel.automatable


def _resolve_technical_impact(intel: IntelResult) -> bool:
    """True = total control; False = partial. Derived from CVSS; defaults to partial."""
    if intel.cvss and intel.cvss.vector:
        # Re-derive from vector string stored on the CvssInfo object
        vector = intel.cvss.vector
        scope_changed = "S:C" in vector
        conf_high = "C:H" in vector
        integ_high = "I:H" in vector
        return scope_changed or (conf_high and integ_high)
    return False  # conservative default: partial impact


def evaluate(
    finding: Finding,
    intel: IntelResult,
    policy_version: str = "bod-26-04",
) -> Assessment:
    mit_effect = _mitigation_effect(finding.mitigations)

    internet_exposed = finding.reachability == "internet_exposed"
    kev_listed = intel.kev is not None and intel.kev.listed
    automatable = _resolve_automatable(finding, intel)
    total_impact = _resolve_technical_impact(intel)

    # BOD 26-04 signal count (unknown automatable is treated as False conservatively)
    auto_bool = bool(automatable)  # None → False
    signal_count = sum([internet_exposed, kev_listed, auto_bool, total_impact])

    intel_escalation: list[str] = []
    if kev_listed:
        intel_escalation.append("kev_listed")
    if internet_exposed:
        intel_escalation.append("internet_exposed")
    if auto_bool:
        intel_escalation.append("automatable")
    if total_impact:
        intel_escalation.append("total_impact")

    rationale: list[str] = []
    actions: list[str] = []
    evidence_gaps: list[str] = []

    # --- Lane determination ---
    if signal_count >= 4:
        lane = "critical"
        rationale.append(
            "All 4 BOD 26-04 signals active: internet-exposed, KEV-listed, "
            "automatable exploitation, and total technical impact."
        )
        actions.append(
            "Initiate forensic triage to determine whether affected systems "
            "may already be compromised (BOD 26-04 requirement)."
        )
    elif signal_count == 3:
        lane = "high"
        active = [
            s
            for s, v in [
                ("internet_exposed", internet_exposed),
                ("kev_listed", kev_listed),
                ("automatable", auto_bool),
                ("total_impact", total_impact),
            ]
            if v
        ]
        rationale.append(f"3 of 4 BOD 26-04 signals active: {', '.join(active)}.")
    elif signal_count == 2:
        lane = "medium"
        rationale.append("2 of 4 BOD 26-04 signals active — moderate risk.")
    else:
        lane = "low"
        rationale.append(
            f"{'1' if signal_count == 1 else 'No'} BOD 26-04 signal(s) active — "
            "schedule remediation at next major system upgrade cycle."
        )

    # --- Signal transparency ---
    if not internet_exposed:
        rationale.append("Asset is not internet-exposed — reduces BOD 26-04 score.")
    if not kev_listed:
        rationale.append(
            "CVE is not on CISA KEV — no confirmed exploitation in the wild."
        )
    if automatable is None:
        evidence_gaps.append(
            "automatable signal is unknown — Vulnrichment data absent and CVSS "
            "vector unavailable. Confirm with the engineer whether exploitation "
            "can be fully automated."
        )
    elif not auto_bool:
        rationale.append("Exploitation is not fully automatable.")
    if not total_impact:
        rationale.append("Technical impact is partial (not total system control).")

    # --- Mitigation notes ---
    if mit_effect == "partial":
        rationale.append(
            "Mitigations are present but do not fully break the exploit chain."
        )
        actions.append(
            "Strengthen mitigations with causal claims or escalate to patching."
        )

    # --- Remediation action ---
    targets = BOD_26_04_LANE_TARGETS
    target_days = targets[lane]
    if target_days is None:
        actions.append("Schedule remediation at next major system upgrade cycle.")
    elif lane == "critical":
        actions.append(
            f"Remediate within {target_days * 24} hours per BOD 26-04 mandate."
        )
    else:
        actions.append(f"Remediate within {target_days} days per BOD 26-04.")

    # --- Evidence gaps for escalated lanes ---
    if lane in ("critical", "high") and not finding.mitigations:
        evidence_gaps.append(
            "No mitigations documented — patch or apply compensating controls immediately."
        )

    priority_score, priority_breakdown = compute_priority_score(finding, intel)

    return Assessment(
        policy_version=policy_version,
        lane=lane,
        target=RemediationTarget(
            days=targets[lane],
            basis=BOD_26_04_LANE_BASES[lane],
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
