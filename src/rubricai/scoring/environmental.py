"""CVSS v3.1 Environmental Score computation.

Derives a context-aware numeric score (0–10) by applying environmental
modifiers — sourced from the engineer interview — to the base CVSS vector
fetched from NVD. This is a standard FIRST/NIST metric designed specifically
for "what does this CVE score in my environment."

The CHML lane (Critical/High/Medium/Low) remains the actionable output.
The Environmental Score is the numeric representation for auditors,
dashboards, and cross-finding comparisons.
"""

from __future__ import annotations

from cvss import CVSS3

from ..schemas.finding import Finding
from ..schemas.intel import IntelResult

_PII_KEYWORDS = frozenset(
    {"pii", "personal", "credential", "password", "token", "payment", "card", "ssn"}
)

# CVSS severity label → (low, high) inclusive range
_SEVERITY_RANGES = {
    "None": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}


def _severity_label(score: float) -> str:
    for label, (lo, hi) in _SEVERITY_RANGES.items():
        if lo <= score <= hi:
            return label
    return "None"


def _build_env_modifiers(finding: Finding) -> list[str]:
    """Map interview fields to CVSS environmental metric tokens."""
    modifiers: list[str] = []

    # Modified Attack Vector — reflects actual reachability in this environment
    if finding.reachability in ("constrained_external", "internal"):
        modifiers.append("MAV:A")  # Adjacent: network-reachable but not from internet
    elif finding.reachability == "local_only":
        modifiers.append("MAV:L")  # Local: requires machine access
    # internet_exposed: leave as Not Defined (preserves base AV)

    utility = list(finding.attacker_utility)

    # Confidentiality Requirement — high if data access utility or PII mentioned
    if "data_access" in utility:
        modifiers.append("CR:H")
    elif finding.data_impact and finding.data_impact.notes:
        notes_lower = finding.data_impact.notes.lower()
        if any(kw in notes_lower for kw in _PII_KEYWORDS):
            modifiers.append("CR:H")

    # Integrity Requirement — high if tampering utility present
    if "tampering" in utility:
        modifiers.append("IR:H")

    # Availability Requirement — high if DoS utility present
    if "dos" in utility:
        modifiers.append("AR:H")

    return modifiers


def compute_environmental_score(
    finding: Finding,
    intel: IntelResult,
) -> tuple[float, str, str] | None:
    """Compute CVSS v3.1 Environmental Score for this finding in this environment.

    Args:
        finding: Engineer-provided finding context.
        intel: Public intel result containing the base CVSS vector.

    Returns:
        ``(score, severity, basis)`` tuple, where ``basis`` is one of:
        - ``"cvss_v3_environmental"`` — full environmental score computed
        - ``"cvss_v3_base"`` — no vector available, base score returned as-is
        Returns ``None`` if no CVSS data is available at all.
    """
    if intel.cvss is None:
        return None

    # Prefer full environmental computation if we have the vector
    if intel.cvss.vector:
        try:
            modifiers = _build_env_modifiers(finding)
            if modifiers:
                env_vector = intel.cvss.vector + "/" + "/".join(modifiers)
            else:
                env_vector = intel.cvss.vector
            c = CVSS3(env_vector)
            env_score = round(c.scores()[2], 1)
            env_severity = c.severities()[2]
            return (env_score, env_severity, "cvss_v3_environmental")
        except Exception:
            pass  # fall through to base score fallback

    # Fallback: base score only (no vector or parse error)
    if intel.cvss.base is not None:
        base = round(intel.cvss.base, 1)
        return (base, _severity_label(base), "cvss_v3_base")

    return None
