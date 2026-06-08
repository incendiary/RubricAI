"""Derive Finding context from CVE intel.

Maps CVSS vector fields and CVE description keywords to Finding schema fields
so the interview can present pre-populated answers for engineer confirmation
rather than asking security questions they may not be able to answer.
"""

from __future__ import annotations

import re

from .schemas.intel import IntelResult

# CVSS vector component → human labels
_AV_LABELS = {
    "N": "Network-accessible (remote exploit)",
    "A": "Adjacent network (local segment, e.g. VPN, LAN)",
    "L": "Local access required",
    "P": "Physical access required",
}
_PR_MAP = {"N": "none", "L": "low", "H": "high"}
_AC_MAP = {"L": "low", "H": "high"}

# Description keyword patterns → attacker_utility types
# Ordered by specificity — first match wins for primary type
_UTILITY_PATTERNS: list[tuple[str, str]] = [
    (r"remote\s+code\s+exec|arbitrary\s+code|command\s+inject|os\s+command", "rce"),
    (
        r"auth(?:entication)?\s+bypass|bypass\s+auth|without\s+auth|unauthenticated",
        "auth_bypass",
    ),
    (
        r"privilege\s+escal|elevat(?:e|ion)\s+of\s+privil|gain\s+root|become\s+root",
        "priv_esc",
    ),
    (
        r"information\s+disclos|sensitive\s+(?:data|info|file)|read\s+arb|exfiltrat",
        "data_access",
    ),
    (r"denial.of.service|dos\b|crash|exhaust\s+(?:memory|cpu|resource)", "dos"),
    (r"modify|tamper|overwrite|inject\s+(?:data|content)|falsif", "tampering"),
    (r"lateral\s+movement|pivot|move\s+(?:laterally|to\s+other)", "lateral_movement"),
]


def _parse_cvss_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS vector string into a component dict.

    Handles both v2 and v3+ formats. Returns empty dict on parse failure.
    """
    parts: dict[str, str] = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k] = v
    return parts


def _infer_utility_from_description(description: str) -> list[str]:
    """Scan description text for exploitation impact keywords."""
    text = description.lower()
    found: list[str] = []
    for pattern, utility in _UTILITY_PATTERNS:
        if re.search(pattern, text):
            found.append(utility)
    return found or ["other"]


def _infer_utility_from_cvss(components: dict[str, str]) -> list[str]:
    """Fall back to CVSS C/I/A impact when no description is available."""
    utility: list[str] = []
    c = components.get("C", components.get("VC", "N"))
    i = components.get("I", components.get("VI", "N"))
    a = components.get("A", components.get("VA", "N"))
    if c == "H":
        utility.append("data_access")
    if i == "H":
        utility.append("tampering")
    if a == "H":
        utility.append("dos")
    return utility or ["other"]


def derive_finding_context(intel: IntelResult) -> dict:
    """Derive Finding fields from CVE intel for engineer confirmation.

    Returns a dict with pre-populated field suggestions and a confidence label.
    The AI should present these to the engineer and ask for confirmation or
    correction — not treat them as final.

    Keys:
        attacker_utility   list[str]  — derived utility types
        entry_point        dict       — protocol/description hint from CVSS AV
        preconditions      dict       — AC, PR, UI from CVSS vector
        confidence         str        — "cvss+description", "cvss_only", or "none"
        description        str | None — full CVE description for context
    """
    vector_components: dict[str, str] = {}
    if intel.cvss and intel.cvss.vector:
        vector_components = _parse_cvss_vector(intel.cvss.vector)

    # Attacker utility: prefer description keywords, fall back to CVSS impacts
    if intel.description:
        attacker_utility = _infer_utility_from_description(intel.description)
        confidence = "cvss+description" if vector_components else "description_only"
    elif vector_components:
        attacker_utility = _infer_utility_from_cvss(vector_components)
        confidence = "cvss_only"
    else:
        attacker_utility = ["other"]
        confidence = "none"

    # Entry point hint from CVSS Attack Vector
    # cvss_av is surfaced at the top level (not nested in entry_point) so that
    # entry_point can be passed directly to Finding.entry_point without violating
    # its extra="forbid" constraint.
    av = vector_components.get("AV")
    entry_point = {
        "description": _AV_LABELS.get(av, "Unknown — check CVE description"),
    }

    # Preconditions from CVSS
    pr = vector_components.get("PR")
    ac = vector_components.get("AC")
    ui = vector_components.get("UI")
    preconditions = {
        "privileges_required": _PR_MAP.get(pr) if pr else None,
        "attack_complexity": _AC_MAP.get(ac) if ac else None,
        "user_interaction": ui == "R" if ui else None,
    }

    return {
        "attacker_utility": attacker_utility,
        "entry_point": entry_point,
        "cvss_av": av,  # top-level context annotation; not a Finding field
        "preconditions": preconditions,
        "confidence": confidence,
        "description": intel.description,
    }
