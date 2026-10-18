"""Display helpers and the report lines that use them."""

import pytest

from rubricai.formatting import fmt_epss
from rubricai.tools.report import report_generate
from rubricai.tools.scoring import score_evaluate

_FINDING = {
    "id": "FIND-001",
    "cve_or_id": "CVE-2024-3400",
    "component": {"name": "PAN-OS", "type": "appliance"},
    "entry_point": {"description": "GlobalProtect portal"},
    "reachability": "internet_exposed",
    "attacker_utility": ["rce"],
}
_INTEL = {
    "cve_or_id": "CVE-2024-3400",
    "retrieved_at": "2026-10-18T00:00:00Z",
    "sources": ["NVD", "FIRST_EPSS"],
    "epss": {"score": 0.99999, "percentile": 1.0},
}


@pytest.mark.parametrize(
    ("score", "digits", "expected"),
    [
        (0.99999, 3, "0.99999"),
        (0.99999, 4, "0.99999"),
        (0.9996, 3, "0.9996"),
        (0.85, 3, "0.850"),
        (0.85, 4, "0.8500"),
        (0.0, 3, "0.000"),
        (1.0, 3, "1.000"),
    ],
)
def test_fmt_epss(score, digits, expected):
    assert fmt_epss(score, digits) == expected


def _markdown(finding):
    assessment = score_evaluate(finding, _INTEL)
    return report_generate(finding, _INTEL, assessment, formats=["markdown"])[
        "report_markdown"
    ]


def test_report_never_prints_a_sub_one_epss_as_1_000():
    text = _markdown(_FINDING)
    assert "| EPSS score | 0.99999 (100th percentile) |" in text
    assert "0.99999 (100th pct)" in text
    assert "1.000" not in text
    assert "1.0000" not in text


def test_priority_line_shows_a_sign_for_the_mitigation_term():
    assert "+ 0.0 (mitigation)" in _markdown(_FINDING)
    partial = {
        **_FINDING,
        "mitigations": [{"type": "other", "description": "Monitoring added."}],
    }
    assert "- 0.5 (mitigation)" in _markdown(partial)
