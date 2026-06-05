"""Tests for CVSS v3.1 Environmental Score computation."""

from datetime import UTC, datetime

import pytest

from src.rubricai.scoring.environmental import compute_environmental_score
from src.rubricai.schemas.finding import Finding
from src.rubricai.schemas.intel import CvssInfo, EpssInfo, IntelResult

_VECTOR_HIGH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # base 8.8
_VECTOR_MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # base 5.3


def _make_intel(vector: str | None = _VECTOR_HIGH, base: float = 8.8) -> IntelResult:
    return IntelResult(
        cve_or_id="CVE-2024-9999",
        retrieved_at=datetime.now(tz=UTC),
        sources=["NVD"],
        cvss=CvssInfo(base=base, version="3.1", vector=vector) if base else None,
        epss=EpssInfo(score=0.1, percentile=0.5),
    )


def _make_finding(
    reachability: str = "internet_exposed",
    utility: list[str] | None = None,
    data_impact_notes: str | None = None,
) -> Finding:
    data = {
        "id": "FIND-001",
        "cve_or_id": "CVE-2024-9999",
        "component": {"name": "TestLib", "version": "2.0"},
        "entry_point": {"description": "TCP/5432"},
        "reachability": reachability,
        "attacker_utility": utility or ["rce"],
    }
    if data_impact_notes:
        data["data_impact"] = {"notes": data_impact_notes}
    return Finding.model_validate(data)


class TestEnvironmentalScoreReachability:
    def test_internet_exposed_preserves_base_av(self):
        # internet_exposed: no MAV modifier — environmental score ≈ base score
        result = compute_environmental_score(
            _make_finding(reachability="internet_exposed"),
            _make_intel(),
        )
        assert result is not None
        score, severity, basis = result
        assert score == 8.8
        assert basis == "cvss_v3_environmental"

    def test_internal_reduces_score_via_mav_adjacent(self):
        # internal: MAV:A applied — Adjacent is less severe than Network (AV:N)
        result_internal = compute_environmental_score(
            _make_finding(reachability="internal"),
            _make_intel(),
        )
        result_internet = compute_environmental_score(
            _make_finding(reachability="internet_exposed"),
            _make_intel(),
        )
        assert result_internal is not None and result_internet is not None
        assert result_internal[0] < result_internet[0]

    def test_constrained_external_reduces_score(self):
        result = compute_environmental_score(
            _make_finding(reachability="constrained_external"),
            _make_intel(),
        )
        assert result is not None
        assert result[0] < 8.8  # MAV:A applied

    def test_local_only_reduces_score_further(self):
        result_local = compute_environmental_score(
            _make_finding(reachability="local_only"),
            _make_intel(),
        )
        result_internal = compute_environmental_score(
            _make_finding(reachability="internal"),
            _make_intel(),
        )
        assert result_local is not None and result_internal is not None
        # MAV:L ≤ MAV:A in most cases
        assert result_local[0] <= result_internal[0]


class TestEnvironmentalScoreUtility:
    def test_data_access_raises_cr_high(self):
        # CR:H increases score when confidentiality is critical to the org
        result_da = compute_environmental_score(
            _make_finding(utility=["data_access"]),
            _make_intel(vector=_VECTOR_MED, base=5.3),
        )
        result_base = compute_environmental_score(
            _make_finding(utility=["dos"]),
            _make_intel(vector=_VECTOR_MED, base=5.3),
        )
        assert result_da is not None and result_base is not None
        assert result_da[0] >= result_base[0]

    def test_pii_in_data_impact_notes_raises_cr(self):
        result_pii = compute_environmental_score(
            _make_finding(utility=["rce"], data_impact_notes="Component accesses PII database"),
            _make_intel(vector=_VECTOR_MED, base=5.3),
        )
        result_no_pii = compute_environmental_score(
            _make_finding(utility=["rce"]),
            _make_intel(vector=_VECTOR_MED, base=5.3),
        )
        assert result_pii is not None and result_no_pii is not None
        assert result_pii[0] >= result_no_pii[0]

    def test_basis_is_cvss_v3_environmental(self):
        result = compute_environmental_score(_make_finding(), _make_intel())
        assert result is not None
        assert result[2] == "cvss_v3_environmental"


class TestEnvironmentalScoreFallbacks:
    def test_returns_none_when_no_cvss(self):
        intel_no_cvss = IntelResult(
            cve_or_id="CVE-2024-9999",
            retrieved_at=datetime.now(tz=UTC),
            sources=["NVD"],
        )
        result = compute_environmental_score(_make_finding(), intel_no_cvss)
        assert result is None

    def test_falls_back_to_base_when_no_vector(self):
        intel_no_vector = _make_intel(vector=None, base=7.5)
        result = compute_environmental_score(_make_finding(), intel_no_vector)
        assert result is not None
        score, severity, basis = result
        assert score == 7.5
        assert basis == "cvss_v3_base"

    def test_severity_label_correct_for_base_fallback(self):
        intel_critical = _make_intel(vector=None, base=9.8)
        result = compute_environmental_score(_make_finding(), intel_critical)
        assert result is not None
        assert result[1] == "Critical"

        intel_medium = _make_intel(vector=None, base=5.0)
        result2 = compute_environmental_score(_make_finding(), intel_medium)
        assert result2 is not None
        assert result2[1] == "Medium"


class TestEnvironmentalScoreInAssessment:
    def test_score_evaluate_populates_numeric_score(self):
        from src.rubricai.tools.scoring import score_evaluate

        finding = {
            "id": "FIND-ENV-001",
            "cve_or_id": "CVE-2024-9999",
            "component": {"name": "TestLib", "version": "2.0"},
            "entry_point": {"description": "TCP/443"},
            "reachability": "internet_exposed",
            "attacker_utility": ["rce"],
        }
        intel = {
            "cve_or_id": "CVE-2024-9999",
            "retrieved_at": datetime.now(tz=UTC).isoformat(),
            "sources": ["NVD"],
            "cvss": {
                "base": 8.8,
                "version": "3.1",
                "vector": _VECTOR_HIGH,
            },
        }
        result = score_evaluate(finding, intel)
        assert result["numeric_score"] == 8.8
        assert result["numeric_score_basis"] == "cvss_v3_environmental"

    def test_score_evaluate_numeric_score_none_without_cvss(self):
        from src.rubricai.tools.scoring import score_evaluate

        finding = {
            "id": "FIND-ENV-002",
            "cve_or_id": "CVE-2024-0000",
            "component": {"name": "TestLib", "version": "1.0"},
            "entry_point": {"description": "TCP/80"},
            "reachability": "internal",
            "attacker_utility": ["dos"],
        }
        intel = {
            "cve_or_id": "CVE-2024-0000",
            "retrieved_at": datetime.now(tz=UTC).isoformat(),
            "sources": ["NVD"],
        }
        result = score_evaluate(finding, intel)
        assert result["numeric_score"] is None
        assert result["numeric_score_basis"] is None
