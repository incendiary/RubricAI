"""Tests for the RubricAI Priority Score (RPS)."""

from datetime import UTC, datetime

from src.rubricai.scoring.priority import compute_priority_score
from src.rubricai.schemas.finding import Finding
from src.rubricai.schemas.intel import CvssInfo, EpssInfo, IntelResult, KevInfo


def _make_intel(
    cvss_base: float | None = 8.8,
    epss: float = 0.05,
    kev_listed: bool = False,
) -> IntelResult:
    return IntelResult(
        cve_or_id="CVE-2024-9999",
        retrieved_at=datetime.now(tz=UTC),
        sources=["NVD"],
        cvss=CvssInfo(base=cvss_base, version="3.1") if cvss_base else None,
        epss=EpssInfo(score=epss, percentile=0.5),
        kev=KevInfo(listed=True) if kev_listed else None,
    )


def _make_finding(
    reachability: str = "internet_exposed",
    utility: list[str] | None = None,
    mitigations: list[dict] | None = None,
) -> Finding:
    return Finding.model_validate(
        {
            "id": "FIND-001",
            "cve_or_id": "CVE-2024-9999",
            "component": {"name": "TestLib", "version": "2.0"},
            "entry_point": {"description": "TCP/443"},
            "reachability": reachability,
            "attacker_utility": utility or ["rce"],
            "mitigations": mitigations or [],
        }
    )


class TestPriorityScoreReachability:
    def test_internet_exposed_higher_than_internal(self):
        score_internet, _ = compute_priority_score(
            _make_finding(reachability="internet_exposed"), _make_intel()
        )
        score_internal, _ = compute_priority_score(
            _make_finding(reachability="internal"), _make_intel()
        )
        assert score_internet > score_internal

    def test_internal_higher_than_local(self):
        score_internal, _ = compute_priority_score(
            _make_finding(reachability="internal"), _make_intel()
        )
        score_local, _ = compute_priority_score(
            _make_finding(reachability="local_only"), _make_intel()
        )
        assert score_internal > score_local

    def test_reachability_component_in_breakdown(self):
        _, bd = compute_priority_score(
            _make_finding(reachability="internet_exposed"), _make_intel()
        )
        assert bd["reachability"] == 2.5

        _, bd2 = compute_priority_score(
            _make_finding(reachability="internal"), _make_intel()
        )
        assert bd2["reachability"] == 0.5


class TestPriorityScoreIntelSignals:
    def test_kev_raises_score(self):
        score_kev, _ = compute_priority_score(
            _make_finding(), _make_intel(kev_listed=True)
        )
        score_no_kev, _ = compute_priority_score(
            _make_finding(), _make_intel(kev_listed=False)
        )
        assert score_kev > score_no_kev

    def test_high_epss_raises_score(self):
        score_high, _ = compute_priority_score(_make_finding(), _make_intel(epss=0.75))
        score_low, _ = compute_priority_score(_make_finding(), _make_intel(epss=0.05))
        assert score_high > score_low

    def test_kev_and_epss_are_additive(self):
        _, bd_kev_only = compute_priority_score(
            _make_finding(), _make_intel(kev_listed=True, epss=0.05)
        )
        _, bd_kev_epss = compute_priority_score(
            _make_finding(), _make_intel(kev_listed=True, epss=0.75)
        )
        assert bd_kev_epss["intel"] > bd_kev_only["intel"]


class TestPriorityScoreMitigations:
    def test_strong_mitigation_reduces_score(self):
        score_no_mit, _ = compute_priority_score(_make_finding(), _make_intel())
        score_strong, _ = compute_priority_score(
            _make_finding(
                mitigations=[
                    {
                        "type": "waf_rule",
                        "description": "Blocks exploit route",
                        "causal_claim": "Rule blocks the vulnerable endpoint",
                        "evidence": ["WAF-123"],
                    }
                ]
            ),
            _make_intel(),
        )
        assert score_strong < score_no_mit
        _, bd = compute_priority_score(
            _make_finding(
                mitigations=[
                    {
                        "type": "waf_rule",
                        "description": "x",
                        "causal_claim": "blocks it",
                        "evidence": ["WAF-1"],
                    }
                ]
            ),
            _make_intel(),
        )
        assert bd["mitigation_penalty"] == -1.5

    def test_partial_mitigation_smaller_penalty(self):
        _, bd_partial = compute_priority_score(
            _make_finding(
                mitigations=[
                    {"type": "waf_rule", "description": "partial — no causal claim"}
                ]
            ),
            _make_intel(),
        )
        assert bd_partial["mitigation_penalty"] == -0.5


class TestPriorityScoreDifferentiation:
    def test_two_criticals_differentiable(self):
        """Within a Critical lane, EPSS magnitude produces distinct scores."""
        # High EPSS Critical
        score_high, _ = compute_priority_score(
            _make_finding(reachability="internet_exposed", utility=["rce"]),
            _make_intel(cvss_base=9.8, kev_listed=True, epss=0.9),
        )
        # Lower EPSS Critical
        score_lower, _ = compute_priority_score(
            _make_finding(reachability="internet_exposed", utility=["auth_bypass"]),
            _make_intel(cvss_base=7.5, kev_listed=True, epss=0.2),
        )
        assert score_high > score_lower
        assert score_high >= 9.0  # top of range
        assert score_lower >= 7.5  # still clearly High/Critical tier

    def test_calibration_real_finding(self):
        """CVE-2026-2006 equivalent: internal + strong ACL + CVSS 8.8 + EPSS 0.039."""
        score, bd = compute_priority_score(
            _make_finding(
                reachability="internal",
                utility=["rce", "data_access", "priv_esc", "lateral_movement"],
                mitigations=[
                    {
                        "type": "acl_segmentation",
                        "description": "VPC ACL restricts TCP/5432",
                        "causal_claim": "Blocks all direct access to PostgreSQL",
                        "evidence": ["ACL-0a1b2c3d4e"],
                    }
                ],
            ),
            _make_intel(cvss_base=8.8, epss=0.039, kev_listed=False),
        )
        # Should score around 3.0: medium-low priority despite high CVSS,
        # because internal reachability and strong mitigation apply.
        assert 2.5 <= score <= 3.5
        assert bd["mitigation_penalty"] == -1.5


class TestPriorityScoreEdgeCases:
    def test_no_cvss_still_scores(self):
        """Score is computed from remaining signals when CVSS is unavailable."""
        score, bd = compute_priority_score(
            _make_finding(reachability="internet_exposed", utility=["rce"]),
            _make_intel(cvss_base=None, kev_listed=True, epss=0.8),
        )
        assert score > 0.0
        assert bd["cvss"] == 0.0
        assert bd["intel"] > 0.0

    def test_score_clamped_to_10(self):
        """Score never exceeds 10.0."""
        score, _ = compute_priority_score(
            _make_finding(reachability="internet_exposed", utility=["rce"]),
            _make_intel(cvss_base=10.0, kev_listed=True, epss=0.99),
        )
        assert score <= 10.0

    def test_breakdown_totals_match_score(self):
        """breakdown['total'] == returned score."""
        score, bd = compute_priority_score(_make_finding(), _make_intel())
        assert score == bd["total"]


class TestPriorityScoreInAssessment:
    def test_score_evaluate_populates_priority_score(self):
        from src.rubricai.tools.scoring import score_evaluate

        finding = {
            "id": "FIND-RPS-001",
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
            "cvss": {"base": 8.8, "version": "3.1"},
            "kev": {"listed": True},
            "epss": {"score": 0.75, "percentile": 0.9},
        }
        result = score_evaluate(finding, intel)
        assert result["priority_score"] is not None
        assert result["priority_score"] > 0.0
        assert result["priority_score_breakdown"] is not None
        assert "total" in result["priority_score_breakdown"]

    def test_score_evaluate_includes_breakdown_keys(self):
        from src.rubricai.tools.scoring import score_evaluate

        finding = {
            "id": "FIND-RPS-002",
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
        bd = result["priority_score_breakdown"]
        assert bd is not None
        assert all(
            k in bd
            for k in (
                "cvss",
                "reachability",
                "intel",
                "utility",
                "mitigation_penalty",
                "total",
            )
        )
