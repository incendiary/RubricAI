"""CHML scoring policy tests — all four lanes + guardrails."""

from datetime import UTC, datetime

from src.rubricai.policy.chml import _is_high_utility, _mitigation_effect, evaluate
from src.rubricai.policy.definitions import POLICY_VERSION
from src.rubricai.schemas.finding import Finding, Mitigation
from src.rubricai.schemas.intel import EpssInfo, IntelResult, KevInfo, PocInfo


def _make_intel(
    kev_listed: bool = False,
    epss_score: float = 0.1,
    poc_available: bool = False,
) -> IntelResult:
    return IntelResult(
        cve_or_id="CVE-2024-9999",
        retrieved_at=datetime.now(tz=UTC),
        sources=["NVD"],
        kev=KevInfo(listed=kev_listed) if kev_listed else None,
        epss=EpssInfo(score=epss_score, percentile=0.5),
        poc=(
            PocInfo(available=poc_available, confidence="medium")
            if poc_available
            else None
        ),
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
            "entry_point": {"description": "POST /api/exec"},
            "reachability": reachability,
            "attacker_utility": utility or ["rce"],
            "mitigations": mitigations or [],
        }
    )


class TestLaneCritical:
    def test_kev_internet_high_utility(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed", utility=["rce"]),
            _make_intel(kev_listed=True),
        )
        assert result.lane == "critical"
        assert result.target.days == 3

    def test_kev_but_local_only_is_not_critical(self):
        result = evaluate(
            _make_finding(reachability="local_only", utility=["rce"]),
            _make_intel(kev_listed=True),
        )
        assert result.lane != "critical"

    def test_kev_but_low_utility_is_not_critical(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed", utility=["dos"]),
            _make_intel(kev_listed=True),
        )
        assert result.lane != "critical"


class TestLaneHigh:
    def test_epss_high_internet_high_utility(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed", utility=["auth_bypass"]),
            _make_intel(kev_listed=False, epss_score=0.75),
        )
        assert result.lane == "high"
        assert result.target.days == 7

    def test_internet_exposed_high_utility_no_intel_signals(self):
        # v0.2: internet-exposed + high utility alone is sufficient for High,
        # no EPSS or PoC signal required.
        result = evaluate(
            _make_finding(reachability="internet_exposed", utility=["data_access"]),
            _make_intel(kev_listed=False, epss_score=0.1, poc_available=False),
        )
        assert result.lane == "high"

    def test_epss_high_internet_low_utility(self):
        # v0.2: high EPSS on internet-exposed path escalates to High
        # regardless of utility type.
        result = evaluate(
            _make_finding(reachability="internet_exposed", utility=["dos"]),
            _make_intel(kev_listed=False, epss_score=0.75),
        )
        assert result.lane == "high"

    def test_epss_high_but_constrained_is_not_high(self):
        result = evaluate(
            _make_finding(reachability="constrained_external", utility=["rce"]),
            _make_intel(kev_listed=False, epss_score=0.9),
        )
        assert result.lane != "high"


class TestLaneMedium:
    def test_constrained_reachability(self):
        result = evaluate(
            _make_finding(reachability="constrained_external", utility=["rce"]),
            _make_intel(),
        )
        assert result.lane == "medium"
        assert result.target.days is None  # default: patch train

    def test_internal_reachability(self):
        result = evaluate(
            _make_finding(reachability="internal", utility=["rce"]),
            _make_intel(),
        )
        assert result.lane == "medium"

    def test_low_utility_internet_exposed(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed", utility=["dos"]),
            _make_intel(kev_listed=False, epss_score=0.1),
        )
        assert result.lane == "medium"

    def test_strong_mitigation_downgrade(self):
        result = evaluate(
            _make_finding(
                reachability="internet_exposed",
                utility=["rce"],
                mitigations=[
                    {
                        "type": "waf_rule",
                        "description": "Blocks all exploit routes",
                        "causal_claim": "Rule blocks the vulnerable endpoint entirely",
                        "evidence": ["WAF-123"],
                    }
                ],
            ),
            _make_intel(kev_listed=False, epss_score=0.1),
        )
        assert result.lane == "medium"
        assert result.score_breakdown.mitigation_effect == "strong"


class TestLaneLow:
    def test_local_only_low_utility(self):
        result = evaluate(
            _make_finding(reachability="local_only", utility=["dos"]),
            _make_intel(),
        )
        assert result.lane == "low"
        assert result.target.days is None  # default: patch train

    def test_internal_low_utility(self):
        result = evaluate(
            _make_finding(reachability="internal", utility=["tampering"]),
            _make_intel(),
        )
        # internal + low utility → medium at best; confirm not high or critical
        assert result.lane in ("medium", "low")


class TestScoreBreakdown:
    def test_intel_escalation_populated(self):
        result = evaluate(
            _make_finding(),
            _make_intel(kev_listed=True, epss_score=0.8),
        )
        assert "kev_listed" in result.score_breakdown.intel_escalation
        assert "epss_high" in result.score_breakdown.intel_escalation
        assert "poc_present" not in result.score_breakdown.intel_escalation

    def test_no_intel_escalation_when_clean(self):
        result = evaluate(_make_finding(), _make_intel())
        assert result.score_breakdown.intel_escalation == []


class TestEvidenceGaps:
    def test_critical_with_no_mitigations_flagged(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed", utility=["rce"]),
            _make_intel(kev_listed=True),
        )
        assert result.lane == "critical"
        assert any("No mitigations" in g for g in result.evidence_gaps)

    def test_partial_mitigation_missing_causal_claim_flagged(self):
        result = evaluate(
            _make_finding(
                reachability="internet_exposed",
                utility=["rce"],
                mitigations=[
                    {
                        "type": "waf_rule",
                        "description": "Some WAF rule",
                        # no causal_claim
                        "evidence": ["WAF-999"],
                    }
                ],
            ),
            _make_intel(kev_listed=True),
        )
        assert any("causal_claim" in g for g in result.evidence_gaps)


class TestHelpers:
    def test_mitigation_effect_none(self):
        assert _mitigation_effect([]) == "none"

    def test_mitigation_effect_partial_no_causal_claim(self):
        m = Mitigation(type="waf_rule", description="x")
        assert _mitigation_effect([m]) == "partial"

    def test_mitigation_effect_strong(self):
        m = Mitigation(type="waf_rule", description="x", causal_claim="blocks route")
        assert _mitigation_effect([m]) == "strong"

    def test_mitigation_effect_monitoring_is_partial(self):
        m = Mitigation(
            type="increased_monitoring",
            description="SIEM alert added",
            causal_claim="detects exploitation attempts",
        )
        # increased_monitoring not in STRONG_MITIGATION_TYPES → partial
        assert _mitigation_effect([m]) == "partial"

    def test_is_high_utility_true(self):
        assert _is_high_utility(["rce", "dos"]) is True

    def test_is_high_utility_false(self):
        assert _is_high_utility(["dos", "tampering"]) is False

    def test_policy_version_propagated(self):
        result = evaluate(_make_finding(), _make_intel())
        assert result.policy_version == POLICY_VERSION
