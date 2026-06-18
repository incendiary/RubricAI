"""EPSS v5 scoring policy tests."""

from datetime import UTC, datetime

import pytest

from src.rubricai.policy.epss_v5 import evaluate
from src.rubricai.policy.registry import AVAILABLE_POLICIES, get_evaluator
from src.rubricai.schemas.finding import Finding
from src.rubricai.schemas.intel import EpssInfo, IntelResult, KevInfo


def _make_intel(
    epss_score: float | None = 0.05,
    kev_listed: bool = False,
) -> IntelResult:
    return IntelResult(
        cve_or_id="CVE-2026-9999",
        retrieved_at=datetime.now(tz=UTC),
        sources=["NVD"],
        kev=KevInfo(listed=kev_listed) if kev_listed else None,
        epss=(
            EpssInfo(score=epss_score, percentile=0.5)
            if epss_score is not None
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
            "cve_or_id": "CVE-2026-9999",
            "component": {"name": "TestLib", "version": "1.0"},
            "entry_point": {"description": "GET /api/v1/exec"},
            "reachability": reachability,
            "attacker_utility": utility or ["rce"],
            "mitigations": mitigations or [],
        }
    )


class TestEpssV5Critical:
    def test_high_epss_internet_exposed(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed"), _make_intel(epss_score=0.75)
        )
        assert result.lane == "critical"
        assert result.target.days == 3

    def test_high_epss_not_internet_exposed_is_not_critical(self):
        # EPSS >= 0.7 but not internet-exposed → High (EPSS >= high threshold)
        result = evaluate(
            _make_finding(reachability="internal"), _make_intel(epss_score=0.75)
        )
        assert result.lane == "high"

    def test_epss_exactly_at_critical_threshold(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed"), _make_intel(epss_score=0.7)
        )
        assert result.lane == "critical"

    def test_epss_just_below_critical_threshold_is_high(self):
        result = evaluate(
            _make_finding(reachability="internet_exposed"), _make_intel(epss_score=0.69)
        )
        assert result.lane == "high"


class TestEpssV5High:
    def test_epss_at_high_threshold(self):
        result = evaluate(
            _make_finding(reachability="internal"), _make_intel(epss_score=0.4)
        )
        assert result.lane == "high"
        assert result.target.days == 7

    def test_epss_above_high_threshold_no_internet(self):
        result = evaluate(
            _make_finding(reachability="local_only"), _make_intel(epss_score=0.55)
        )
        assert result.lane == "high"

    def test_kev_internet_exposed_no_epss_data(self):
        # KEV + internet-exposed without EPSS → High
        result = evaluate(
            _make_finding(reachability="internet_exposed"),
            _make_intel(epss_score=None, kev_listed=True),
        )
        assert result.lane == "high"

    def test_kev_internet_exposed_below_high_threshold(self):
        # KEV escalates even when EPSS < high threshold
        result = evaluate(
            _make_finding(reachability="internet_exposed"),
            _make_intel(epss_score=0.1, kev_listed=True),
        )
        assert result.lane == "high"


class TestEpssV5Medium:
    def test_epss_at_medium_threshold(self):
        result = evaluate(
            _make_finding(reachability="internal"), _make_intel(epss_score=0.1)
        )
        assert result.lane == "medium"
        # EPSS v5 has explicit 30-day medium SLA
        assert result.target.days == 30

    def test_epss_above_medium_below_high(self):
        result = evaluate(
            _make_finding(reachability="internal"), _make_intel(epss_score=0.25)
        )
        assert result.lane == "medium"

    def test_strong_mitigation_downgrades_medium_to_low(self):
        mitigations = [
            {
                "type": "acl_segmentation",
                "description": "Firewall blocks port 443 from internet",
                "causal_claim": "Blocks the HTTP exploit path entirely.",
                "evidence": ["Firewall rule: deny any any 443"],
            }
        ]
        result = evaluate(
            _make_finding(reachability="internal", mitigations=mitigations),
            _make_intel(epss_score=0.15),
        )
        assert result.lane == "low"


class TestEpssV5Low:
    def test_low_epss_no_escalation(self):
        result = evaluate(
            _make_finding(reachability="local_only"), _make_intel(epss_score=0.02)
        )
        assert result.lane == "low"
        assert result.target.days is None  # patch train

    def test_epss_just_below_medium_threshold(self):
        result = evaluate(
            _make_finding(reachability="internal"), _make_intel(epss_score=0.09)
        )
        assert result.lane == "low"

    def test_no_kev_no_epss_data(self):
        result = evaluate(
            _make_finding(reachability="local_only"),
            _make_intel(epss_score=None, kev_listed=False),
        )
        assert result.lane == "low"


class TestEpssV5PolicyVersion:
    def test_policy_version_propagated(self):
        result = evaluate(_make_finding(), _make_intel(epss_score=0.5))
        assert result.policy_version == "epss-v5"

    def test_custom_policy_version_string_preserved(self):
        result = evaluate(
            _make_finding(), _make_intel(epss_score=0.5), policy_version="epss-v5"
        )
        assert result.policy_version == "epss-v5"


class TestRegistry:
    def test_epss_v5_in_available_policies(self):
        assert "epss-v5" in AVAILABLE_POLICIES
        assert "chml-v0.2" in AVAILABLE_POLICIES

    def test_get_evaluator_returns_epss_v5(self):
        fn = get_evaluator("epss-v5")
        assert fn is evaluate

    def test_get_evaluator_returns_chml_for_default(self):
        from src.rubricai.policy.chml import evaluate as chml_evaluate

        fn = get_evaluator(None)
        assert fn is chml_evaluate

    def test_unknown_policy_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown policy"):
            get_evaluator("nonexistent-v99")

    def test_unknown_policy_error_lists_available(self):
        with pytest.raises(ValueError, match="chml-v0.2"):
            get_evaluator("nonexistent-v99")


class TestPolicyGet:
    def test_policy_get_epss_v5(self):
        from src.rubricai.tools.policy import policy_get

        result = policy_get("epss-v5")
        assert result["policy_version"] == "epss-v5"
        assert "epss_critical" in result["thresholds"]
        assert "epss_high" in result["thresholds"]
        assert "epss_medium" in result["thresholds"]
        assert result["lanes"]["medium"]["target_days"] == 30

    def test_policy_get_list(self):
        from src.rubricai.tools.policy import policy_get

        result = policy_get("list")
        assert "available_policies" in result
        assert "epss-v5" in result["available_policies"]
        assert "chml-v0.2" in result["available_policies"]

    def test_policy_get_default_is_chml(self):
        from src.rubricai.tools.policy import policy_get

        result = policy_get(None)
        assert result["policy_version"] == "chml-v0.2"
