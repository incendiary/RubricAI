"""BOD 26-04 scoring policy tests — all 16 signal combinations + supporting logic."""

from datetime import UTC, datetime

from src.rubricai.fetchers.nvd import extract_automatable, extract_technical_impact
from src.rubricai.policy.bod_26_04 import evaluate
from src.rubricai.policy.registry import AVAILABLE_POLICIES, get_evaluator
from src.rubricai.schemas.finding import Finding
from src.rubricai.schemas.intel import CvssInfo, IntelResult, KevInfo


def _make_intel(
    kev_listed: bool = False,
    automatable: bool | None = None,
    cvss_vector: str | None = None,
) -> IntelResult:
    cvss = None
    if cvss_vector:
        # Extract a base score from vector (simplified — just use 7.5 as placeholder)
        cvss = CvssInfo(base=7.5, vector=cvss_vector, version="3.1")
    return IntelResult(
        cve_or_id="CVE-2026-9999",
        retrieved_at=datetime.now(tz=UTC),
        sources=["NVD"],
        kev=KevInfo(listed=kev_listed) if kev_listed else None,
        automatable=automatable,
        cvss=cvss,
    )


def _make_finding(
    reachability: str = "internet_exposed",
    automatable: bool | None = None,
    mitigations: list[dict] | None = None,
) -> Finding:
    return Finding.model_validate(
        {
            "id": "FIND-001",
            "cve_or_id": "CVE-2026-9999",
            "component": {"name": "TestLib", "version": "1.0"},
            "entry_point": {"description": "POST /admin/exec"},
            "reachability": reachability,
            "attacker_utility": ["rce"],
            "automatable": automatable,
            "mitigations": mitigations or [],
        }
    )


# --- Helper: signals as (internet, kev, auto, total_impact) → expected lane ---
# total_impact derived from CVSS vector "C:H/I:H" → total, otherwise partial

_TOTAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
_PARTIAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
_NO_VECTOR = None


class TestAllSixteenCombinations:
    """Exhaustive test of all 2^4 signal combinations."""

    def _score(
        self,
        internet: bool,
        kev: bool,
        auto: bool,
        total: bool,
    ) -> str:
        finding = _make_finding(
            reachability="internet_exposed" if internet else "internal",
            automatable=auto,
        )
        intel = _make_intel(
            kev_listed=kev,
            cvss_vector=_TOTAL_VECTOR if total else _PARTIAL_VECTOR,
        )
        return evaluate(finding, intel).lane

    def test_4_signals_critical(self):
        assert self._score(True, True, True, True) == "critical"

    def test_3_signals_high_no_internet(self):
        assert self._score(False, True, True, True) == "high"

    def test_3_signals_high_no_kev(self):
        assert self._score(True, False, True, True) == "high"

    def test_3_signals_high_not_automatable(self):
        assert self._score(True, True, False, True) == "high"

    def test_3_signals_high_partial_impact(self):
        assert self._score(True, True, True, False) == "high"

    def test_2_signals_medium_internet_kev(self):
        assert self._score(True, True, False, False) == "medium"

    def test_2_signals_medium_internet_auto(self):
        assert self._score(True, False, True, False) == "medium"

    def test_2_signals_medium_internet_total(self):
        assert self._score(True, False, False, True) == "medium"

    def test_2_signals_medium_kev_auto(self):
        assert self._score(False, True, True, False) == "medium"

    def test_2_signals_medium_kev_total(self):
        assert self._score(False, True, False, True) == "medium"

    def test_2_signals_medium_auto_total(self):
        assert self._score(False, False, True, True) == "medium"

    def test_1_signal_low_internet_only(self):
        assert self._score(True, False, False, False) == "low"

    def test_1_signal_low_kev_only(self):
        assert self._score(False, True, False, False) == "low"

    def test_1_signal_low_auto_only(self):
        assert self._score(False, False, True, False) == "low"

    def test_1_signal_low_total_only(self):
        assert self._score(False, False, False, True) == "low"

    def test_0_signals_low(self):
        assert self._score(False, False, False, False) == "low"


class TestRemediation:
    def test_critical_3_days(self):
        result = evaluate(
            _make_finding(automatable=True),
            _make_intel(kev_listed=True, cvss_vector=_TOTAL_VECTOR),
        )
        assert result.lane == "critical"
        assert result.target.days == 3

    def test_high_14_days(self):
        result = evaluate(
            _make_finding(automatable=True),
            _make_intel(kev_listed=True, cvss_vector=_PARTIAL_VECTOR),
        )
        assert result.lane == "high"
        assert result.target.days == 14

    def test_medium_60_days(self):
        # 2 signals: kev_listed + total_impact (no internet, not automatable)
        result = evaluate(
            _make_finding(reachability="internal", automatable=False),
            _make_intel(kev_listed=True, cvss_vector=_TOTAL_VECTOR),
        )
        assert result.lane == "medium"
        assert result.target.days == 60

    def test_low_patch_train(self):
        result = evaluate(
            _make_finding(reachability="local_only", automatable=False),
            _make_intel(kev_listed=False),
        )
        assert result.lane == "low"
        assert result.target.days is None


class TestAutomatableResolution:
    def test_finding_override_true_takes_precedence(self):
        # intel says not automatable, finding says True → use True
        result = evaluate(
            _make_finding(automatable=True),
            _make_intel(kev_listed=True, automatable=False, cvss_vector=_TOTAL_VECTOR),
        )
        assert result.lane == "critical"

    def test_finding_override_false_takes_precedence(self):
        # intel says automatable, finding says False → use False
        result = evaluate(
            _make_finding(automatable=False),
            _make_intel(kev_listed=True, automatable=True, cvss_vector=_TOTAL_VECTOR),
        )
        assert result.lane == "high"  # 3 signals (no auto)

    def test_unknown_automatable_treated_as_false(self):
        # No automatable data at all → conservative False
        result = evaluate(
            _make_finding(automatable=None),
            _make_intel(kev_listed=True, automatable=None, cvss_vector=_TOTAL_VECTOR),
        )
        # internet + kev + total = 3 signals → high (auto=False reduces by 1)
        assert result.lane == "high"

    def test_unknown_automatable_adds_evidence_gap(self):
        result = evaluate(
            _make_finding(automatable=None),
            _make_intel(automatable=None),
        )
        assert any("automatable" in gap.lower() for gap in result.evidence_gaps)


class TestVulnrichmentExtraction:
    """Unit tests for NVD record extraction helpers."""

    def test_extract_automatable_from_cvss_vector_true(self):
        record = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    }
                ]
            }
        }
        assert extract_automatable(record) is True

    def test_extract_automatable_user_interaction_required(self):
        record = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                        }
                    }
                ]
            }
        }
        assert extract_automatable(record) is False

    def test_extract_automatable_local_attack_vector(self):
        record = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    }
                ]
            }
        }
        assert extract_automatable(record) is False

    def test_extract_automatable_missing_metrics(self):
        assert extract_automatable({}) is None

    def test_extract_automatable_vulnrichment_field_yes(self):
        record = {"automatable": "yes"}
        assert extract_automatable(record) is True

    def test_extract_automatable_vulnrichment_field_no(self):
        record = {"automatable": "no"}
        assert extract_automatable(record) is False

    def test_extract_technical_impact_total_scope_changed(self):
        record = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                        }
                    }
                ]
            }
        }
        assert extract_technical_impact(record) == "total"

    def test_extract_technical_impact_total_both_high(self):
        record = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
                        }
                    }
                ]
            }
        }
        assert extract_technical_impact(record) == "total"

    def test_extract_technical_impact_partial(self):
        record = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"
                        }
                    }
                ]
            }
        }
        assert extract_technical_impact(record) == "partial"

    def test_extract_technical_impact_no_metrics(self):
        assert extract_technical_impact({}) is None


class TestPolicyGet:
    def test_bod_26_04_definition(self):
        from src.rubricai.tools.policy import policy_get

        result = policy_get("bod-26-04")
        assert result["policy_version"] == "bod-26-04"
        assert "signals" in result
        assert result["lanes"]["critical"]["target_days"] == 3
        assert result["lanes"]["high"]["target_days"] == 14
        assert result["lanes"]["medium"]["target_days"] == 60
        assert result["lanes"]["low"]["patch_train"] is True

    def test_bod_26_04_in_list(self):
        from src.rubricai.tools.policy import policy_get

        result = policy_get("list")
        assert "bod-26-04" in result["available_policies"]


class TestRegistry:
    def test_bod_26_04_in_available(self):
        assert "bod-26-04" in AVAILABLE_POLICIES

    def test_get_evaluator_returns_bod(self):
        fn = get_evaluator("bod-26-04")
        from src.rubricai.policy.bod_26_04 import evaluate as bod_evaluate

        assert fn is bod_evaluate


class TestPolicyVersion:
    def test_policy_version_propagated(self):
        result = evaluate(_make_finding(), _make_intel())
        assert result.policy_version == "bod-26-04"

    def test_forensic_triage_action_on_critical(self):
        result = evaluate(
            _make_finding(automatable=True),
            _make_intel(kev_listed=True, cvss_vector=_TOTAL_VECTOR),
        )
        assert result.lane == "critical"
        assert any("forensic" in a.lower() for a in result.actions)
