"""Tests for score.evaluate, report.generate, and policy.get tools."""

import json
from datetime import UTC, datetime

from src.rubricai.tools.policy import policy_get
from src.rubricai.tools.report import report_generate
from src.rubricai.tools.scoring import score_evaluate


def _finding_dict(**overrides) -> dict:
    base = {
        "id": "FIND-TEST-001",
        "cve_or_id": "CVE-2024-5678",
        "component": {"name": "TestService", "version": "3.0"},
        "entry_point": {"description": "POST /api/exec"},
        "reachability": "internet_exposed",
        "attacker_utility": ["rce"],
    }
    base.update(overrides)
    return base


def _intel_dict(**overrides) -> dict:
    base = {
        "cve_or_id": "CVE-2024-5678",
        "retrieved_at": datetime.now(tz=UTC).isoformat(),
        "sources": ["CISA_KEV", "FIRST_EPSS"],
        "kev": {"listed": True, "due_date": "2024-07-01"},
        "epss": {"score": 0.85, "percentile": 0.99},
    }
    base.update(overrides)
    return base


def _assessment_dict(**overrides) -> dict:
    base = {
        "policy_version": "chml-v0.1",
        "lane": "critical",
        "target": {"days": 3, "basis": "kev_listed + internet_exposed + high_utility"},
        "rationale": ["KEV listed with internet-exposed RCE."],
        "actions": ["Remediate within 72 hours."],
        "evidence_gaps": ["No mitigations documented."],
    }
    base.update(overrides)
    return base


class TestScoreEvaluate:
    def test_critical_lane_kev_internet_rce(self):
        result = score_evaluate(_finding_dict(), _intel_dict())
        assert result["lane"] == "critical"
        assert result["target"]["days"] == 3

    def test_high_lane_epss_no_kev(self):
        result = score_evaluate(
            _finding_dict(
                reachability="internet_exposed", attacker_utility=["auth_bypass"]
            ),
            _intel_dict(kev=None, epss={"score": 0.75, "percentile": 0.95}),
        )
        assert result["lane"] == "high"

    def test_policy_version_in_result(self):
        result = score_evaluate(_finding_dict(), _intel_dict())
        assert "policy_version" in result

    def test_score_breakdown_present(self):
        result = score_evaluate(_finding_dict(), _intel_dict())
        assert "score_breakdown" in result
        assert result["score_breakdown"]["reachability"] == "internet_exposed"


class TestReportGenerate:
    def test_generates_markdown_and_json(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        result = report_generate(_finding_dict(), _intel_dict(), _assessment_dict())

        assert "report_markdown" in result
        assert "report_json" in result
        assert len(result["saved_to"]) == 2

    def test_markdown_contains_finding_id(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        result = report_generate(_finding_dict(), _intel_dict(), _assessment_dict())
        assert "FIND-TEST-001" in result["report_markdown"]

    def test_markdown_contains_lane(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        result = report_generate(_finding_dict(), _intel_dict(), _assessment_dict())
        assert "CRITICAL" in result["report_markdown"]

    def test_json_persisted_to_disk(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        report_generate(_finding_dict(), _intel_dict(), _assessment_dict())

        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 1
        saved = json.loads(json_files[0].read_text())
        assert saved["finding"]["id"] == "FIND-TEST-001"
        assert saved["assessment"]["lane"] == "critical"

    def test_markdown_only_format(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        result = report_generate(
            _finding_dict(), _intel_dict(), _assessment_dict(), formats=["markdown"]
        )
        assert "report_markdown" in result
        assert "report_json" not in result
        assert len(result["saved_to"]) == 1

    def test_evidence_gaps_in_markdown(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        result = report_generate(_finding_dict(), _intel_dict(), _assessment_dict())
        assert "No mitigations documented" in result["report_markdown"]


class TestPolicyGet:
    def test_returns_policy_version(self):
        p = policy_get()
        assert "policy_version" in p
        assert p["policy_version"].startswith("chml-")

    def test_all_lanes_present(self):
        p = policy_get()
        assert set(p["lanes"].keys()) == {"critical", "high", "medium", "low"}

    def test_critical_target_is_3_days(self):
        p = policy_get()
        assert p["lanes"]["critical"]["target_days"] == 3

    def test_guardrails_present(self):
        p = policy_get()
        assert len(p["guardrails"]) > 0
