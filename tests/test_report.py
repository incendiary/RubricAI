"""Tests for score.evaluate, report.generate, and policy.get tools."""

import json
from datetime import UTC, datetime

import pytest

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

    def test_pdf_format_produces_valid_pdf(self, tmp_path, monkeypatch):
        pytest.importorskip("weasyprint", reason="weasyprint not installed")
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        result = report_generate(
            _finding_dict(), _intel_dict(), _assessment_dict(), formats=["pdf"]
        )
        assert "report_pdf_path" in result
        pdf_path = tmp_path / (list(tmp_path.glob("*.pdf"))[0].name)
        assert pdf_path.exists()
        assert pdf_path.read_bytes()[:4] == b"%PDF"
        # Markdown and JSON not generated when not requested
        assert "report_markdown" not in result
        assert len(list(tmp_path.glob("*.md"))) == 0

    def test_all_formats_produces_three_files(self, tmp_path, monkeypatch):
        pytest.importorskip("weasyprint", reason="weasyprint not installed")
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        result = report_generate(
            _finding_dict(),
            _intel_dict(),
            _assessment_dict(),
            formats=["markdown", "json", "pdf"],
        )
        assert len(result["saved_to"]) == 3
        assert "report_markdown" in result
        assert "report_json" in result
        assert "report_pdf_path" in result
        assert any(p.endswith(".pdf") for p in result["saved_to"])

    def test_pdf_appendix_skipped_when_flag_false(self, tmp_path, monkeypatch):
        """include_evidence_appendix=False (default) renders no appendix section."""
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        evidence = [
            {
                "claim": "WAF rule blocks exploit",
                "type": "waf_config",
                "content": "RULE 1234: DROP",
                "verified": True,
            }
        ]
        from src.rubricai.schemas.assessment import Assessment
        from src.rubricai.schemas.evidence import EvidenceItem
        from src.rubricai.schemas.finding import Finding
        from src.rubricai.schemas.intel import IntelResult
        from src.rubricai.tools.report import _render_html_card

        f = Finding.model_validate(_finding_dict())
        i = IntelResult.model_validate(
            {k: v for k, v in _intel_dict().items() if k != "derived_finding_context"}
        )
        a = Assessment.model_validate(_assessment_dict())
        ev = [EvidenceItem.model_validate(e) for e in evidence]

        html = _render_html_card(f, i, a, ev, include_appendix=False)
        assert "Evidence Appendix" not in html

    def test_pdf_appendix_contains_evidence_content(self, tmp_path, monkeypatch):
        """include_evidence_appendix=True renders evidence content in appendix."""
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        from src.rubricai.schemas.assessment import Assessment
        from src.rubricai.schemas.evidence import EvidenceItem
        from src.rubricai.schemas.finding import Finding
        from src.rubricai.schemas.intel import IntelResult
        from src.rubricai.tools.report import _render_html_card

        f = Finding.model_validate(_finding_dict())
        i = IntelResult.model_validate(
            {k: v for k, v in _intel_dict().items() if k != "derived_finding_context"}
        )
        a = Assessment.model_validate(_assessment_dict())
        ev = [
            EvidenceItem.model_validate(
                {
                    "claim": "Firewall blocks port 8080",
                    "type": "firewall_policy",
                    "content": "DENY tcp any eq 8080",
                    "verified": True,
                }
            )
        ]

        html = _render_html_card(f, i, a, ev, include_appendix=True)
        assert "Evidence Appendix" in html
        assert "Firewall blocks port 8080" in html
        assert "DENY tcp any eq 8080" in html

    def test_pdf_appendix_embeds_file_as_data_uri(self, tmp_path, monkeypatch):
        """Evidence items with a valid file_path are embedded as base64 data URIs."""
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        # Write a small fake "screenshot" file
        fake_png = tmp_path / "screenshot.png"
        fake_png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)  # PNG header stub

        from src.rubricai.schemas.assessment import Assessment
        from src.rubricai.schemas.evidence import EvidenceItem
        from src.rubricai.schemas.finding import Finding
        from src.rubricai.schemas.intel import IntelResult
        from src.rubricai.tools.report import _render_html_card

        f = Finding.model_validate(_finding_dict())
        i = IntelResult.model_validate(
            {k: v for k, v in _intel_dict().items() if k != "derived_finding_context"}
        )
        a = Assessment.model_validate(_assessment_dict())
        ev = [
            EvidenceItem.model_validate(
                {
                    "claim": "Screenshot of patched system",
                    "type": "screenshot",
                    "verified": True,
                    "file_path": str(fake_png),
                }
            )
        ]

        html = _render_html_card(f, i, a, ev, include_appendix=True)
        assert "data:image/png;base64," in html

    def test_pdf_appendix_rejects_path_traversal(self, tmp_path, monkeypatch):
        """Evidence file_path outside allowed directories is rejected."""
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path / "envs"))

        from src.rubricai.schemas.assessment import Assessment
        from src.rubricai.schemas.evidence import EvidenceItem
        from src.rubricai.schemas.finding import Finding
        from src.rubricai.schemas.intel import IntelResult
        from src.rubricai.tools.report import _prepare_appendix_items

        ev = [
            EvidenceItem.model_validate(
                {
                    "claim": "Malicious path",
                    "type": "screenshot",
                    "verified": False,
                    "file_path": "/etc/passwd",
                }
            )
        ]

        items = _prepare_appendix_items(ev)
        assert "embedded_data" not in items[0]
        assert "Rejected" in items[0].get("embedded_data_error", "")

    def test_pdf_appendix_rejects_symlink_escape(self, tmp_path, monkeypatch):
        """Symlinks that resolve outside allowed dirs are rejected."""
        monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path / "reports"))
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path / "envs"))
        (tmp_path / "reports").mkdir()

        # Create a symlink inside report dir that points outside
        escape_link = tmp_path / "reports" / "escape.txt"
        escape_link.symlink_to("/etc/hostname")

        from src.rubricai.schemas.evidence import EvidenceItem
        from src.rubricai.tools.report import _prepare_appendix_items

        ev = [
            EvidenceItem.model_validate(
                {
                    "claim": "Symlink escape",
                    "type": "other",
                    "verified": False,
                    "file_path": str(escape_link),
                }
            )
        ]

        items = _prepare_appendix_items(ev)
        assert "embedded_data" not in items[0]
        assert "Rejected" in items[0].get("embedded_data_error", "")
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
