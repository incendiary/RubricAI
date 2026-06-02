"""Tests for env_read / env_write tools and EvidenceItem integration."""

import json

import pytest
from pydantic import ValidationError

from src.rubricai.schemas.evidence import EvidenceItem
from src.rubricai.tools.environment import env_read, env_write
from src.rubricai.tools.report import report_generate

# ---------------------------------------------------------------------------
# env_read / env_write
# ---------------------------------------------------------------------------


def test_env_read_returns_empty_template_when_no_files(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    state = env_read()
    assert state["version"] == 1
    assert state["components"] == []
    assert state["session_log"] == []


def test_env_write_creates_versioned_file(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    result = env_write({"context_notes": "test env"})
    assert result["version"] == 1
    assert (tmp_path / "state_v001.json").exists()
    assert (tmp_path / "state_latest.json").exists()


def test_env_write_increments_version(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "v1"})
    env_write({"context_notes": "v2"})
    result = env_write({"context_notes": "v3"})
    assert result["version"] == 3
    assert (tmp_path / "state_v001.json").exists()
    assert (tmp_path / "state_v002.json").exists()
    assert (tmp_path / "state_v003.json").exists()


def test_env_write_never_overwrites(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "original"})
    v1_content = (tmp_path / "state_v001.json").read_text()
    env_write({"context_notes": "second write"})
    assert (tmp_path / "state_v001.json").read_text() == v1_content


def test_env_read_returns_latest_after_write(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "first"})
    env_write({"context_notes": "second"})
    state = env_read()
    assert state["context_notes"] == "second"
    assert state["version"] == 2


def test_env_write_persists_components(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    components = [{"name": "PaymentAPI", "version": "3.1", "environment": "production"}]
    env_write({"components": components})
    state = env_read()
    assert state["components"][0]["name"] == "PaymentAPI"


def test_env_write_appends_session_log(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write(
        {
            "session_log": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "summary": "Assessed CVE-2024-1234",
                }
            ]
        }
    )
    state = env_read()
    assert len(state["session_log"]) == 1
    assert "CVE-2024-1234" in state["session_log"][0]["summary"]


# ---------------------------------------------------------------------------
# EvidenceItem schema
# ---------------------------------------------------------------------------


def test_evidence_item_valid():
    e = EvidenceItem(
        claim="Firewall blocks port 8080",
        type="firewall_policy",
        content="iptables -A INPUT -p tcp --dport 8080 -j DROP",
        analyst_note="Rule confirmed to block inbound 8080",
        verified=True,
    )
    assert e.verified is True


def test_evidence_item_unverified_by_default():
    e = EvidenceItem(claim="WAF rule in place", type="waf_config")
    assert e.verified is False
    assert e.content is None


def test_evidence_item_invalid_type():
    with pytest.raises(ValidationError):
        EvidenceItem(claim="x", type="invalid_type")


# ---------------------------------------------------------------------------
# report_generate with evidence
# ---------------------------------------------------------------------------


def _finding_dict():
    return {
        "id": "FIND-EV-001",
        "cve_or_id": "CVE-2024-9999",
        "component": {"name": "TestSvc", "version": "1.0"},
        "entry_point": {"description": "POST /api/exec"},
        "reachability": "internet_exposed",
        "attacker_utility": ["rce"],
    }


def _intel_dict():
    from datetime import UTC, datetime

    return {
        "cve_or_id": "CVE-2024-9999",
        "retrieved_at": datetime.now(tz=UTC).isoformat(),
        "sources": ["NVD"],
        "kev": {"listed": True, "due_date": "2024-07-01"},
        "epss": {"score": 0.85, "percentile": 0.99},
    }


def _assessment_dict():
    return {
        "policy_version": "chml-v0.1",
        "lane": "critical",
        "target": {"days": 3, "basis": "kev_listed + internet_exposed + high_utility"},
        "rationale": ["KEV listed."],
        "actions": ["Remediate within 72 hours."],
        "evidence_gaps": [],
    }


def test_report_with_evidence_sets_has_verified_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
    evidence = [
        {
            "claim": "Firewall blocks port 8080",
            "type": "firewall_policy",
            "content": "DENY tcp 0.0.0.0/0 any eq 8080",
            "analyst_note": "Policy confirms block",
            "verified": True,
        }
    ]
    result = report_generate(
        _finding_dict(), _intel_dict(), _assessment_dict(), evidence=evidence
    )
    assert result["has_verified_evidence"] is True
    assert result["report_json"]["has_verified_evidence"] is True
    assert len(result["report_json"]["evidence"]) == 1


def test_report_unverified_evidence_flag_false(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
    evidence = [
        {
            "claim": "WAF rule exists",
            "type": "waf_config",
            "verified": False,
        }
    ]
    result = report_generate(
        _finding_dict(), _intel_dict(), _assessment_dict(), evidence=evidence
    )
    assert result["has_verified_evidence"] is False


def test_report_no_evidence_flag_false(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
    result = report_generate(_finding_dict(), _intel_dict(), _assessment_dict())
    assert result["has_verified_evidence"] is False
    assert result["report_json"]["evidence"] == []


def test_report_evidence_in_markdown(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
    evidence = [
        {
            "claim": "Firewall blocks port 8080",
            "type": "firewall_policy",
            "content": "DENY tcp any eq 8080",
            "verified": True,
        }
    ]
    result = report_generate(
        _finding_dict(), _intel_dict(), _assessment_dict(), evidence=evidence
    )
    assert "Evidence" in result["report_markdown"]
    assert "Firewall blocks port 8080" in result["report_markdown"]
    assert "✅ Verified" in result["report_markdown"]


def test_report_patch_train_renders_in_markdown(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))
    assessment = {
        **_assessment_dict(),
        "lane": "medium",
        "target": {"days": None, "basis": "constrained_reachability"},
    }
    finding = {**_finding_dict(), "reachability": "constrained_external"}
    result = report_generate(finding, _intel_dict(), assessment)
    assert "Patch train" in result["report_markdown"]


def test_env_write_to_json_is_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write(
        {
            "components": [{"name": "Svc", "version": "1.0"}],
            "network": {"internet_exposed_services": ["Svc"]},
            "standing_mitigations": [],
            "context_notes": "prod env",
            "session_log": [],
        }
    )
    raw = json.loads((tmp_path / "state_v001.json").read_text())
    assert raw["schema_version"] == "1"
    assert raw["version"] == 1
