"""Tests for env_read / env_write tools and EvidenceItem integration."""

import json

import pytest
from pydantic import ValidationError

from src.rubricai.schemas.evidence import EvidenceItem
from src.rubricai.tools.environment import (
    env_list,
    env_migrate_legacy,
    env_read,
    env_write,
)
from src.rubricai.tools.report import report_generate

_ENV = "test-env"  # canonical name used in all env tests


def _env_dir(tmp_path):
    """Return the per-environment state directory for the test environment."""
    return tmp_path / "environments" / _ENV


# ---------------------------------------------------------------------------
# env_list
# ---------------------------------------------------------------------------


def test_env_list_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    result = env_list()
    assert result["environments"] == []
    assert result["count"] == 0
    assert result["needs_migration"] is False


def test_env_list_after_write(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "prod"}, "production")
    env_write({"context_notes": "staging"}, "staging")
    result = env_list()
    assert set(result["environments"]) == {"production", "staging"}
    assert result["count"] == 2


def test_env_list_detects_legacy_files(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    # Write a legacy flat state file at root
    (tmp_path / "state_v001.json").write_text('{"version": 1}')
    result = env_list()
    assert result["needs_migration"] is True
    assert result["legacy_files"] == 1


# ---------------------------------------------------------------------------
# env_read / env_write (named environment)
# ---------------------------------------------------------------------------


def test_env_read_returns_empty_template_when_no_files(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    state = env_read(_ENV)
    assert state["version"] == 1
    assert state["components"] == []
    assert state["session_log"] == []
    assert state["environment_name"] == _ENV


def test_env_write_creates_versioned_file(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    result = env_write({"context_notes": "test env"}, _ENV)
    assert result["version"] == 1
    assert result["environment_name"] == _ENV
    d = _env_dir(tmp_path)
    assert (d / "state_v001.json").exists()
    assert (d / "state_latest.json").exists()


def test_env_write_increments_version(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "v1"}, _ENV)
    env_write({"context_notes": "v2"}, _ENV)
    result = env_write({"context_notes": "v3"}, _ENV)
    assert result["version"] == 3
    d = _env_dir(tmp_path)
    for ver in ("v001", "v002", "v003"):
        assert (d / f"state_{ver}.json").exists()


def test_env_write_never_overwrites(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "original"}, _ENV)
    v1_content = (_env_dir(tmp_path) / "state_v001.json").read_text()
    env_write({"context_notes": "second write"}, _ENV)
    assert (_env_dir(tmp_path) / "state_v001.json").read_text() == v1_content


def test_env_read_returns_latest_after_write(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "first"}, _ENV)
    env_write({"context_notes": "second"}, _ENV)
    state = env_read(_ENV)
    assert state["context_notes"] == "second"
    assert state["version"] == 2


def test_env_write_persists_components(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    components = [{"name": "PaymentAPI", "version": "3.1", "environment": "production"}]
    env_write({"components": components}, _ENV)
    state = env_read(_ENV)
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
        },
        _ENV,
    )
    state = env_read(_ENV)
    assert len(state["session_log"]) == 1
    assert "CVE-2024-1234" in state["session_log"][0]["summary"]


def test_multiple_environments_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "prod notes"}, "production")
    env_write({"context_notes": "staging notes"}, "staging")
    prod = env_read("production")
    stage = env_read("staging")
    assert prod["context_notes"] == "prod notes"
    assert stage["context_notes"] == "staging notes"


# ---------------------------------------------------------------------------
# env_migrate_legacy
# ---------------------------------------------------------------------------


def test_env_migrate_legacy(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    # Simulate legacy flat state at root
    legacy_content = '{"schema_version": "1", "version": 1, "components": []}'
    (tmp_path / "state_v001.json").write_text(legacy_content)
    (tmp_path / "state_latest.json").write_text(legacy_content)

    result = env_migrate_legacy("legacy-prod")
    assert result["migrated"] >= 1
    assert result["environment_name"] == "legacy-prod"

    # Legacy files should now be in the environments directory
    migrated_dir = tmp_path / "environments" / "legacy-prod"
    assert (migrated_dir / "state_v001.json").exists()

    # env_list should no longer flag migration needed
    listing = env_list()
    assert listing["needs_migration"] is False


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


def test_evidence_item_accepts_file_path():
    e = EvidenceItem(
        claim="Screenshot of patched system",
        type="screenshot",
        file_path="/tmp/screenshot.png",
        verified=True,
    )
    assert e.file_path == "/tmp/screenshot.png"
    assert e.type == "screenshot"


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


def test_env_read_falls_back_to_versioned_file_when_no_latest(tmp_path, monkeypatch):
    """env_read returns the highest versioned file when state_latest.json is absent."""
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write({"context_notes": "fallback test"}, "fallback-env")
    env_dir = tmp_path / "environments" / "fallback-env"
    (env_dir / "state_latest.json").unlink()
    state = env_read("fallback-env")
    assert state["context_notes"] == "fallback test"


def test_env_write_to_json_is_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
    env_write(
        {
            "components": [{"name": "Svc", "version": "1.0"}],
            "network": {"internet_exposed_services": ["Svc"]},
            "standing_mitigations": [],
            "context_notes": "prod env",
            "session_log": [],
        },
        _ENV,
    )
    raw = json.loads((_env_dir(tmp_path) / "state_v001.json").read_text())
    assert raw["schema_version"] == "1"
    assert raw["version"] == 1
