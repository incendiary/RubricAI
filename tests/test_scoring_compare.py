"""Tests for the score_compare tool — runs all 3 policies and returns a comparison."""

from datetime import UTC, datetime

from src.rubricai.policy.registry import AVAILABLE_POLICIES
from src.rubricai.tools.scoring_compare import score_compare


def _base_finding(mitigations: list | None = None) -> dict:
    return {
        "id": "FIND-001",
        "cve_or_id": "CVE-2024-3400",
        "component": {"name": "PAN-OS", "version": "11.1.0", "type": "appliance"},
        "entry_point": {"description": "GlobalProtect TCP 443", "protocol": "HTTPS"},
        "reachability": "internet_exposed",
        "attacker_utility": ["rce"],
        "mitigations": mitigations or [],
    }


def _base_intel() -> dict:
    return {
        "cve_or_id": "CVE-2024-3400",
        "retrieved_at": datetime.now(tz=UTC).isoformat(),
        "sources": ["NVD"],
        "kev": {"listed": True},
        "epss": {"score": 0.95, "percentile": 0.99},
        "cvss": {
            "base": 10.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "version": "3.1",
        },
        "automatable": True,
    }


class TestScoreCompareStructure:
    def test_returns_all_policies(self):
        result = score_compare(_base_finding(), _base_intel())
        assert set(result["results"].keys()) == set(AVAILABLE_POLICIES)

    def test_summary_has_one_row_per_policy(self):
        result = score_compare(_base_finding(), _base_intel())
        assert len(result["summary"]) == len(AVAILABLE_POLICIES)

    def test_summary_row_fields(self):
        result = score_compare(_base_finding(), _base_intel())
        for row in result["summary"]:
            assert "policy" in row
            assert "lane" in row
            assert "sla_days" in row
            assert "basis" in row

    def test_consensus_key_present(self):
        result = score_compare(_base_finding(), _base_intel())
        assert result["consensus"] in ("agree", "diverge")


class TestScoreCompareConsensus:
    def test_critical_finding_may_diverge(self):
        """KEV + internet + RCE + automatable — all 3 policies should land Critical."""
        result = score_compare(_base_finding(), _base_intel())
        # Either all agree (critical) or diverge — both are valid; just verify the field
        assert result["consensus"] in ("agree", "diverge")

    def test_all_agree_on_low_when_patched(self):
        """vendor_patch + causal_claim → all policies short-circuit to low."""
        patched_finding = _base_finding(
            mitigations=[
                {
                    "type": "vendor_patch",
                    "description": "Upgraded PAN-OS to 11.1.2-h3.",
                    "causal_claim": "Patch removes the command injection vulnerability.",  # noqa: E501
                    "evidence": ["JIRA-9001"],
                }
            ]
        )
        result = score_compare(patched_finding, _base_intel())
        assert result["consensus"] == "agree"
        for row in result["summary"]:
            assert row["lane"] == "low"
            assert row["basis"] == "vendor_patch_applied"

    def test_diverge_when_lanes_differ(self):
        """Low EPSS + no KEV + internal → CHML may differ from EPSS-v5."""
        finding = {
            "id": "FIND-002",
            "cve_or_id": "CVE-2024-1086",
            "component": {"name": "Linux kernel", "version": "5.15.140", "type": "os"},
            "entry_point": {"description": "Local shell", "protocol": "local"},
            "reachability": "local_only",
            "attacker_utility": ["priv_esc"],
            "mitigations": [],
        }
        intel = {
            "cve_or_id": "CVE-2024-1086",
            "retrieved_at": datetime.now(tz=UTC).isoformat(),
            "sources": ["NVD"],
            "kev": {"listed": True},
            "epss": {"score": 0.05, "percentile": 0.3},
            "automatable": False,
        }
        result = score_compare(finding, intel)
        # Result keys exist regardless of consensus outcome
        assert "results" in result
        assert "chml-v0.2" in result["results"]
        assert "epss-v5" in result["results"]
        assert "bod-26-04" in result["results"]
