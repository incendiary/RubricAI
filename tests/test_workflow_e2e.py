"""End-to-end workflow test — full interview cycle in a single test (#51).

Chains: env_write → bom_update → bom_check → intel_lookup →
score_evaluate → report_generate
All network calls are mocked at the fetcher layer.
"""

from unittest.mock import AsyncMock, patch

import pytest

from src.rubricai.tools.bom import bom_check, bom_update
from src.rubricai.tools.environment import env_read, env_write
from src.rubricai.tools.intel import lookup as intel_lookup
from src.rubricai.tools.report import report_generate
from src.rubricai.tools.scoring import score_evaluate

_ENV = "test-e2e-workflow"

# --- Mock data matching what fetchers return ---

_MOCK_KEV = {"listed": True, "due_date": "2024-06-30", "notes": "Actively exploited"}
_MOCK_EPSS = {"score": 0.85, "percentile": 0.99, "date": "2026-06-01"}
_MOCK_NVD_RECORD = {
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ]
    },
    "references": [
        {"url": "https://exploit-db.com/exploits/99999", "tags": []},
        {"url": "https://vendor.example.com/advisory", "tags": ["Vendor Advisory"]},
    ],
}
_MOCK_NVD_SEARCH_RESULT = [
    {"id": "CVE-2024-9999", "description": "RCE in TestLib", "cvss_base": 9.8}
]
_MOCK_POC = {
    "available": True,
    "confidence": "high",
    "references": ["https://exploit-db.com/exploits/99999"],
}


@pytest.fixture(autouse=True)
def env_dirs(tmp_path, monkeypatch):
    """Redirect environment and report state to tmp_path."""
    monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path / "envs"))
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path / "reports"))


@pytest.fixture
def mock_network():
    """Mock all external fetcher calls."""
    with (
        patch(
            "src.rubricai.tools.intel.kev_fetcher.fetch",
            new=AsyncMock(return_value=_MOCK_KEV),
        ),
        patch(
            "src.rubricai.tools.intel.epss_fetcher.fetch",
            new=AsyncMock(return_value=_MOCK_EPSS),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch",
            new=AsyncMock(return_value=_MOCK_NVD_RECORD),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch_cvss",
            new=AsyncMock(
                return_value={
                    "base": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "version": "3.1",
                }
            ),
        ),
        patch(
            "src.rubricai.tools.intel.poc_fetcher.fetch",
            new=AsyncMock(return_value=_MOCK_POC),
        ),
        patch(
            "src.rubricai.tools.bom.nvd_fetcher.search",
            new=AsyncMock(return_value=_MOCK_NVD_SEARCH_RESULT),
        ),
    ):
        yield


class TestWorkflowE2E:
    """Full interview workflow: write state → BOM → intel → score → report."""

    @pytest.mark.asyncio
    async def test_full_workflow_produces_report(self, mock_network):
        # === Step 1: Initialise environment ===
        initial_state = {
            "schema_version": "1",
            "context": "Production DMZ web tier",
            "bom": [],
        }
        write_result = env_write(initial_state, _ENV)
        assert write_result["version"] == 1

        # === Step 2: Register BOM components ===
        bom_result = bom_update(
            [
                {"name": "nginx", "version": "1.24.0", "type": "service"},
                {"name": "openssl", "version": "3.1.4", "type": "library"},
            ],
            _ENV,
        )
        assert bom_result["stored"] == 2

        # === Step 3: BOM check for new CVEs ===
        check_result = await bom_check(_ENV, days_back=30)
        assert "total_cves" in check_result
        # Our mock returns 1 CVE per component
        assert check_result["total_cves"] >= 1

        # === Step 4: Deep intel lookup on discovered CVE ===
        intel_result = await intel_lookup(["CVE-2024-9999"])
        assert "results" in intel_result
        intel_data = intel_result["results"][0]
        assert intel_data["kev"]["listed"] is True
        assert intel_data["epss"]["score"] == 0.85

        # === Step 5: Score the finding ===
        finding = {
            "id": "FIND-E2E-001",
            "cve_or_id": "CVE-2024-9999",
            "component": {"name": "nginx", "version": "1.24.0"},
            "entry_point": {"description": "HTTPS/443 internet-facing"},
            "reachability": "internet_exposed",
            "attacker_utility": ["rce"],
            "mitigations": [],
            "preconditions": {
                "privileges_required": "none",
                "attack_complexity": "low",
                "user_interaction": False,
            },
        }
        score_result = score_evaluate(finding, intel_data)
        assert score_result["lane"] == "critical"
        assert "target" in score_result
        assert "rationale" in score_result

        # === Step 6: Generate report ===
        assessment = {
            "lane": score_result["lane"],
            "target": score_result["target"],
            "rationale": score_result["rationale"],
            "actions": ["Patch nginx immediately", "Verify WAF rule coverage"],
            "evidence_gaps": ["No compensating control evidence provided"],
            "policy_version": score_result.get("policy_version", "chml-v0.1"),
        }
        evidence = [
            {
                "claim": "Exploit is public on exploit-db",
                "type": "other",
                "content": "https://exploit-db.com/exploits/99999",
                "verified": True,
            }
        ]
        report_result = report_generate(
            finding,
            intel_data,
            assessment,
            formats=["markdown", "json"],
            evidence=evidence,
        )
        assert "report_markdown" in report_result
        assert "report_json" in report_result
        assert len(report_result["saved_to"]) >= 2
        assert "critical" in report_result["report_markdown"].lower()

        # === Step 7: Save updated session state ===
        read_result = env_read(_ENV)
        updated_state = read_result.copy()
        updated_state.pop("environment_name", None)
        updated_state["session_log"] = [
            {"summary": "Assessed CVE-2024-9999 — Critical lane, 72h SLA"}
        ]
        final_write = env_write(updated_state, _ENV)
        # Version was 1 after BOM update (which calls env_write internally),
        # so the next version should be > 1
        assert final_write["version"] > 1

    @pytest.mark.asyncio
    async def test_workflow_with_mitigations_lowers_lane(self, mock_network):
        """Same scenario but with strong mitigations.

        Strong mitigations → lane should drop below Critical.
        """
        initial_state = {
            "schema_version": "1",
            "context": "Internal-only staging env",
            "bom": [],
        }
        env_write(initial_state, _ENV)
        bom_update([{"name": "openssl", "version": "3.1.4"}], _ENV)

        intel_result = await intel_lookup(["CVE-2024-9999"])
        intel_data = intel_result["results"][0]

        finding = {
            "id": "FIND-E2E-002",
            "cve_or_id": "CVE-2024-9999",
            "component": {"name": "openssl", "version": "3.1.4"},
            "entry_point": {"description": "Internal only, behind VPN"},
            "reachability": "internal",
            "attacker_utility": ["data_access"],
            "mitigations": [
                {
                    "type": "acl_segmentation",
                    "description": (
                        "Network segmentation —"
                        " component not reachable from internet"
                    ),
                    "evidence": ["Firewall rules verified 2026-06-01"],
                },
                {
                    "type": "waf_rule",
                    "description": "WAF blocks known exploit patterns",
                    "evidence": ["WAF rule ID 4412 active"],
                },
            ],
            "preconditions": {
                "privileges_required": "high",
                "attack_complexity": "high",
                "user_interaction": True,
            },
        }
        score_result = score_evaluate(finding, intel_data)
        # With internal + mitigations, should not be critical
        assert score_result["lane"] in ("high", "medium", "low")
