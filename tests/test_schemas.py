"""Schema validation tests — no network, no MCP."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.rubricai.schemas.assessment import (
    Assessment,
)
from src.rubricai.schemas.finding import (
    Finding,
)
from src.rubricai.schemas.intel import (
    IntelResult,
)


def _minimal_finding(**overrides) -> dict:
    base = {
        "id": "FIND-001",
        "cve_or_id": "CVE-2024-1234",
        "component": {"name": "ExampleLib", "version": "1.0.0"},
        "entry_point": {"description": "POST /api/login"},
        "reachability": "internet_exposed",
        "attacker_utility": ["auth_bypass"],
    }
    base.update(overrides)
    return base


def _minimal_intel(**overrides) -> dict:
    base = {
        "cve_or_id": "CVE-2024-1234",
        "retrieved_at": datetime.now(tz=UTC).isoformat(),
        "sources": ["NVD"],
    }
    base.update(overrides)
    return base


class TestFindingSchema:
    def test_minimal_valid(self):
        f = Finding.model_validate(_minimal_finding())
        assert f.id == "FIND-001"
        assert f.reachability == "internet_exposed"

    def test_attacker_utility_must_have_one_item(self):
        with pytest.raises(ValidationError):
            Finding.model_validate(_minimal_finding(attacker_utility=[]))

    def test_invalid_reachability(self):
        with pytest.raises(ValidationError):
            Finding.model_validate(_minimal_finding(reachability="public"))

    def test_extra_fields_forbidden(self):
        data = _minimal_finding()
        data["unexpected_field"] = "boom"
        with pytest.raises(ValidationError):
            Finding.model_validate(data)

    def test_mitigation_with_causal_claim(self):
        f = Finding.model_validate(
            _minimal_finding(
                mitigations=[
                    {
                        "type": "waf_rule",
                        "description": "Blocks exploit pattern",
                        "causal_claim": "Blocks the vulnerable route entirely",
                        "evidence": ["WAF-RULE-001"],
                    }
                ]
            )
        )
        assert f.mitigations[0].causal_claim == "Blocks the vulnerable route entirely"

    def test_port_bounds(self):
        with pytest.raises(ValidationError):
            Finding.model_validate(
                _minimal_finding(entry_point={"description": "SSH", "port": 0})
            )
        with pytest.raises(ValidationError):
            Finding.model_validate(
                _minimal_finding(entry_point={"description": "SSH", "port": 65536})
            )


class TestIntelResultSchema:
    def test_minimal_valid(self):
        r = IntelResult.model_validate(_minimal_intel())
        assert r.cve_or_id == "CVE-2024-1234"
        assert r.kev is None

    def test_epss_bounds(self):
        with pytest.raises(ValidationError):
            IntelResult.model_validate(
                _minimal_intel(epss={"score": 1.5, "percentile": 0.9})
            )

    def test_cvss_bounds(self):
        with pytest.raises(ValidationError):
            IntelResult.model_validate(
                _minimal_intel(cvss={"base": 11.0, "version": "3.1"})
            )

    def test_full_intel(self):
        r = IntelResult.model_validate(
            _minimal_intel(
                sources=["CISA_KEV", "FIRST_EPSS", "NVD"],
                kev={"listed": True, "due_date": "2024-06-30"},
                epss={"score": 0.72, "percentile": 0.97},
                cvss={
                    "base": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "version": "3.1",
                },
                poc={"available": True, "confidence": "medium"},
                vendor={"patch_available": True, "advisory_refs": ["SA-2024-001"]},
            )
        )
        assert r.kev.listed is True
        assert r.epss.score == 0.72
        assert r.poc.available is True


class TestAssessmentSchema:
    def test_valid_assessment(self):
        a = Assessment.model_validate(
            {
                "policy_version": "chml-v0.1",
                "lane": "critical",
                "target": {"days": 3, "basis": "kev_listed + internet_exposed"},
                "rationale": ["KEV listed"],
                "evidence_gaps": [],
            }
        )
        assert a.lane == "critical"
        assert a.target.days == 3

    def test_invalid_lane(self):
        with pytest.raises(ValidationError):
            Assessment.model_validate(
                {
                    "policy_version": "chml-v0.1",
                    "lane": "urgent",
                    "target": {"days": 1},
                    "rationale": [],
                    "evidence_gaps": [],
                }
            )


class TestFindingNewFields:
    def test_ticket_id_accepted(self):
        f = Finding.model_validate(
            {
                "id": "FIND-001",
                "ticket_id": "JIRA-1234",
                "cve_or_id": "CVE-2024-9999",
                "component": {"name": "nginx", "version": "1.25.3"},
                "entry_point": {"description": "TCP 443"},
                "reachability": "internet_exposed",
                "attacker_utility": ["rce"],
            }
        )
        assert f.ticket_id == "JIRA-1234"

    def test_ticket_id_optional(self):
        f = Finding.model_validate(
            {
                "id": "FIND-001",
                "cve_or_id": "CVE-2024-9999",
                "component": {"name": "nginx", "version": "1.25.3"},
                "entry_point": {"description": "TCP 443"},
                "reachability": "internet_exposed",
                "attacker_utility": ["rce"],
            }
        )
        assert f.ticket_id is None

    def test_vendor_patch_mitigation_accepted(self):
        f = Finding.model_validate(
            {
                "id": "FIND-001",
                "cve_or_id": "CVE-2024-9999",
                "component": {"name": "nginx", "version": "1.25.3"},
                "entry_point": {"description": "TCP 443"},
                "reachability": "internet_exposed",
                "attacker_utility": ["rce"],
                "mitigations": [
                    {
                        "type": "vendor_patch",
                        "description": "Upgraded to 1.26.1.",
                        "causal_claim": "Patch eliminates the vulnerable code path.",
                        "evidence": ["JIRA-001"],
                    }
                ],
            }
        )
        assert f.mitigations[0].type == "vendor_patch"
