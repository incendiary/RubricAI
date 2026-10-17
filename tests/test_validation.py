"""Validation messages tell the client what IS allowed, without echoing input."""

import asyncio
import json
import re
import textwrap

import pytest
from fastmcp.exceptions import ToolError

from rubricai.schemas.finding import Component, Finding
from rubricai.schemas.intel import IntelResult
from rubricai.server import mcp
from rubricai.tools.scoring import score_evaluate
from rubricai.validation import validate_model

_FINDING = {
    "id": "FIND-001",
    "cve_or_id": "CVE-2024-3400",
    "component": {"name": "PAN-OS", "type": "appliance"},
    "entry_point": {"description": "GlobalProtect portal"},
    "reachability": "internet_exposed",
    "attacker_utility": ["rce"],
}
_INTEL = {
    "cve_or_id": "CVE-2024-3400",
    "retrieved_at": "2026-10-18T00:00:00Z",
    "sources": ["NVD"],
}


def _error(data, model=Finding, label="finding"):
    with pytest.raises(ValueError, match="^Invalid ") as exc:
        validate_model(model, data, label)
    return str(exc.value)


def test_valid_data_passes_through():
    assert validate_model(Finding, _FINDING, "finding").id == "FIND-001"


def test_unknown_top_level_field_lists_allowed_fields():
    msg = _error({**_FINDING, "cve": "CVE-2024-3400"})
    assert "finding.cve: unknown field" in msg
    for field in ("attacker_utility", "reachability", "entry_point", "component"):
        assert field in msg


def test_unknown_nested_field_lists_that_objects_fields():
    bad = {**_FINDING, "component": {"name": "PAN-OS", "device": "PA-3200"}}
    msg = _error(bad)
    assert "finding.component.device: unknown field" in msg
    assert "name, version, vendor, type" in msg


def test_component_accepts_vendor():
    assert Component(name="PAN-OS", vendor="Palo Alto Networks").vendor


def test_context_only_keys_get_a_specific_hint():
    msg = _error({**_FINDING, "cvss_av": "N", "confidence": "x"})
    assert "derived_finding_context" in msg
    assert "attacker_utility, entry_point and preconditions" in msg


def test_missing_required_fields_are_named():
    msg = _error({k: v for k, v in _FINDING.items() if k not in ("id", "cve_or_id")})
    assert "finding.id: required field is missing" in msg
    assert "finding.cve_or_id: required field is missing" in msg


def test_wrong_type_for_an_object_names_its_fields():
    msg = _error({**_FINDING, "component": "PAN-OS 11.1.0"})
    assert "finding.component" in msg
    assert "an object with fields: name, version, vendor, type" in msg


def test_input_values_are_never_echoed():
    secret = "super-secret-value-123"  # pragma: allowlist secret
    assert secret not in _error({**_FINDING, "token": secret})


def test_other_models_use_their_own_label():
    msg = _error({**_INTEL, "bogus": 1}, model=IntelResult, label="intel")
    assert "intel.bogus: unknown field" in msg


def test_score_evaluate_surfaces_the_friendly_message():
    with pytest.raises(ValueError, match="Allowed here"):
        score_evaluate({**_FINDING, "environment_name": "x"}, _INTEL)


def test_tool_error_carries_the_message_to_the_client():
    with pytest.raises(ToolError, match="finding.environment_name: unknown field"):
        asyncio.run(
            mcp.call_tool(
                "score_evaluate",
                {"finding": {**_FINDING, "environment_name": "x"}, "intel": _INTEL},
            )
        )


@pytest.mark.parametrize("tool", ["score_evaluate", "score_compare"])
def test_tool_description_contains_a_valid_example_finding(tool):
    description = next(
        t.description for t in asyncio.run(mcp.list_tools()) if t.name == tool
    )
    block = re.search(r"::\n\n(.*?)\n\n", description, re.S).group(1)
    example = json.loads(textwrap.dedent(block))
    assert validate_model(Finding, example, "finding").component.vendor
    assert "derived_finding_context" in description


def test_vendor_appears_in_the_generated_report():
    from rubricai.tools.report import report_generate

    finding = {
        **_FINDING,
        "component": {"name": "PAN-OS", "vendor": "Palo Alto Networks"},
    }
    assessment = score_evaluate(finding, _INTEL)
    result = report_generate(finding, _INTEL, assessment, formats=["markdown"])
    assert "| Vendor | Palo Alto Networks |" in result["report_markdown"]
