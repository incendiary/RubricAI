"""Findings and reports carry the name of the environment they belong to."""

import json

import pytest

from rubricai.schemas.assessment import Assessment
from rubricai.schemas.finding import Finding
from rubricai.schemas.intel import IntelResult
from rubricai.tools.report import _render_html_card, report_generate
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


def _report(finding):
    assessment = score_evaluate(finding, _INTEL)
    return report_generate(finding, _INTEL, assessment, formats=["markdown", "json"])


def test_environment_name_defaults_to_none():
    assert Finding.model_validate(_FINDING).environment_name is None


@pytest.mark.parametrize(
    ("given", "stored"),
    [("production-edge", "production-edge"), ("Production Edge", "production-edge")],
)
def test_environment_name_is_normalised_like_the_environment_tools(given, stored):
    finding = Finding.model_validate({**_FINDING, "environment_name": given})
    assert finding.environment_name == stored


@pytest.mark.parametrize("bad", ["../etc", "a/b", "", "x" * 80])
def test_invalid_environment_name_is_rejected_with_a_clear_message(bad):
    with pytest.raises(ValueError, match="Invalid environment name"):
        validate_model(Finding, {**_FINDING, "environment_name": bad}, "finding")


def test_report_markdown_and_json_show_the_environment():
    result = _report({**_FINDING, "environment_name": "production-edge"})
    assert "| Environment | production-edge |" in result["report_markdown"]
    assert result["report_json"]["finding"]["environment_name"] == "production-edge"
    saved = [p for p in result["saved_to"] if str(p).endswith(".json")]
    with open(saved[0]) as handle:
        assert json.load(handle)["finding"]["environment_name"] == "production-edge"


def test_report_without_an_environment_is_unchanged():
    result = _report(_FINDING)
    assert "| Environment |" not in result["report_markdown"]
    assert result["report_json"]["finding"]["environment_name"] is None


def test_pdf_card_html_shows_the_environment():
    finding = {**_FINDING, "environment_name": "production-edge"}
    html = _render_html_card(
        Finding.model_validate(finding),
        IntelResult.model_validate(_INTEL),
        Assessment.model_validate(score_evaluate(finding, _INTEL)),
        [],
    )
    assert "env: production-edge" in html
