"""The rendered client prompts carry the workflow steps the assistant must follow."""

import re

import pytest

from scripts import render_prompt


@pytest.mark.parametrize("target", render_prompt.TARGETS)
def test_every_client_prompt_checks_for_earlier_assessments(
    target, tmp_path, monkeypatch
):
    monkeypatch.setattr(render_prompt, "OUT_DIR", tmp_path)
    text = render_prompt.render(target).read_text(encoding="utf-8")
    step = text.index("Check what the environment already records about this CVE")
    assert "session_log" in text[step : step + 600]
    # The check sits after the CVE is known and before intel/scoring begins.
    assert (
        text.index("Minimal initial questions")
        < step
        < text.index("Call intel_lookup immediately")
    )
    assert "same asset" in text[step : step + 1200]


def _workflow_text():
    return render_prompt.WORKFLOW_FILE.read_text(encoding="utf-8")


@pytest.mark.parametrize("target", render_prompt.TARGETS)
def test_every_client_prompt_lists_every_registered_tool(target, tmp_path, monkeypatch):
    import asyncio

    from rubricai.server import mcp

    monkeypatch.setattr(render_prompt, "OUT_DIR", tmp_path)
    text = render_prompt.render(target).read_text(encoding="utf-8")
    registered = {t.name for t in asyncio.run(mcp.list_tools())}
    assert {name for name in registered if f"`{name}`" not in text} == set()
    # No row for a tool that no longer exists
    template = (render_prompt.TEMPLATES_DIR / f"{target}.md.j2").read_text("utf-8")
    rows = set(re.findall(r"^\| `(\w+)` \|", template, re.M))
    assert rows - registered == set()
    claimed = re.findall(r"\*\*(\d+) MCP tools\*\*", text)
    assert all(int(n) == len(registered) for n in claimed)


def test_workflow_documents_every_finding_field_and_enum_value():
    from typing import get_args

    from rubricai.schemas import finding as schema

    text = _workflow_text()
    for model in (
        schema.Finding,
        schema.Component,
        schema.Environment,
        schema.EntryPoint,
        schema.Preconditions,
        schema.DataImpact,
        schema.Mitigation,
        schema.EvidencePointer,
    ):
        for field in model.model_fields:
            assert re.search(rf'[`"]{field}[`"]', text), f"{model.__name__}.{field}"
    for model in (schema.Mitigation, schema.EvidencePointer):
        for value in get_args(model.model_fields["type"].annotation):
            assert f'"{value}"' in text, f"{model.__name__}.type {value}"


def test_step_1b_defines_matching_and_unattended_behaviour():
    text = _workflow_text()
    step = text[text.index("Step 1b") : text.index("Step 2 — Call intel_lookup")]
    for phrase in (
        "CVE ID",
        "both its name and its version",
        "Unattended runs",
        "do not wait",
    ):
        assert phrase in step


def test_workflow_warns_that_env_write_replaces_state():
    assert "replaces the whole saved state" in _workflow_text()
