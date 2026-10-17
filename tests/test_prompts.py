"""The rendered client prompts carry the workflow steps the assistant must follow."""

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
