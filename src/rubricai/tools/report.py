"""report.generate MCP tool — produces markdown + JSON report cards."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..schemas.assessment import Assessment
from ..schemas.evidence import EvidenceItem
from ..schemas.finding import Finding
from ..schemas.intel import IntelResult

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_DEFAULT_REPORT_DIR = Path.home() / ".local" / "share" / "rubricai" / "reports"


def _report_dir() -> Path:
    p = Path(os.getenv("RUBRICAI_REPORT_DIR", str(_DEFAULT_REPORT_DIR)))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _render_markdown(
    finding: Finding,
    intel: IntelResult,
    assessment: Assessment,
    evidence: list[EvidenceItem],
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")
    return template.render(
        finding=finding,
        intel=intel,
        assessment=assessment,
        evidence=evidence,
        generated_at=datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def report_generate(
    finding: dict[str, Any],
    intel: dict[str, Any],
    assessment: dict[str, Any],
    formats: list[str] | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate and persist a standardised report card.

    Args:
        finding: Finding dict (engineer-provided context).
        intel: IntelResult dict (from intel.lookup).
        assessment: Assessment dict (from score.evaluate).
        formats: List of output formats. Defaults to ``["markdown", "json"]``.
        evidence: Optional list of EvidenceItem dicts. Each item captures a
                  claim, supporting content, and whether the AI assessed it
                  as verified. Stored in the JSON report and rendered in the
                  markdown Evidence section.

    Returns:
        Dict with ``report_markdown``, ``report_json``, ``saved_to``, and
        ``has_verified_evidence`` keys.
    """
    requested = set(formats or ["markdown", "json"])

    f = Finding.model_validate(finding)
    # Strip AI-use fields not in IntelResult schema (e.g. derived_finding_context)
    intel_clean = {k: v for k, v in intel.items() if k != "derived_finding_context"}
    i = IntelResult.model_validate(intel_clean)
    a = Assessment.model_validate(assessment)
    ev = [EvidenceItem.model_validate(e) for e in (evidence or [])]

    ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    base_name = f"{f.id}_{ts}"
    report_dir = _report_dir()

    has_verified = any(e.verified for e in ev)
    result: dict[str, Any] = {"has_verified_evidence": has_verified}
    saved_paths: list[str] = []

    if "markdown" in requested:
        md = _render_markdown(f, i, a, ev)
        md_path = report_dir / f"{base_name}.md"
        md_path.write_text(md, encoding="utf-8")
        saved_paths.append(str(md_path))
        result["report_markdown"] = md

    if "json" in requested:
        report_json = {
            "finding": f.model_dump(mode="json"),
            "intel": i.model_dump(mode="json"),
            "assessment": a.model_dump(mode="json"),
            "evidence": [e.model_dump(mode="json") for e in ev],
            "has_verified_evidence": has_verified,
        }
        json_path = report_dir / f"{base_name}.json"
        json_path.write_text(
            json.dumps(report_json, indent=2, default=str), encoding="utf-8"
        )
        saved_paths.append(str(json_path))
        result["report_json"] = report_json

    result["saved_to"] = saved_paths
    return result
