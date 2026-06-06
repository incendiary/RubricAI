#!/usr/bin/env python3
"""Render the platform-agnostic workflow into a platform-specific system prompt.

Usage:
    python scripts/render_prompt.py --target claude
    python scripts/render_prompt.py --target generic
    python scripts/render_prompt.py --target gemini

Output is written to prompts/out/<target>_system_prompt.md
"""

import argparse
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"
WORKFLOW_FILE = PROMPTS_DIR / "workflow.md"
TEMPLATES_DIR = PROMPTS_DIR / "templates"
OUT_DIR = PROMPTS_DIR / "out"

TARGETS = ["claude", "generic", "gemini", "openai"]


def render(target: str) -> Path:
    template_file = f"{target}.md.j2"
    if not (TEMPLATES_DIR / template_file).exists():
        raise FileNotFoundError(
            f"No template found for target '{target}': {TEMPLATES_DIR / template_file}"
        )

    workflow = WORKFLOW_FILE.read_text(encoding="utf-8")

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        keep_trailing_newline=True,
    )
    template = env.get_template(template_file)
    rendered = template.render(workflow=workflow)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"{target}_system_prompt.md"
    out_path.write_text(rendered, encoding="utf-8")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render RubricAI system prompt for a target platform."
    )
    parser.add_argument(
        "--target",
        choices=TARGETS,
        required=True,
        help=f"Target platform: {', '.join(TARGETS)}",
    )
    args = parser.parse_args()

    out_path = render(args.target)
    print(f"Written: {out_path}")


if __name__ == "__main__":
    main()
