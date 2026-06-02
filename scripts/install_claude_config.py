#!/usr/bin/env python3
"""Merge the RubricAI MCP server entry into claude_desktop_config.json.

Usage:
    # Preview what will change (dry-run, default)
    python scripts/install_claude_config.py

    # Write the merged config
    python scripts/install_claude_config.py --write

    # Custom config path (e.g. non-standard Claude install)
    python scripts/install_claude_config.py --config ~/my-config.json --write

    # Override the RubricAI project root (default: current directory)
    python scripts/install_claude_config.py --cwd /path/to/RubricAI --write
"""

import argparse
import difflib
import json
import os
import pathlib
import sys


def _default_config_path() -> pathlib.Path:
    if sys.platform == "darwin":
        return (
            pathlib.Path.home()
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    if sys.platform == "win32":
        return (
            pathlib.Path(os.environ["APPDATA"])
            / "Claude"
            / "claude_desktop_config.json"
        )
    # Linux / other
    return pathlib.Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def _rubricai_entry(project_root: pathlib.Path) -> dict:
    return {
        "command": "python",
        "args": ["-m", "src.main"],
        "cwd": str(project_root.resolve()),
        "env": {
            "RUBRICAI_TRANSPORT": "stdio",
            "RUBRICAI_REPORT_DIR": str((project_root / "reports").resolve()),
        },
    }


def _merge(existing: dict, project_root: pathlib.Path) -> dict:
    merged = dict(existing)
    merged.setdefault("mcpServers", {})
    merged["mcpServers"]["rubricai"] = _rubricai_entry(project_root)
    return merged


def _format(config: dict) -> str:
    return json.dumps(config, indent=2) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge the RubricAI entry into claude_desktop_config.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=None,
        metavar="PATH",
        help="Path to claude_desktop_config.json (auto-detected if omitted)",
    )
    parser.add_argument(
        "--cwd",
        type=pathlib.Path,
        default=pathlib.Path.cwd(),
        metavar="DIR",
        help="RubricAI project root (default: current directory)",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the merged config to disk (default: dry-run / preview only)",
    )
    args = parser.parse_args()

    config_path: pathlib.Path = args.config or _default_config_path()

    if config_path.exists():
        try:
            existing = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"Error: {config_path} is not valid JSON — {exc}", file=sys.stderr)
            sys.exit(1)
        original_text = _format(existing)
    else:
        existing = {}
        original_text = None

    merged = _merge(existing, args.cwd)
    merged_text = _format(merged)

    # --- Compute diff ---
    if original_text is not None:
        diff_lines = list(
            difflib.unified_diff(
                original_text.splitlines(keepends=True),
                merged_text.splitlines(keepends=True),
                fromfile=f"{config_path} (current)",
                tofile=f"{config_path} (merged)",
            )
        )
        has_changes = bool(diff_lines)
    else:
        diff_lines = []
        has_changes = True  # new file

    # --- Report ---
    print(f"Config path : {config_path}")
    print(f"Project root: {args.cwd.resolve()}")
    print()

    if not has_changes:
        print("No changes — rubricai entry is already up to date.")
        return

    if original_text is None:
        print("Config file not found — will be created with:")
        print()
        print(merged_text)
    else:
        print("Changes to apply:")
        print()
        # Colour the diff if the terminal supports it
        use_colour = sys.stdout.isatty()
        for line in diff_lines:
            if use_colour:
                if line.startswith("+") and not line.startswith("+++"):
                    print(f"\033[32m{line}\033[0m", end="")
                elif line.startswith("-") and not line.startswith("---"):
                    print(f"\033[31m{line}\033[0m", end="")
                else:
                    print(line, end="")
            else:
                print(line, end="")
        print()

    if args.write:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(merged_text, encoding="utf-8")
        print(f"Written to {config_path}")
        print()
        print("Restart Claude Desktop to pick up the change.")
    else:
        print("Dry run — pass --write to apply.")


if __name__ == "__main__":
    main()
