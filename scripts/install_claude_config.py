#!/usr/bin/env python3
"""Merge the RubricAI MCP server entry into claude_desktop_config.json.

Usage:
    # Preview what will change (dry-run, default)
    python scripts/install_claude_config.py

    # Write the merged config
    python scripts/install_claude_config.py --write

    # Force writing even if the RubricAI entry point is missing
    python scripts/install_claude_config.py --write --force

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
    # Use the installed console script rather than `python -m src.main`.
    # `src` is a layout convention and is not importable after `pip install -e .`
    # (only `rubricai` is installed). The `rubricai` entry point script is
    # created by pip in .venv/bin/ and works without any module path gymnastics.
    root = project_root.resolve()
    if sys.platform == "win32":
        command = str(root / ".venv" / "Scripts" / "rubricai.exe")
    else:
        command = str(root / ".venv" / "bin" / "rubricai")
    return {
        "command": command,
        "args": [],
        "cwd": str(root),
        "env": {
            "RUBRICAI_TRANSPORT": "stdio",
            "RUBRICAI_REPORT_DIR": str(root / "reports"),
        },
    }


def _entry_point_exists(project_root: pathlib.Path) -> bool:
    entry = pathlib.Path(_rubricai_entry(project_root)["command"])
    return entry.exists()


def _print_setup_steps(project_root: pathlib.Path) -> None:
    root = project_root.resolve()
    print("Error: RubricAI entry point not found.", file=sys.stderr)
    print("Set up the local virtual environment first:", file=sys.stderr)
    print(file=sys.stderr)
    print(f"  cd {root}", file=sys.stderr)
    print("  python3 -m venv .venv", file=sys.stderr)
    print("  source .venv/bin/activate", file=sys.stderr)
    print('  pip install -e ".[dev]"', file=sys.stderr)
    print(file=sys.stderr)
    print("Then rerun this script, or pass --force to write anyway.", file=sys.stderr)


def _merge(existing: dict, project_root: pathlib.Path) -> dict:
    merged = dict(existing)
    merged.setdefault("mcpServers", {})
    new_entry = _rubricai_entry(project_root)
    # Preserve env vars already in the config (e.g. NVD_API_KEY) that our
    # template doesn't set. New template values take precedence on overlap.
    existing_env = merged["mcpServers"].get("rubricai", {}).get("env", {})
    new_entry["env"] = {**existing_env, **new_entry["env"]}
    merged["mcpServers"]["rubricai"] = new_entry
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
    parser.add_argument(
        "--force",
        action="store_true",
        help="Write the config even if the RubricAI entry point is missing",
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
        if not _entry_point_exists(args.cwd) and not args.force:
            _print_setup_steps(args.cwd)
            sys.exit(1)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        # Back up the existing config before writing so it can be restored manually
        # if something goes wrong.
        if config_path.exists():
            backup_path = config_path.with_suffix(".json.bak")
            backup_path.write_text(
                config_path.read_text(encoding="utf-8"), encoding="utf-8"
            )
            print(f"Backup written to {backup_path}")
        config_path.write_text(merged_text, encoding="utf-8")
        print(f"Written to {config_path}")
        print()
        print("Restart Claude Desktop to pick up the change.")
    else:
        print("Dry run — pass --write to apply.")


if __name__ == "__main__":
    main()
