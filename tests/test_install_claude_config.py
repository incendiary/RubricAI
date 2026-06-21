"""Regression tests for scripts/install_claude_config.py."""

import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / "scripts" / "install_claude_config.py"
    spec = spec_from_file_location("install_claude_config", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_merge_preserves_existing_env_vars(tmp_path):
    module = _load_module()

    existing = {
        "mcpServers": {
            "rubricai": {
                "command": "/custom/rubricai",
                "args": [],
                "cwd": "/tmp/old",
                "env": {
                    "NVD_API_KEY": "secret-key",
                    "CUSTOM_FLAG": "enabled",
                    "RUBRICAI_TRANSPORT": "sse",
                },
            }
        }
    }

    merged = module._merge(existing, tmp_path)
    env = merged["mcpServers"]["rubricai"]["env"]

    # Existing user-provided variables should be retained.
    assert env["NVD_API_KEY"] == "secret-key"
    assert env["CUSTOM_FLAG"] == "enabled"

    # Template values should win where keys overlap.
    assert env["RUBRICAI_TRANSPORT"] == "stdio"
    assert env["RUBRICAI_REPORT_DIR"] == str(tmp_path.resolve() / "reports")


def test_main_refuses_to_write_when_entry_point_is_missing(tmp_path, monkeypatch):
    module = _load_module()

    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

    monkeypatch.setattr(module.sys, "argv", [
        "install_claude_config.py",
        "--config",
        str(config_path),
        "--cwd",
        str(tmp_path),
        "--write",
    ])
    monkeypatch.setattr(module, "_entry_point_exists", lambda project_root: False)

    stderr = pytest.MonkeyPatch()
    with redirect_stdout(sys.stdout), redirect_stderr(sys.stderr):
        with pytest.raises(SystemExit) as excinfo:
            module.main()

    assert excinfo.value.code == 1
    assert config_path.read_text(encoding="utf-8") == json.dumps({"mcpServers": {}})


def test_main_force_writes_even_when_entry_point_is_missing(tmp_path, monkeypatch):
    module = _load_module()

    config_path = tmp_path / "claude_desktop_config.json"
    monkeypatch.setattr(module.sys, "argv", [
        "install_claude_config.py",
        "--config",
        str(config_path),
        "--cwd",
        str(tmp_path),
        "--write",
        "--force",
    ])
    monkeypatch.setattr(module, "_entry_point_exists", lambda project_root: False)

    module.main()

    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert written["mcpServers"]["rubricai"]["cwd"] == str(tmp_path.resolve())
