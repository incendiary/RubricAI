"""Regression tests for scripts/install_claude_config.py."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


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
