import shutil
import subprocess
import sys
from pathlib import Path


def test_no_new_secrets(tmp_path):
    tracked = Path(__file__).resolve().parent.parent / ".secrets.baseline"
    assert tracked.exists(), (
        ".secrets.baseline not found. "
        "Generate it with: detect-secrets scan > .secrets.baseline"
    )
    # Scan against a copy: detect-secrets rewrites the baseline it is given.
    baseline = tmp_path / ".secrets.baseline"
    shutil.copy(tracked, baseline)
    result = subprocess.run(  # pylint: disable=subprocess-run-check
        [sys.executable, "-m", "detect_secrets", "scan", "--baseline", str(baseline)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "detect-secrets found potential secrets not present in the baseline.\n\n"
        "To investigate:\n"
        "  detect-secrets scan --baseline .secrets.baseline\n"
        "  detect-secrets audit .secrets.baseline\n\n"
        f"Raw output:\n{result.stdout}\n{result.stderr}"
    )
