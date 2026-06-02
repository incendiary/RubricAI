import subprocess
import sys
from pathlib import Path


def test_no_new_secrets():
    baseline = Path(__file__).resolve().parent.parent / ".secrets.baseline"
    assert baseline.exists(), (
        ".secrets.baseline not found. "
        "Generate it with: detect-secrets scan > .secrets.baseline"
    )
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
