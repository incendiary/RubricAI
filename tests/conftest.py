"""Point every home-relative default at a session temp dir before the app imports."""

import atexit
import os
import shutil
import tempfile
from pathlib import Path


def pytest_configure(config):
    root = Path(tempfile.mkdtemp(prefix="rubricai-test-"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    os.environ["HOME"] = str(root)
    os.environ["RUBRICAI_ENV_DIR"] = str(root / "environments")
    os.environ["RUBRICAI_REPORT_DIR"] = str(root / "reports")
    os.environ["RUBRICAI_LOG_DIR"] = str(root / "logs")
