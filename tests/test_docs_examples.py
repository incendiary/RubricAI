"""Checks for docs/examples.md CVE data quality."""

import re
from pathlib import Path

_EXAMPLES = Path(__file__).resolve().parents[1] / "docs" / "examples.md"


def test_examples_uses_real_cves_not_fabricated_2026_ids():
    text = _EXAMPLES.read_text(encoding="utf-8")
    assert "CVE-2026-" not in text, "Found fabricated CVE-2026 IDs in docs/examples.md"


def test_examples_contains_expected_real_cves():
    text = _EXAMPLES.read_text(encoding="utf-8")
    cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", text))

    expected = {
        "CVE-2024-3400",
        "CVE-2024-24762",
        "CVE-2024-23334",
        "CVE-2024-1086",
    }
    missing = expected - cves
    assert not missing, f"Missing expected CVEs in docs/examples.md: {sorted(missing)}"
