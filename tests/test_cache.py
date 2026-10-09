import json
from unittest.mock import patch

import pytest

from rubricai.cache import FileCache


def test_dir_created_only_on_first_set(tmp_path):
    d = tmp_path / "cache"
    c = FileCache(d)
    assert not d.exists()
    assert c.get("ns", "k") is None
    assert not d.exists()
    c.set("ns", "k", 1)
    assert c.get("ns", "k") == 1


def test_ttl_expiry(tmp_path):
    c = FileCache(tmp_path)
    c.set("ns", "k", 1, ttl_hours=1)
    assert c.get("ns", "k") == 1
    with patch("rubricai.cache.time.time", return_value=9e12):
        assert c.get("ns", "k") is None


def test_failed_replace_keeps_previous_file(tmp_path):
    c = FileCache(tmp_path)
    c.set("ns", "a", 1)
    with patch("rubricai.cache.os.replace", side_effect=OSError("boom")):
        with pytest.raises(OSError, match="boom"):
            c.set("ns", "b", 2)
    assert json.loads((tmp_path / "ns.json").read_text())["a"]["value"] == 1
    assert c.get("ns", "a") == 1
    assert list(tmp_path.glob("*.tmp")) == []
