"""Tests for fetchers and intel.lookup — mocked network, real cache logic."""

import json
import time
from unittest.mock import AsyncMock, patch

import pytest

from src.rubricai.cache import FileCache
from src.rubricai.tools.intel import lookup

# ---------------------------------------------------------------------------
# FileCache unit tests
# ---------------------------------------------------------------------------


class TestFileCache:
    def test_miss_on_empty(self, tmp_path):
        cache = FileCache(tmp_path)
        assert cache.get("ns", "key") is None

    def test_set_and_get(self, tmp_path):
        cache = FileCache(tmp_path)
        cache.set("ns", "key", {"score": 0.5}, ttl_hours=1)
        assert cache.get("ns", "key") == {"score": 0.5}

    def test_expired_entry_returns_none(self, tmp_path):
        cache = FileCache(tmp_path)
        store_path = tmp_path / "ns.json"
        store_path.write_text(
            json.dumps({"key": {"value": "old", "expires_at": time.time() - 1}})
        )
        assert cache.get("ns", "key") is None

    def test_different_namespaces_isolated(self, tmp_path):
        cache = FileCache(tmp_path)
        cache.set("a", "k", "val_a")
        cache.set("b", "k", "val_b")
        assert cache.get("a", "k") == "val_a"
        assert cache.get("b", "k") == "val_b"

    def test_corrupted_file_returns_empty(self, tmp_path):
        cache = FileCache(tmp_path)
        (tmp_path / "ns.json").write_text("not json")
        assert cache.get("ns", "key") is None


# ---------------------------------------------------------------------------
# intel.lookup integration (mocked fetchers)
# ---------------------------------------------------------------------------

_MOCK_KEV = {"listed": True, "due_date": "2024-06-30", "notes": "Actively exploited"}
_MOCK_EPSS = {"score": 0.72, "percentile": 0.97, "date": "2024-05-10"}
_MOCK_NVD_RECORD = {
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ]
    },
    "references": [
        {"url": "https://exploit-db.com/exploits/12345", "tags": []},
        {"url": "https://vendor.example.com/advisory", "tags": ["Vendor Advisory"]},
    ],
}


@pytest.fixture
def mock_fetchers():
    with (
        patch(
            "src.rubricai.tools.intel.kev_fetcher.fetch",
            new=AsyncMock(return_value=_MOCK_KEV),
        ),
        patch(
            "src.rubricai.tools.intel.epss_fetcher.fetch",
            new=AsyncMock(return_value=_MOCK_EPSS),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch",
            new=AsyncMock(return_value=_MOCK_NVD_RECORD),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch_cvss",
            new=AsyncMock(
                return_value={"base": 9.8, "vector": "CVSS:3.1/...", "version": "3.1"}
            ),
        ),
        patch(
            "src.rubricai.tools.intel.poc_fetcher.fetch",
            new=AsyncMock(
                return_value={
                    "available": True,
                    "confidence": "high",
                    "references": ["https://exploit-db.com/exploits/12345"],
                }
            ),
        ),
    ):
        yield


@pytest.mark.asyncio
async def test_lookup_returns_result(mock_fetchers):
    result = await lookup(["CVE-2024-1234"])
    assert "results" in result
    assert len(result["results"]) == 1
    r = result["results"][0]
    assert r["cve_or_id"] == "CVE-2024-1234"
    assert r["kev"]["listed"] is True
    assert r["epss"]["score"] == 0.72
    assert r["poc"]["available"] is True


@pytest.mark.asyncio
async def test_lookup_multiple_cves(mock_fetchers):
    result = await lookup(["CVE-2024-0001", "CVE-2024-0002"])
    assert len(result["results"]) == 2


@pytest.mark.asyncio
async def test_lookup_include_subset(mock_fetchers):
    result = await lookup(["CVE-2024-1234"], include=["kev", "epss"])
    r = result["results"][0]
    assert r["kev"]["listed"] is True
    assert r["epss"]["score"] == 0.72
    # poc not requested — should be None
    assert r["poc"] is None


@pytest.mark.asyncio
async def test_lookup_kev_not_listed():
    with (
        patch(
            "src.rubricai.tools.intel.kev_fetcher.fetch",
            new=AsyncMock(return_value={"listed": False}),
        ),
        patch(
            "src.rubricai.tools.intel.epss_fetcher.fetch",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch_cvss",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "src.rubricai.tools.intel.poc_fetcher.fetch",
            new=AsyncMock(
                return_value={
                    "available": False,
                    "confidence": "unknown",
                    "references": [],
                }
            ),
        ),
    ):
        result = await lookup(["CVE-2099-0000"])
    r = result["results"][0]
    assert r["kev"]["listed"] is False
    assert r["epss"] is None
