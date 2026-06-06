"""Tests for individual fetchers and end-to-end pipeline.

Fetcher tests mock httpx.AsyncClient and patch the module-level _cache with a
FileCache(tmp_path) so each test runs with an isolated, real cache. This exercises
the full parsing and caching logic without making network calls.

End-to-end tests mock at the fetcher-function level (same approach as test_intel.py)
and verify that lookup → score_evaluate → report_generate composes correctly.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.rubricai.cache import FileCache
from src.rubricai.fetchers import epss as epss_fetcher
from src.rubricai.fetchers import kev as kev_fetcher
from src.rubricai.fetchers import nvd as nvd_fetcher
from src.rubricai.fetchers import poc as poc_fetcher
from src.rubricai.fetchers.poc import _classify
from src.rubricai.tools.intel import lookup
from src.rubricai.tools.report import report_generate
from src.rubricai.tools.scoring import score_evaluate

# ---------------------------------------------------------------------------
# Shared HTTP mock helpers
# ---------------------------------------------------------------------------


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


def _mock_client(response):
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


# ---------------------------------------------------------------------------
# KEV fetcher
# ---------------------------------------------------------------------------

_KEV_CATALOG = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-1234",
            "dueDate": "2024-06-30",
            "shortDescription": "Actively exploited in the wild",
        }
    ]
}


async def test_kev_listed(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_KEV_CATALOG))
    with (
        patch.object(kev_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.kev.httpx.AsyncClient", return_value=client),
    ):
        result = await kev_fetcher.fetch("CVE-2024-1234")
    assert result["listed"] is True
    assert result["due_date"] == "2024-06-30"
    assert "Actively exploited" in result["notes"]


async def test_kev_not_listed(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_KEV_CATALOG))
    with (
        patch.object(kev_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.kev.httpx.AsyncClient", return_value=client),
    ):
        result = await kev_fetcher.fetch("CVE-9999-9999")
    assert result == {"listed": False}


async def test_kev_case_insensitive_lookup(tmp_path):
    """CVE IDs should be normalised to uppercase before lookup."""
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_KEV_CATALOG))
    with (
        patch.object(kev_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.kev.httpx.AsyncClient", return_value=client),
    ):
        result = await kev_fetcher.fetch("cve-2024-1234")
    assert result["listed"] is True


async def test_kev_cache_prevents_second_http_call(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_KEV_CATALOG))
    with (
        patch.object(kev_fetcher, "_cache", cache),
        patch(
            "src.rubricai.fetchers.kev.httpx.AsyncClient", return_value=client
        ) as mock_cls,
    ):
        await kev_fetcher.fetch("CVE-2024-1234")
        await kev_fetcher.fetch("CVE-2024-1234")
    # Catalog downloaded once; second call hits cache
    assert mock_cls.call_count == 1


# ---------------------------------------------------------------------------
# EPSS fetcher
# ---------------------------------------------------------------------------

_EPSS_RESPONSE = {
    "data": [{"epss": "0.72345", "percentile": "0.97123", "date": "2024-05-10"}]
}


async def test_epss_returns_parsed_score(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_EPSS_RESPONSE))
    with (
        patch.object(epss_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.epss.httpx.AsyncClient", return_value=client),
    ):
        result = await epss_fetcher.fetch("CVE-2024-5678")
    assert result["score"] == pytest.approx(0.72345)
    assert result["percentile"] == pytest.approx(0.97123)
    assert result["date"] == "2024-05-10"


async def test_epss_empty_data_returns_none(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response({"data": []}))
    with (
        patch.object(epss_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.epss.httpx.AsyncClient", return_value=client),
    ):
        result = await epss_fetcher.fetch("CVE-2099-0001")
    assert result is None


async def test_epss_cache_prevents_second_http_call(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_EPSS_RESPONSE))
    with (
        patch.object(epss_fetcher, "_cache", cache),
        patch(
            "src.rubricai.fetchers.epss.httpx.AsyncClient", return_value=client
        ) as mock_cls,
    ):
        await epss_fetcher.fetch("CVE-2024-5678")
        await epss_fetcher.fetch("CVE-2024-5678")
    assert mock_cls.call_count == 1


# ---------------------------------------------------------------------------
# NVD fetcher
# ---------------------------------------------------------------------------


def _nvd_catalog(metrics: dict, references: list | None = None) -> dict:
    """Build a minimal NVD API response with the given CVSS metrics dict."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": metrics,
                    "references": references or [],
                }
            }
        ]
    }


_NVD_V31_ONLY = _nvd_catalog(
    {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ]
    }
)

_NVD_V30_ONLY = _nvd_catalog(
    {
        "cvssMetricV30": [
            {
                "cvssData": {
                    "baseScore": 7.5,
                    "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }
            }
        ]
    }
)

_NVD_BOTH_V31_AND_V30 = _nvd_catalog(
    {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 9.8,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ],
        "cvssMetricV30": [
            {
                "cvssData": {
                    "baseScore": 7.5,
                    "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }
            }
        ],
    }
)


async def test_nvd_fetch_returns_cve_record(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_NVD_V31_ONLY))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        record = await nvd_fetcher.fetch("CVE-2024-1111")
    assert record is not None
    assert "metrics" in record


async def test_nvd_fetch_404_returns_none(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response({}, status_code=404))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        result = await nvd_fetcher.fetch("CVE-9999-0000")
    assert result is None


async def test_nvd_fetch_empty_vulnerabilities_returns_none(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response({"vulnerabilities": []}))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        result = await nvd_fetcher.fetch("CVE-9999-0001")
    assert result is None


async def test_nvd_cvss_v31_preferred_over_v30(tmp_path):
    """When both v3.1 and v3.0 metrics are present, v3.1 is returned."""
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_NVD_BOTH_V31_AND_V30))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        cvss = await nvd_fetcher.fetch_cvss("CVE-2024-2222")
    assert cvss["version"] == "3.1"
    assert cvss["base"] == 9.8


async def test_nvd_cvss_falls_back_to_v30(tmp_path):
    """When only v3.0 is present, v3.0 is returned."""
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_NVD_V30_ONLY))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        cvss = await nvd_fetcher.fetch_cvss("CVE-2024-3333")
    assert cvss["version"] == "3.0"
    assert cvss["base"] == 7.5


async def test_nvd_fetch_cvss_returns_none_when_fetch_returns_none(tmp_path):
    """fetch_cvss returns None when the underlying fetch() finds no record."""
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response({"vulnerabilities": []}))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        cvss = await nvd_fetcher.fetch_cvss("CVE-9999-0000")
    assert cvss is None


async def test_nvd_cvss_returns_none_when_no_metrics(tmp_path):
    """A record with no CVSS metrics returns None from fetch_cvss."""
    no_metrics = _nvd_catalog({})
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(no_metrics))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        cvss = await nvd_fetcher.fetch_cvss("CVE-2024-4444")
    assert cvss is None


async def test_nvd_cache_prevents_second_http_call(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_NVD_V31_ONLY))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch(
            "src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client
        ) as mock_cls,
    ):
        await nvd_fetcher.fetch("CVE-2024-5555")
        await nvd_fetcher.fetch("CVE-2024-5555")
    assert mock_cls.call_count == 1


# ---------------------------------------------------------------------------
# NVD search() — keyword-based CVE lookup used by bom_check
# ---------------------------------------------------------------------------


def _nvd_search_response(cve_id: str, cvss_base: float = 8.0) -> dict:
    """Build a minimal NVD keywordSearch API response."""
    return {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-15T00:00:00.000",
                    "lastModified": "2024-02-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": cvss_base,
                                    "vectorString": "CVSS:3.1/...",
                                }
                            }
                        ]
                    },
                }
            }
        ],
    }


async def test_nvd_search_returns_cve_list(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_nvd_search_response("CVE-2024-1234")))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        results = await nvd_fetcher.search("nginx 1.20", days_back=7)
    assert len(results) == 1
    assert results[0]["id"] == "CVE-2024-1234"
    assert results[0]["description"] == "A test vulnerability."
    assert results[0]["cvss_base"] == 8.0
    assert results[0]["cvss_version"] == "3.1"
    assert "nvd.nist.gov" in results[0]["url"]


async def test_nvd_search_empty_results(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response({"totalResults": 0, "vulnerabilities": []}))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        results = await nvd_fetcher.search("unknown-package 99.0", days_back=7)
    assert results == []


async def test_nvd_search_description_truncated(tmp_path):
    """Descriptions longer than 300 chars are truncated."""
    long_desc = "x" * 500
    response = {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "published": "",
                    "lastModified": "",
                    "descriptions": [{"lang": "en", "value": long_desc}],
                    "metrics": {},
                }
            }
        ],
    }
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(response))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch("src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client),
    ):
        results = await nvd_fetcher.search("anything", days_back=1)
    assert len(results[0]["description"]) == 300


async def test_nvd_search_cache_prevents_second_call(tmp_path):
    cache = FileCache(tmp_path)
    client = _mock_client(_mock_response(_nvd_search_response("CVE-2024-7777")))
    with (
        patch.object(nvd_fetcher, "_cache", cache),
        patch(
            "src.rubricai.fetchers.nvd.httpx.AsyncClient", return_value=client
        ) as mock_cls,
    ):
        await nvd_fetcher.search("redis 7.0", days_back=7)
        await nvd_fetcher.search("redis 7.0", days_back=7)
    assert mock_cls.call_count == 1


# ---------------------------------------------------------------------------
# PoC fetcher — _classify is pure Python, test directly
# ---------------------------------------------------------------------------


def test_poc_exploit_db_is_high_confidence():
    result = _classify(["https://www.exploit-db.com/exploits/51337"])
    assert result["available"] is True
    assert result["confidence"] == "high"
    assert len(result["references"]) == 1


def test_poc_packetstorm_is_high_confidence():
    result = _classify(["https://packetstormsecurity.com/files/12345/exploit.py"])
    assert result["available"] is True
    assert result["confidence"] == "high"


def test_poc_github_exploit_path_is_medium_confidence():
    result = _classify(["https://github.com/user/exploit-cve-2024-1234"])
    assert result["available"] is True
    assert result["confidence"] == "medium"


def test_poc_poc_keyword_is_medium_confidence():
    result = _classify(["https://github.com/user/repo/blob/main/poc.py"])
    assert result["available"] is True
    assert result["confidence"] == "medium"


def test_poc_high_takes_priority_over_medium():
    """When both high- and medium-confidence refs are present, high wins."""
    refs = [
        "https://exploit-db.com/exploits/99999",
        "https://github.com/user/poc-script",
    ]
    result = _classify(refs)
    assert result["confidence"] == "high"


def test_poc_clean_vendor_refs_returns_not_available():
    refs = [
        "https://vendor.example.com/advisory/2024-001",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    ]
    result = _classify(refs)
    assert result["available"] is False
    assert result["confidence"] == "unknown"
    assert result["references"] == []


def test_poc_empty_refs_returns_not_available():
    assert _classify([])["available"] is False


async def test_poc_fetch_with_exploit_refs_returns_available():
    """When NVD record has exploit-db references, fetch returns available=True."""
    record_with_refs = {
        "references": [
            {"url": "https://www.exploit-db.com/exploits/51337"},
            {"url": "https://vendor.example.com/advisory"},
        ]
    }
    with patch(
        "src.rubricai.fetchers.poc.nvd.fetch",
        new=AsyncMock(return_value=record_with_refs),
    ):
        result = await poc_fetcher.fetch("CVE-2024-1111")
    assert result["available"] is True
    assert result["confidence"] == "high"
    assert "exploit-db.com" in result["references"][0]


async def test_poc_no_nvd_record_returns_not_available():
    """When NVD has no record for the CVE, PoC fetch returns available=False."""
    with patch(
        "src.rubricai.fetchers.poc.nvd.fetch",
        new=AsyncMock(return_value=None),
    ):
        result = await poc_fetcher.fetch("CVE-9999-9999")
    assert result["available"] is False
    assert result["confidence"] == "unknown"


# ---------------------------------------------------------------------------
# End-to-end pipeline: lookup → score_evaluate → report_generate
# ---------------------------------------------------------------------------

_CRITICAL_FINDING = {
    "id": "FIND-E2E-001",
    "cve_or_id": "CVE-2024-9001",
    "component": {"name": "PublicAPI", "version": "2.1.0"},
    "entry_point": {"description": "POST /api/execute"},
    "reachability": "internet_exposed",
    "attacker_utility": ["rce"],
}

_LOW_FINDING = {
    "id": "FIND-E2E-002",
    "cve_or_id": "CVE-2024-9002",
    "component": {"name": "LocalTool", "version": "1.0.0"},
    "entry_point": {"description": "local CLI"},
    "reachability": "local_only",
    "attacker_utility": ["dos"],
}

_MOCK_KEV_LISTED = {"listed": True, "due_date": "2024-07-01", "notes": "Exploited"}
_MOCK_KEV_NOT_LISTED = {"listed": False}
_MOCK_EPSS_HIGH = {"score": 0.91, "percentile": 0.99, "date": "2024-06-01"}
_MOCK_NVD = {
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
    "references": [],
}


def _patch_fetchers(kev, epss, nvd_record, cvss, poc):
    return (
        patch(
            "src.rubricai.tools.intel.kev_fetcher.fetch",
            new=AsyncMock(return_value=kev),
        ),
        patch(
            "src.rubricai.tools.intel.epss_fetcher.fetch",
            new=AsyncMock(return_value=epss),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch",
            new=AsyncMock(return_value=nvd_record),
        ),
        patch(
            "src.rubricai.tools.intel.nvd_fetcher.fetch_cvss",
            new=AsyncMock(return_value=cvss),
        ),
        patch(
            "src.rubricai.tools.intel.poc_fetcher.fetch",
            new=AsyncMock(return_value=poc),
        ),
    )


async def test_pipeline_critical_lane(tmp_path, monkeypatch):
    """KEV listed + internet_exposed + RCE → Critical lane, 72h target."""
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))

    patches = _patch_fetchers(
        kev=_MOCK_KEV_LISTED,
        epss=_MOCK_EPSS_HIGH,
        nvd_record=_MOCK_NVD,
        cvss={"base": 9.8, "vector": "CVSS:3.1/...", "version": "3.1"},
        poc={"available": True, "confidence": "high", "references": []},
    )
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        intel = await lookup(["CVE-2024-9001"])

    intel_result = intel["results"][0]
    assessment = score_evaluate(_CRITICAL_FINDING, intel_result)

    assert assessment["lane"] == "critical"
    assert assessment["target"]["days"] == 3

    result = report_generate(_CRITICAL_FINDING, intel_result, assessment)
    assert result["report_json"]["assessment"]["lane"] == "critical"
    # Report files persisted to disk
    report_files = list(tmp_path.iterdir())
    assert len(report_files) >= 2  # .md and .json


async def test_pipeline_low_lane(tmp_path, monkeypatch):
    """local_only + dos + no KEV + low EPSS → Low lane."""
    monkeypatch.setenv("RUBRICAI_REPORT_DIR", str(tmp_path))

    patches = _patch_fetchers(
        kev=_MOCK_KEV_NOT_LISTED,
        epss={"score": 0.02, "percentile": 0.10, "date": "2024-06-01"},
        nvd_record=None,
        cvss=None,
        poc={"available": False, "confidence": "unknown", "references": []},
    )
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        intel = await lookup(["CVE-2024-9002"])

    intel_result = intel["results"][0]
    assessment = score_evaluate(_LOW_FINDING, intel_result)

    assert assessment["lane"] == "low"
    assert assessment["target"]["days"] is None  # patch train
