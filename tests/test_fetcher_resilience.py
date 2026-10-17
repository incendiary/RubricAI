"""Resilience of every fetcher against a misbehaving upstream.

Requests go through the real ``fetch_with_timeout_escalation`` and
``httpx.MockTransport``; only ``asyncio.sleep`` is patched so backoff is instant.
Each fetcher must return its documented empty value and never raise.
"""

import httpx
import pytest

from rubricai.cache import FileCache
from rubricai.fetchers import epss, gh_advisory, kev, nvd, osv, poc
from rubricai.tools.intel import lookup

CVE = "CVE-2024-1234"
_NO_POC = {"available": False, "confidence": "unknown", "references": []}


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    """Route all httpx traffic to ``upstream.handler``; isolate caches and sleeps."""

    class Upstream:
        requests: list[httpx.Request] = []
        handler = staticmethod(lambda request: httpx.Response(500))

    up = Upstream()
    up.requests = []

    def dispatch(request):
        up.requests.append(request)
        return up.handler(request)

    async def _instant(_):
        pass

    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(dispatch), **kw),
    )
    monkeypatch.setattr("asyncio.sleep", _instant)
    for mod in (epss, gh_advisory, kev, nvd, osv):
        monkeypatch.setattr(mod, "_cache", FileCache(tmp_path / mod.__name__))
    monkeypatch.setattr(gh_advisory, "_blocked_until", 0.0)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    return up


def _timeout(request):
    raise httpx.ReadTimeout("slow", request=request)


def _connect_error(request):
    raise httpx.ConnectError("refused", request=request)


def _status(code):
    return lambda request: httpx.Response(code)


def _body(content, status=200):
    return lambda request: httpx.Response(status, content=content)


_INVALID_JSON = _body(b"<html>not json</html>")

# (fetcher id, awaitable factory, documented empty value)
_FETCHERS = [
    ("kev", lambda: kev.fetch(CVE), {"listed": False}),
    ("epss", lambda: epss.fetch(CVE), None),
    ("gh_advisory", lambda: gh_advisory.fetch(CVE), None),
    ("nvd_fetch", lambda: nvd.fetch(CVE), None),
    ("nvd_fetch_cvss", lambda: nvd.fetch_cvss(CVE), None),
    ("nvd_search", lambda: nvd.search("log4j-core"), []),
    ("osv", lambda: osv.search("log4j-core", "maven"), []),
    ("poc", lambda: poc.fetch(CVE), _NO_POC),
]
_IDS = [f[0] for f in _FETCHERS]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call", "empty"), _FETCHERS, ids=_IDS)
@pytest.mark.parametrize(
    "handler",
    [
        _timeout,
        _connect_error,
        _status(404),
        _status(429),
        _status(500),
        _status(503),
        _INVALID_JSON,
        _body(b""),
    ],
    ids=[
        "timeout",
        "connect-error",
        "404",
        "429",
        "500",
        "503",
        "invalid-json",
        "empty-body",
    ],
)
async def test_failure_returns_empty_value(upstream, name, call, empty, handler):
    upstream.handler = handler
    assert await call() == empty


# Bodies that are valid JSON but not the shape the fetcher expects.
_WRONG_SHAPE = [
    ("kev", lambda: kev.fetch(CVE), [], {"listed": False}),
    (
        "kev",
        lambda: kev.fetch(CVE),
        {"vulnerabilities": [{"dueDate": "2024-01-01"}]},
        {"listed": False},
    ),
    ("epss", lambda: epss.fetch(CVE), [], None),
    ("epss", lambda: epss.fetch(CVE), {"data": [{"epss": "n/a"}]}, None),
    ("epss", lambda: epss.fetch(CVE), {"data": "oops"}, None),
    ("gh_advisory", lambda: gh_advisory.fetch(CVE), {"message": "Bad"}, None),
    ("gh_advisory", lambda: gh_advisory.fetch(CVE), ["not-a-dict"], None),
    ("nvd_fetch", lambda: nvd.fetch(CVE), [], None),
    ("nvd_fetch", lambda: nvd.fetch(CVE), {"vulnerabilities": ["x"]}, None),
    ("nvd_search", lambda: nvd.search("log4j-core"), [], []),
    ("osv", lambda: osv.search("log4j-core", "maven"), [], []),
    ("poc", lambda: poc.fetch(CVE), [], _NO_POC),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "payload", "empty"),
    _WRONG_SHAPE,
    ids=[f"{w[0]}-{i}" for i, w in enumerate(_WRONG_SHAPE)],
)
async def test_wrong_shape_200_returns_empty_value(
    upstream, name, call, payload, empty
):
    import json

    upstream.handler = _body(json.dumps(payload).encode())
    assert await call() == empty


# ---------------------------------------------------------------------------
# Caching: failures must not poison the cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "handler", [_INVALID_JSON, _body(b'{"message": "Bad"}'), _timeout, _status(500)]
)
async def test_gh_advisory_bad_response_is_not_cached(upstream, handler):
    upstream.handler = handler
    assert await gh_advisory.fetch(CVE) is None
    assert gh_advisory._cache.get("gh_advisory", CVE) is None

    upstream.handler = _body(b'[{"cve_id": "CVE-2024-1234", "summary": "ok"}]')
    result = await gh_advisory.fetch(CVE)
    assert result["id"] == CVE
    assert result["description"] == "ok"


@pytest.mark.asyncio
async def test_epss_malformed_body_is_not_cached(upstream):
    upstream.handler = _body(b'{"data": [{"epss": "n/a"}]}')
    assert await epss.fetch(CVE) is None

    upstream.handler = _body(
        b'{"data": [{"epss": "0.5", "percentile": "0.9", "date": "2024-01-01"}]}'
    )
    assert await epss.fetch(CVE) == {
        "score": 0.5,
        "percentile": 0.9,
        "date": "2024-01-01",
    }


@pytest.mark.asyncio
async def test_kev_malformed_catalog_is_not_cached(upstream):
    upstream.handler = _INVALID_JSON
    assert await kev.fetch(CVE) == {"listed": False}

    upstream.handler = _body(
        b'{"vulnerabilities": [{"cveID": "CVE-2024-1234", "dueDate": "2024-06-30",'
        b' "shortDescription": "exploited"}]}'
    )
    assert await kev.fetch(CVE) == {
        "listed": True,
        "due_date": "2024-06-30",
        "notes": "exploited",
    }


# ---------------------------------------------------------------------------
# NVD 503 auth fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nvd_503_with_api_key_retries_without_key(upstream, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-not-real")

    def handler(request):
        if "apiKey" in request.headers:
            return httpx.Response(503)
        return httpx.Response(
            200, json={"vulnerabilities": [{"cve": {"id": CVE, "metrics": {}}}]}
        )

    upstream.handler = handler
    assert await nvd.fetch(CVE) == {"id": CVE, "metrics": {}}

    keyed = ["apiKey" in r.headers for r in upstream.requests]
    assert keyed[0] is True
    assert keyed[-1] is False
    assert keyed.count(False) == 1


@pytest.mark.asyncio
async def test_nvd_rejected_key_404_retries_without_key(upstream, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-not-real")

    def handler(request):
        if "apiKey" in request.headers:
            return httpx.Response(404, headers={"message": "Invalid apiKey."})
        return httpx.Response(
            200, json={"vulnerabilities": [{"cve": {"id": CVE, "metrics": {}}}]}
        )

    upstream.handler = handler
    assert await nvd.fetch(CVE) == {"id": CVE, "metrics": {}}
    assert ["apiKey" in r.headers for r in upstream.requests] == [True, False]


@pytest.mark.asyncio
async def test_nvd_genuine_404_with_valid_key_is_not_retried(upstream, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-not-real")
    upstream.handler = _status(404)  # no "Invalid apiKey" header: CVE really absent
    assert await nvd.fetch(CVE) is None
    assert len(upstream.requests) == 1


@pytest.mark.asyncio
async def test_nvd_with_api_key_sends_key_when_healthy(upstream, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-not-real")
    upstream.handler = lambda r: httpx.Response(
        200, json={"vulnerabilities": [{"cve": {"id": CVE}}]}
    )
    assert await nvd.fetch(CVE) == {"id": CVE}
    assert [r.headers["apiKey"] for r in upstream.requests] == ["test-key-not-real"]


@pytest.mark.asyncio
async def test_nvd_503_on_both_attempts_returns_none(upstream, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key-not-real")
    upstream.handler = _status(503)
    assert await nvd.fetch(CVE) is None
    assert "apiKey" not in upstream.requests[-1].headers


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [_timeout, _INVALID_JSON], ids=["timeout", "json"])
async def test_nvd_search_keeps_results_found_before_a_failure(upstream, bad):
    def handler(request):
        if request.url.params["keywordSearch"] == "log4j-core":
            return httpx.Response(
                200,
                json={
                    "totalResults": 1,
                    "vulnerabilities": [{"cve": {"id": CVE, "descriptions": []}}],
                },
            )
        return bad(request)

    upstream.handler = handler
    results = await nvd.search("log4j-core")
    assert [r["id"] for r in results] == [CVE]
    assert nvd._cache.get("nvd_search", "log4j-core::7:200") is None


# ---------------------------------------------------------------------------
# intel_lookup: one failing source must not sink healthy results
# ---------------------------------------------------------------------------

_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_HEALTHY, _SICK = "CVE-2024-1111", "CVE-2024-2222"


def _intel_upstream(sick_nvd):
    def handler(request):
        host, params = request.url.host, dict(request.url.params)
        if host == "www.cisa.gov":
            return httpx.Response(
                200,
                json={
                    "vulnerabilities": [
                        {
                            "cveID": _HEALTHY,
                            "dueDate": "2024-06-30",
                            "shortDescription": "exploited",
                        }
                    ]
                },
            )
        if host == "api.first.org":
            return httpx.Response(500)
        if host == "api.github.com":
            return httpx.Response(200, json={"message": "unexpected"})
        if params["cveId"] == _SICK:
            return sick_nvd(request)
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": params["cveId"],
                            "descriptions": [{"lang": "en", "value": "healthy"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.8,
                                            "vectorString": _VECTOR,
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            },
        )

    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sick_nvd", [_timeout, _status(503), _INVALID_JSON], ids=["timeout", "503", "json"]
)
async def test_intel_lookup_survives_failing_sources(upstream, sick_nvd):
    upstream.handler = _intel_upstream(sick_nvd)

    out = await lookup([_HEALTHY, _SICK])
    by_id = {r["cve_or_id"]: r for r in out["results"]}

    healthy, sick = by_id[_HEALTHY], by_id[_SICK]
    assert "NVD" in healthy["sources"]
    assert "FIRST_EPSS" not in healthy["sources"]
    assert healthy["description"] == "healthy"
    assert healthy["cvss"]["base"] == 9.8
    assert healthy["kev"]["listed"] is True
    assert healthy["epss"] is None  # EPSS 500 for every CVE

    assert "NVD" not in sick["sources"]
    assert "GITHUB_ADVISORY" not in sick["sources"]
    assert sick["kev"]["listed"] is False
    assert sick["cvss"] is None
    assert sick["description"] is None
    assert sick["poc"]["available"] is False
