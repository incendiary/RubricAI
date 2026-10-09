"""Tests for fetchers/retry.py latency bounds."""

import httpx
import pytest

from rubricai.fetchers import retry
from rubricai.fetchers.retry import fetch_with_retry, fetch_with_timeout_escalation


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _instant(_):
        pass

    monkeypatch.setattr(retry.asyncio, "sleep", _instant)


def _patch_transport(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(
        retry.httpx,
        "AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
    )


@pytest.mark.asyncio
async def test_timeout_called_once_per_window(monkeypatch):
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ReadTimeout("slow", request=request)

    _patch_transport(monkeypatch, handler)
    with pytest.raises(httpx.ReadTimeout):
        await fetch_with_timeout_escalation("GET", "https://example.test")
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_503_then_200_returns_200():
    codes = iter([503, 200])
    transport = httpx.MockTransport(lambda r: httpx.Response(next(codes)))
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await fetch_with_retry(client, "GET", "https://example.test")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_404_returns_immediately():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await fetch_with_retry(client, "GET", "https://example.test")
    assert resp.status_code == 404
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 30), ("abc", 30), ("0", 30), ("-5", 30), ("20", 20), ("100", 30)],
)
def test_timeout_cap(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("RUBRICAI_HTTP_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("RUBRICAI_HTTP_TIMEOUT", value)
    assert retry._timeout_windows() == (5, 10, expected)
