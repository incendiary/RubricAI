"""Tests for the transport wiring in ``src/main.py``."""

import pytest

from main import build_run_kwargs
from rubricai.auth import APIKeyAuthMiddleware

_ENV = (
    "RUBRICAI_API_KEY",
    "RUBRICAI_ALLOW_NO_AUTH",
    "RUBRICAI_TLS_CERT",
    "RUBRICAI_TLS_KEY",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)


def test_stdio_has_no_middleware_or_tls():
    assert build_run_kwargs("stdio") == {"transport": "stdio"}


def test_stdio_ignores_security_env(monkeypatch):
    monkeypatch.setenv("RUBRICAI_TLS_CERT", "/c.pem")
    assert build_run_kwargs("stdio") == {"transport": "stdio"}


def test_sse_without_key_exits(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        build_run_kwargs("sse")
    assert "RUBRICAI_API_KEY" in str(exc.value)


def test_sse_allow_no_auth_starts_without_middleware(monkeypatch):
    monkeypatch.setenv("RUBRICAI_ALLOW_NO_AUTH", "1")
    assert build_run_kwargs("sse") == {"transport": "sse"}


def test_sse_allow_no_auth_requires_exact_one(monkeypatch):
    monkeypatch.setenv("RUBRICAI_ALLOW_NO_AUTH", "true")
    with pytest.raises(SystemExit):
        build_run_kwargs("sse")


def test_sse_with_key_includes_middleware(monkeypatch):
    monkeypatch.setenv("RUBRICAI_API_KEY", "k")
    kwargs = build_run_kwargs("sse")
    (mw,) = kwargs["middleware"]
    assert mw.cls is APIKeyAuthMiddleware
    assert mw.kwargs == {"api_key": "k"}
    assert "uvicorn_config" not in kwargs


@pytest.mark.parametrize("name", ["RUBRICAI_TLS_CERT", "RUBRICAI_TLS_KEY"])
def test_sse_only_one_of_cert_key_exits(monkeypatch, name):
    monkeypatch.setenv("RUBRICAI_API_KEY", "k")
    monkeypatch.setenv(name, "/some/file.pem")
    with pytest.raises(SystemExit) as exc:
        build_run_kwargs("sse")
    assert "TLS" in str(exc.value)


def test_sse_cert_and_key_enable_tls(monkeypatch):
    monkeypatch.setenv("RUBRICAI_API_KEY", "k")
    monkeypatch.setenv("RUBRICAI_TLS_CERT", "/c.pem")
    monkeypatch.setenv("RUBRICAI_TLS_KEY", "/k.pem")
    assert build_run_kwargs("sse")["uvicorn_config"] == {
        "ssl_certfile": "/c.pem",
        "ssl_keyfile": "/k.pem",
    }
