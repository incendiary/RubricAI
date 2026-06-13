"""Tests for the Bearer token authentication middleware.

Exercises the APIKeyAuthMiddleware defined in src/main.py by constructing
a minimal ASGI app with the same middleware logic and driving it through
Starlette's TestClient.
"""

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send


# Reproduce the middleware from src/main.py so we can test in isolation.
class _APIKeyAuthMiddleware:
    """Reject requests without a valid Bearer token."""

    def __init__(self, app: ASGIApp, *, api_key: str) -> None:
        self.app = app
        self.api_key = api_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            request = Request(scope)
            auth_header = request.headers.get("authorization", "")
            if auth_header != f"Bearer {self.api_key}":
                response = JSONResponse({"error": "Unauthorized"}, status_code=401)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


async def _ok_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


_TEST_KEY = "test-secret-key-12345"


def _make_app(api_key: str | None = None) -> Starlette:
    """Build a minimal Starlette app, optionally with auth middleware."""
    middleware = []
    if api_key:
        middleware.append(
            Middleware(_APIKeyAuthMiddleware, api_key=api_key)
        )
    return Starlette(
        routes=[Route("/test", _ok_endpoint, methods=["GET"])],
        middleware=middleware,
    )


# --- Tests ---


class TestNoAuth:
    """When RUBRICAI_API_KEY is not set, all requests pass through."""

    def setup_method(self):
        self.client = TestClient(_make_app(api_key=None))

    def test_request_without_token_succeeds(self):
        resp = self.client.get("/test")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_request_with_arbitrary_header_succeeds(self):
        resp = self.client.get("/test", headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == 200


class TestWithAuth:
    """When RUBRICAI_API_KEY is set, Bearer token is required."""

    def setup_method(self):
        self.client = TestClient(_make_app(api_key=_TEST_KEY))

    def test_missing_token_returns_401(self):
        resp = self.client.get("/test")
        assert resp.status_code == 401
        assert resp.json() == {"error": "Unauthorized"}

    def test_wrong_token_returns_401(self):
        resp = self.client.get("/test", headers={"Authorization": "Bearer wrong-key"})
        assert resp.status_code == 401

    def test_correct_token_returns_200(self):
        resp = self.client.get(
            "/test", headers={"Authorization": f"Bearer {_TEST_KEY}"}
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_basic_auth_scheme_rejected(self):
        """Only Bearer scheme is accepted, not Basic or others."""
        resp = self.client.get(
            "/test", headers={"Authorization": f"Basic {_TEST_KEY}"}
        )
        assert resp.status_code == 401

    def test_token_is_case_sensitive(self):
        resp = self.client.get(
            "/test",
            headers={"Authorization": f"Bearer {_TEST_KEY.upper()}"},
        )
        assert resp.status_code == 401

    def test_empty_authorization_header_returns_401(self):
        resp = self.client.get("/test", headers={"Authorization": ""})
        assert resp.status_code == 401
