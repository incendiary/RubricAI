"""Bearer-token authentication middleware for the SSE/HTTP transport.

Extracted into its own module so that tests exercise the *real* middleware
rather than a copy. The middleware leaves the unauthenticated ``/health``
endpoint open so container orchestrators can probe liveness without a token;
every other route requires ``Authorization: Bearer <api_key>``.
"""

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

# Paths that must remain reachable without a Bearer token (health/liveness probes).
PUBLIC_PATHS: frozenset[str] = frozenset({"/health"})


class APIKeyAuthMiddleware:
    """Reject HTTP requests without a valid Bearer token, except for PUBLIC_PATHS."""

    def __init__(self, app: ASGIApp, *, api_key: str) -> None:
        self.app = app
        self.api_key = api_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            request = Request(scope)
            if request.url.path not in PUBLIC_PATHS:
                auth_header = request.headers.get("authorization", "")
                if auth_header != f"Bearer {self.api_key}":
                    response = JSONResponse({"error": "Unauthorized"}, status_code=401)
                    await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)
