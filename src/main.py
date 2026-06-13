"""Entry point — starts the RubricAI MCP server.

Transport is controlled by the RUBRICAI_TRANSPORT environment variable:
  - stdio  (default) — for Claude Desktop and local MCP clients
  - sse              — for Dockerised / remote HTTP deployment

Security (SSE/HTTP transport only):
  - RUBRICAI_API_KEY  — if set, requires Authorization: Bearer <key> on all HTTP requests
  - RUBRICAI_TLS_CERT — path to PEM certificate file (enables HTTPS)
  - RUBRICAI_TLS_KEY  — path to PEM private key file (required with TLS_CERT)
"""

import argparse
import os

from rubricai.server import mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="RubricAI MCP server")
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG logging (overrides RUBRICAI_LOG_LEVEL)",
    )
    args = parser.parse_args()

    if args.verbose:
        os.environ["RUBRICAI_LOG_LEVEL"] = "DEBUG"

    transport = os.getenv("RUBRICAI_TRANSPORT", "stdio")

    if transport == "stdio":
        mcp.run(transport=transport)
    else:
        # HTTP/SSE transport — apply optional auth middleware and TLS
        kwargs: dict = {}

        # Optional TLS (bring-your-own cert and key)
        tls_cert = os.getenv("RUBRICAI_TLS_CERT")
        tls_key = os.getenv("RUBRICAI_TLS_KEY")
        if tls_cert and tls_key:
            kwargs["uvicorn_config"] = {
                "ssl_certfile": tls_cert,
                "ssl_keyfile": tls_key,
            }

        # Optional API key authentication
        api_key = os.getenv("RUBRICAI_API_KEY")
        if api_key:
            from starlette.middleware import Middleware
            from starlette.requests import Request
            from starlette.responses import JSONResponse
            from starlette.types import ASGIApp, Receive, Scope, Send

            class APIKeyAuthMiddleware:
                """Reject requests without a valid Bearer token."""

                def __init__(self, app: ASGIApp) -> None:
                    self.app = app

                async def __call__(
                    self, scope: Scope, receive: Receive, send: Send
                ) -> None:
                    if scope["type"] == "http":
                        request = Request(scope)
                        auth_header = request.headers.get("authorization", "")
                        if auth_header != f"Bearer {api_key}":
                            response = JSONResponse(
                                {"error": "Unauthorized"}, status_code=401
                            )
                            await response(scope, receive, send)
                            return
                    await self.app(scope, receive, send)

            kwargs["middleware"] = [Middleware(APIKeyAuthMiddleware)]

        mcp.run(transport=transport, **kwargs)


if __name__ == "__main__":
    main()
