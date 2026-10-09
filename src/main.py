"""Entry point — starts the RubricAI MCP server.

Transport is controlled by the RUBRICAI_TRANSPORT environment variable:
  - stdio  (default) — for Claude Desktop and local MCP clients
  - sse              — for Dockerised / remote HTTP deployment

Security (SSE/HTTP transport only):
  - RUBRICAI_API_KEY  — requires Authorization: Bearer <key> on all HTTP
    requests; the server refuses to start without it
  - RUBRICAI_ALLOW_NO_AUTH — set to 1 to start without RUBRICAI_API_KEY
  - RUBRICAI_TLS_CERT — path to PEM certificate file (enables HTTPS)
  - RUBRICAI_TLS_KEY  — path to PEM private key file (must be set with TLS_CERT)
"""

import argparse
import os

from rubricai.server import mcp


def build_run_kwargs(transport: str) -> dict:
    """Return the ``mcp.run`` keyword arguments for the given transport.

    Raises SystemExit on an insecure or inconsistent SSE configuration.
    """
    if transport == "stdio":
        return {"transport": transport}

    kwargs: dict = {"transport": transport}

    tls_cert = os.getenv("RUBRICAI_TLS_CERT")
    tls_key = os.getenv("RUBRICAI_TLS_KEY")
    if bool(tls_cert) != bool(tls_key):
        raise SystemExit(
            "RUBRICAI_TLS_CERT and RUBRICAI_TLS_KEY must be set together; "
            "refusing to fall back to plain HTTP."
        )
    if tls_cert and tls_key:
        kwargs["uvicorn_config"] = {
            "ssl_certfile": tls_cert,
            "ssl_keyfile": tls_key,
        }

    api_key = os.getenv("RUBRICAI_API_KEY")
    if api_key:
        from starlette.middleware import Middleware

        from rubricai.auth import APIKeyAuthMiddleware

        kwargs["middleware"] = [Middleware(APIKeyAuthMiddleware, api_key=api_key)]
    elif os.getenv("RUBRICAI_ALLOW_NO_AUTH") != "1":
        raise SystemExit(
            "RUBRICAI_API_KEY is not set; refusing to start the SSE transport "
            "unauthenticated. Set RUBRICAI_API_KEY, or set "
            "RUBRICAI_ALLOW_NO_AUTH=1 to accept the risk explicitly."
        )

    return kwargs


def main() -> None:
    parser = argparse.ArgumentParser(description="RubricAI MCP server")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging (overrides RUBRICAI_LOG_LEVEL)",
    )
    args = parser.parse_args()

    if args.verbose:
        os.environ["RUBRICAI_LOG_LEVEL"] = "DEBUG"

    mcp.run(**build_run_kwargs(os.getenv("RUBRICAI_TRANSPORT", "stdio")))


if __name__ == "__main__":
    main()
