"""Entry point — starts the RubricAI MCP server.

Transport is controlled by the RUBRICAI_TRANSPORT environment variable:
  - stdio  (default) — for Claude Desktop and local MCP clients
  - sse              — for Dockerised / remote HTTP deployment
"""

import os

from rubricai.server import mcp


def main() -> None:
    transport = os.getenv("RUBRICAI_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
