"""Smoke tests for server.py — import, tool registration, input validation (#52)."""

import asyncio

import pytest
from fastmcp.exceptions import ToolError

from src.rubricai.server import mcp

# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

EXPECTED_TOOLS = {
    "intel_lookup",
    "score_evaluate",
    "report_generate",
    "env_list",
    "env_read",
    "env_write",
    "env_migrate_legacy",
    "policy_get",
    "bom_update",
    "bom_check",
    "project_scan",
}


@pytest.fixture
def registered_tools():
    """Fetch registered tool names from the FastMCP instance."""
    tools = asyncio.run(mcp.list_tools())
    return {t.name for t in tools}


class TestServerImport:
    def test_mcp_instance_name(self):
        assert mcp.name == "RubricAI"

    def test_tool_count(self, registered_tools):
        assert len(registered_tools) == 11

    def test_expected_tool_names(self, registered_tools):
        assert registered_tools == EXPECTED_TOOLS


# ---------------------------------------------------------------------------
# Input validation guards (intel_lookup)
# ---------------------------------------------------------------------------


class TestIntelLookupValidation:
    @pytest.mark.asyncio
    async def test_rejects_invalid_cve_format(self):
        with pytest.raises(ToolError, match="Invalid CVE ID format"):
            await mcp.call_tool("intel_lookup", {"cves": ["not-a-cve"]})

    @pytest.mark.asyncio
    async def test_rejects_empty_cve_id(self):
        with pytest.raises(ToolError, match="Invalid CVE ID format"):
            await mcp.call_tool("intel_lookup", {"cves": [""]})

    @pytest.mark.asyncio
    async def test_rejects_oversized_list(self):
        cves = [f"CVE-2024-{i:04d}" for i in range(51)]
        with pytest.raises(ToolError, match="Too many CVEs"):
            await mcp.call_tool("intel_lookup", {"cves": cves})

    @pytest.mark.asyncio
    async def test_accepts_valid_cve_format(self):
        """Valid format passes validation (will fail on fetch but not validation)."""
        # Patch fetchers so we don't hit the network
        from unittest.mock import AsyncMock, patch

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
            result = await mcp.call_tool("intel_lookup", {"cves": ["CVE-2024-1234"]})
            assert result is not None
