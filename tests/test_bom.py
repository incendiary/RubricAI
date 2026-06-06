"""Tests for bom_update and bom_check tools."""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from src.rubricai.tools.bom import bom_check, bom_update

# ---------------------------------------------------------------------------
# bom_update
# ---------------------------------------------------------------------------


class TestBomUpdate:
    def test_stores_components(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = bom_update(
            [
                {"name": "nginx", "version": "1.24.0"},
                {"name": "openssl", "version": "3.1.2"},
            ]
        )
        assert result["stored"] == 2
        assert result["bom"][0]["name"] == "nginx"
        assert result["bom"][1]["name"] == "openssl"

    def test_creates_state_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = bom_update([{"name": "redis", "version": "7.0.0"}])
        assert (tmp_path / "state_latest.json").exists()
        assert result["saved_to"].endswith("state_v001.json")

    def test_empty_list_stores_empty_bom(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = bom_update([])
        assert result["stored"] == 0
        assert result["bom"] == []

    def test_optional_fields_accepted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = bom_update(
            [
                {
                    "name": "postgres",
                    "version": "15.2",
                    "type": "database",
                    "vendor": "PostgreSQL Global Development Group",
                    "notes": "Primary datastore",
                }
            ]
        )
        assert result["stored"] == 1
        entry = result["bom"][0]
        assert entry["vendor"] == "PostgreSQL Global Development Group"
        assert entry["type"] == "database"

    def test_replaces_existing_bom(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "old-service", "version": "1.0"}])
        result = bom_update([{"name": "new-service", "version": "2.0"}])
        # BOM should be replaced, not appended
        assert result["stored"] == 1
        assert result["bom"][0]["name"] == "new-service"

    def test_missing_name_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        with pytest.raises(ValidationError):
            bom_update([{"version": "1.0"}])  # missing name

    def test_missing_version_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        with pytest.raises(ValidationError):
            bom_update([{"name": "nginx"}])  # missing version


# ---------------------------------------------------------------------------
# bom_check
# ---------------------------------------------------------------------------


class TestBomCheck:
    @pytest.mark.asyncio
    async def test_empty_bom_returns_message(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = await bom_check()
        assert result["total_cves"] == 0
        assert "BOM is empty" in result["message"]

    @pytest.mark.asyncio
    async def test_finds_cves_for_components(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update(
            [
                {"name": "nginx", "version": "1.20.0"},
            ]
        )
        mock_cves = [
            {"id": "CVE-2024-0001", "description": "Buffer overflow", "cvss_base": 8.8},
        ]
        with patch(
            "src.rubricai.tools.bom.nvd_fetcher.search",
            new=AsyncMock(return_value=mock_cves),
        ):
            result = await bom_check(days_back=7)

        assert result["total_cves"] == 1
        assert "nginx 1.20.0" in result["findings"]
        assert result["findings"]["nginx 1.20.0"][0]["id"] == "CVE-2024-0001"

    @pytest.mark.asyncio
    async def test_no_cves_found(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "curl", "version": "8.0.0"}])
        with patch(
            "src.rubricai.tools.bom.nvd_fetcher.search",
            new=AsyncMock(return_value=[]),
        ):
            result = await bom_check(days_back=30)

        assert result["total_cves"] == 0
        assert result["findings"] == {}
        assert "No new CVEs" in result["summary"]

    @pytest.mark.asyncio
    async def test_days_back_passed_to_fetcher(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "openssh", "version": "9.0"}])
        mock_search = AsyncMock(return_value=[])
        with patch("src.rubricai.tools.bom.nvd_fetcher.search", new=mock_search):
            await bom_check(days_back=14)

        mock_search.assert_called_once_with("openssh 9.0", days_back=14)

    @pytest.mark.asyncio
    async def test_last_checked_updated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "haproxy", "version": "2.6"}])
        with patch(
            "src.rubricai.tools.bom.nvd_fetcher.search",
            new=AsyncMock(return_value=[]),
        ):
            result = await bom_check()

        # After check, state_latest.json should contain updated last_checked timestamp
        import json

        state = json.loads((tmp_path / "state_latest.json").read_text())
        entry = state["bom"][0]
        assert entry["last_checked"] is not None
        # checked_at from result should be a valid ISO timestamp
        assert result["checked_at"] is not None
        datetime.fromisoformat(result["checked_at"])

    @pytest.mark.asyncio
    async def test_multiple_components_queried(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update(
            [
                {"name": "nginx", "version": "1.20.0"},
                {"name": "redis", "version": "7.0.0"},
                {"name": "postgres", "version": "15.0"},
            ]
        )
        mock_search = AsyncMock(return_value=[])
        with patch("src.rubricai.tools.bom.nvd_fetcher.search", new=mock_search):
            await bom_check()

        assert mock_search.call_count == 3
