"""Tests for bom_update and bom_check tools."""

import json
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from src.rubricai.tools.bom import bom_check, bom_update

_ENV = "test-env"  # canonical environment name for all bom tests


def _env_state_dir(tmp_path):
    return tmp_path / "environments" / _ENV


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
            ],
            _ENV,
        )
        assert result["stored"] == 2
        assert result["bom"][0]["name"] == "nginx"
        assert result["bom"][1]["name"] == "openssl"
        assert result["environment_name"] == _ENV

    def test_creates_state_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = bom_update([{"name": "redis", "version": "7.0.0"}], _ENV)
        assert (_env_state_dir(tmp_path) / "state_latest.json").exists()
        assert result["saved_to"].endswith("state_v001.json")

    def test_empty_list_stores_empty_bom(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = bom_update([], _ENV)
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
            ],
            _ENV,
        )
        assert result["stored"] == 1
        entry = result["bom"][0]
        assert entry["vendor"] == "PostgreSQL Global Development Group"
        assert entry["type"] == "database"

    def test_replaces_existing_bom(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "old-service", "version": "1.0"}], _ENV)
        result = bom_update([{"name": "new-service", "version": "2.0"}], _ENV)
        assert result["stored"] == 1
        assert result["bom"][0]["name"] == "new-service"

    def test_missing_name_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        with pytest.raises(ValidationError):
            bom_update([{"version": "1.0"}], _ENV)

    def test_missing_version_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        with pytest.raises(ValidationError):
            bom_update([{"name": "nginx"}], _ENV)


# ---------------------------------------------------------------------------
# bom_check
# ---------------------------------------------------------------------------


class TestBomCheck:
    @pytest.mark.asyncio
    async def test_empty_bom_returns_message(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        result = await bom_check(_ENV)
        assert result["total_cves"] == 0
        assert "BOM is empty" in result["message"]

    @pytest.mark.asyncio
    async def test_finds_cves_for_components(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "nginx", "version": "1.20.0"}], _ENV)
        mock_cves = [
            {"id": "CVE-2024-0001", "description": "Buffer overflow", "cvss_base": 8.8},
        ]
        with patch(
            "src.rubricai.tools.bom.nvd_fetcher.search",
            new=AsyncMock(return_value=mock_cves),
        ):
            result = await bom_check(_ENV, days_back=7)

        assert result["total_cves"] == 1
        assert "nginx 1.20.0" in result["findings"]
        assert result["findings"]["nginx 1.20.0"][0]["id"] == "CVE-2024-0001"

    @pytest.mark.asyncio
    async def test_no_cves_found(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "curl", "version": "8.0.0"}], _ENV)
        with patch(
            "src.rubricai.tools.bom.nvd_fetcher.search",
            new=AsyncMock(return_value=[]),
        ):
            result = await bom_check(_ENV, days_back=30)

        assert result["total_cves"] == 0
        assert result["findings"] == {}
        assert "No new CVEs" in result["summary"]

    @pytest.mark.asyncio
    async def test_days_back_passed_to_fetcher(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "openssh", "version": "9.0"}], _ENV)
        mock_search = AsyncMock(return_value=[])
        with patch("src.rubricai.tools.bom.nvd_fetcher.search", new=mock_search):
            await bom_check(_ENV, days_back=14)

        mock_search.assert_called_once_with("openssh", days_back=14)

    @pytest.mark.asyncio
    async def test_last_checked_updated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RUBRICAI_ENV_DIR", str(tmp_path))
        bom_update([{"name": "haproxy", "version": "2.6"}], _ENV)
        with patch(
            "src.rubricai.tools.bom.nvd_fetcher.search",
            new=AsyncMock(return_value=[]),
        ):
            result = await bom_check(_ENV)

        state = json.loads((_env_state_dir(tmp_path) / "state_latest.json").read_text())
        assert state["bom"][0]["last_checked"] is not None
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
            ],
            _ENV,
        )
        mock_search = AsyncMock(return_value=[])
        with patch("src.rubricai.tools.bom.nvd_fetcher.search", new=mock_search):
            await bom_check(_ENV)

        assert mock_search.call_count == 3
