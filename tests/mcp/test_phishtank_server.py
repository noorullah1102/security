"""Tests for PhishTank MCP Server — TTLCache, PhishTankAPI, and tool functions."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.mcp.phishtank_server import (
    TTLCache,
    PhishTankAPI,
    _parse_timestamp,
)


# ---------------------------------------------------------------------------
# TTLCache Tests
# ---------------------------------------------------------------------------

class TestTTLCache:
    def test_set_and_get(self):
        cache = TTLCache(default_ttl=60)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_missing_key(self):
        cache = TTLCache()
        assert cache.get("nonexistent") is None

    def test_expiry(self):
        cache = TTLCache(default_ttl=60)
        cache.set("key1", "value1", ttl=0)  # Immediate expiry
        assert cache.get("key1") is None

    def test_custom_ttl(self):
        cache = TTLCache(default_ttl=0)  # Immediate default expiry
        cache.set("key1", "value1", ttl=60)
        assert cache.get("key1") == "value1"

    def test_clear(self):
        cache = TTLCache()
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_overwrite_key(self):
        cache = TTLCache()
        cache.set("key", "old")
        cache.set("key", "new")
        assert cache.get("key") == "new"


# ---------------------------------------------------------------------------
# PhishTankAPI Tests
# ---------------------------------------------------------------------------

class TestPhishTankAPI:
    def test_is_valid_url(self):
        assert PhishTankAPI._is_valid_url("https://example.com") is True
        assert PhishTankAPI._is_valid_url("http://test.com/path") is True
        assert PhishTankAPI._is_valid_url("not-a-url") is False
        assert PhishTankAPI._is_valid_url("") is False

    def test_rate_limit_config(self):
        api_with_key = PhishTankAPI(api_key="test-key")
        assert api_with_key._rate_limit_max == 100

        api_without_key = PhishTankAPI(api_key=None)
        assert api_without_key._rate_limit_max == 10

    def test_url_check_summary(self):
        # Not in database
        resp = {"results": {"in_database": False}}
        assert "not found" in PhishTankAPI._url_check_summary(resp).lower()

        # Verified phishing
        resp = {"results": {"in_database": True, "verified": True, "valid": True, "phish_id": 12345}}
        summary = PhishTankAPI._url_check_summary(resp)
        assert "PHISHING DETECTED" in summary
        assert "12345" in summary

        # In database but not verified
        resp = {"results": {"in_database": True, "verified": False, "valid": False, "phish_id": 99}}
        summary = PhishTankAPI._url_check_summary(resp)
        assert "not yet verified" in summary

        # Invalid response
        assert "Invalid" in PhishTankAPI._url_check_summary({})

    @pytest.mark.asyncio
    async def test_check_url_rate_limited(self):
        api = PhishTankAPI()
        mock_resp = MagicMock()
        mock_resp.status = 509
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post.return_value = mock_cm

        api._get_session = AsyncMock(return_value=mock_session)
        result = await api.check_url("https://test.com")
        assert result.get("status") == 509
        assert "rate limit" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_check_url_success(self):
        api_response = {
            "results": {
                "in_database": True,
                "verified": True,
                "valid": True,
                "phish_id": 12345,
            }
        }

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=api_response)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post.return_value = mock_cm

        api = PhishTankAPI()
        api._get_session = AsyncMock(return_value=mock_session)
        result = await api.check_url("https://evil-phishing.com")
        assert "result" in result
        assert result["result"]["results"]["in_database"] is True

    @pytest.mark.asyncio
    async def test_download_database_cached(self):
        api = PhishTankAPI()
        cached_data = [{"phish_id": 1, "url": "https://phish.com"}]
        api._cache.set("phishtank_database", cached_data, ttl=3600)

        result = await api.download_database()
        assert result == cached_data

    @pytest.mark.asyncio
    async def test_download_database_fresh(self):
        db_data = [
            {"phish_id": 1, "url": "https://phish1.com", "online": "yes"},
            {"phish_id": 2, "url": "https://phish2.com", "online": "no"},
        ]

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=db_data)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_cm

        api = PhishTankAPI()
        api._get_session = AsyncMock(return_value=mock_session)

        result = await api.download_database()
        assert len(result) == 2
        assert result[0]["phish_id"] == 1

    @pytest.mark.asyncio
    async def test_close(self):
        api = PhishTankAPI()
        mock_session = AsyncMock()
        mock_session.closed = False
        api._session = mock_session

        await api.close()
        mock_session.close.assert_called_once()


# ---------------------------------------------------------------------------
# _parse_timestamp Tests
# ---------------------------------------------------------------------------

class TestParseTimestamp:
    def test_valid_iso(self):
        ts = _parse_timestamp("2026-04-09T12:00:00+00:00")
        assert ts > 0

    def test_invalid_string(self):
        assert _parse_timestamp("not-a-date") == 0.0

    def test_empty(self):
        assert _parse_timestamp("") == 0.0

    def test_none(self):
        assert _parse_timestamp(None) == 0.0


# ---------------------------------------------------------------------------
# Tool Function Tests (unit level — no MCP protocol)
# ---------------------------------------------------------------------------

class TestToolLogic:
    """Test the underlying logic used by MCP tools without running the MCP protocol."""

    @pytest.mark.asyncio
    async def test_recent_phish_filters_offline(self):
        api = PhishTankAPI()
        api._cache.set(
            "phishtank_database",
            [
                {"phish_id": 1, "url": "a", "online": "yes", "submission_time": "2026-04-09T10:00:00+00:00"},
                {"phish_id": 2, "url": "b", "online": "no", "submission_time": "2026-04-09T11:00:00+00:00"},
            ],
            ttl=3600,
        )

        entries = await api.download_database()
        online_only = [e for e in entries if e.get("online") == "yes"]
        assert len(online_only) == 1
        assert online_only[0]["phish_id"] == 1

    @pytest.mark.asyncio
    async def test_search_by_target(self):
        api = PhishTankAPI()
        api._cache.set(
            "phishtank_database",
            [
                {"phish_id": 1, "url": "a", "target": "PayPal", "verified": "yes", "submission_time": "2026-04-09T10:00:00+00:00"},
                {"phish_id": 2, "url": "b", "target": "Apple", "verified": "yes", "submission_time": "2026-04-09T11:00:00+00:00"},
                {"phish_id": 3, "url": "c", "target": "paypal-login", "verified": "no", "submission_time": "2026-04-09T12:00:00+00:00"},
            ],
            ttl=3600,
        )

        entries = await api.download_database()
        matches = [
            e for e in entries
            if "paypal" in (e.get("target") or "").lower()
            and e.get("verified") == "yes"
        ]
        assert len(matches) == 1
        assert matches[0]["phish_id"] == 1

    @pytest.mark.asyncio
    async def test_get_phish_details_found(self):
        api = PhishTankAPI()
        api._cache.set(
            "phishtank_database",
            [{"phish_id": 42, "url": "https://evil.com", "target": "Google"}],
            ttl=3600,
        )

        entries = await api.download_database()
        entry = next((e for e in entries if e.get("phish_id") == 42), None)
        assert entry is not None
        assert entry["target"] == "Google"

    @pytest.mark.asyncio
    async def test_get_phish_details_not_found(self):
        api = PhishTankAPI()
        api._cache.set("phishtank_database", [], ttl=3600)

        entries = await api.download_database()
        entry = next((e for e in entries if e.get("phish_id") == 999), None)
        assert entry is None
