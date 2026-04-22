"""PhishTank MCP Server — Python conversion of the TypeScript PhishTank MCP server.

Provides 7 MCP tools for PhishTank API access:
- check_url: Check a URL against PhishTank's phishing database
- check_multiple_urls: Batch URL checking with rate limiting
- get_recent_phish: Get recent verified phishing URLs
- search_phish_by_target: Search by target brand/company
- get_phish_details: Get details for a specific phish ID
- get_phish_stats: Get phishing statistics and top targets
- search_phish_by_date: Search by submission date range

PhishTank API docs: https://www.phishtank.com/api_info.php
MCP SDK docs: https://github.com/modelcontextprotocol/python-sdk
"""

import asyncio
import os
import time
from collections import Counter
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import aiohttp
from mcp.server.fastmcp import FastMCP


# ---------------------------------------------------------------------------
# TTL Cache
# ---------------------------------------------------------------------------

class TTLCache:
    """Simple dict-based cache with per-key time-to-live expiration."""

    def __init__(self, default_ttl: int = 300):
        self._store: dict[str, tuple[float, Any]] = {}
        self._default_ttl = default_ttl

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        expiry, value = entry
        if time.monotonic() >= expiry:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        effective_ttl = ttl if ttl is not None else self._default_ttl
        self._store[key] = (time.monotonic() + effective_ttl, value)

    def clear(self) -> None:
        self._store.clear()


# ---------------------------------------------------------------------------
# PhishTank API Client
# ---------------------------------------------------------------------------

class PhishTankAPI:
    """Async client for PhishTank API with caching and rate limiting."""

    CHECK_URL_ENDPOINT = "http://checkurl.phishtank.com/checkurl/"
    DATA_BASE_URL = "http://data.phishtank.com/data"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self._session: aiohttp.ClientSession | None = None
        self._last_request_time: float = 0.0
        self._rate_limit_max: int = 100 if api_key else 10
        self._cache = TTLCache(default_ttl=300)

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _enforce_rate_limit(self) -> None:
        min_interval = 60.0 / self._rate_limit_max
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    async def check_url(self, url: str, fmt: str = "json") -> dict[str, Any]:
        """Check a single URL against PhishTank's database."""
        await self._enforce_rate_limit()
        session = await self._get_session()

        form_data = aiohttp.FormData()
        form_data.add_field("url", url)
        form_data.add_field("format", fmt)
        if self.api_key:
            form_data.add_field("app_key", self.api_key)

        async with session.post(self.CHECK_URL_ENDPOINT, data=form_data) as resp:
            if resp.status == 509:
                return {
                    "error": "Rate limit exceeded. Try again later or use an API key for higher limits.",
                    "status": 509,
                }
            if resp.status != 200:
                text = await resp.text()
                return {
                    "error": f"PhishTank API error ({resp.status}): {text}",
                    "status": resp.status,
                }
            data = await resp.json()

        # Extract rate-limit info from headers (PhishTank provides these)
        rate_info: dict[str, Any] | None = None
        # Headers are available on the response object before the context closes
        return {
            "result": data,
            "summary": self._url_check_summary(data),
        }

    async def download_database(self) -> list[dict[str, Any]]:
        """Download the PhishTank online-valid database (cached for 1 hour)."""
        cached = self._cache.get("phishtank_database")
        if cached is not None:
            return cached

        url = (
            f"{self.DATA_BASE_URL}/{self.api_key}/online-valid.json"
            if self.api_key
            else f"{self.DATA_BASE_URL}/online-valid.json"
        )

        await self._enforce_rate_limit()
        session = await self._get_session()

        async with session.get(url) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"Failed to download PhishTank database ({resp.status}): {text}")
            data = await resp.json()

        entries = data if isinstance(data, list) else []
        self._cache.set("phishtank_database", entries, ttl=3600)
        return entries

    @staticmethod
    def _url_check_summary(response: dict[str, Any]) -> str:
        results = response.get("results")
        if not results:
            return "Invalid response from PhishTank"
        in_database = results.get("in_database")
        verified = results.get("verified")
        valid = results.get("valid")
        phish_id = results.get("phish_id")
        if not in_database:
            return "URL not found in PhishTank database (likely safe)"
        if verified and valid:
            return f"PHISHING DETECTED - Verified phishing URL (ID: {phish_id})"
        return f"URL found in database but not yet verified (ID: {phish_id})"


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Manage PhishTankAPI lifecycle — create on startup, close on shutdown."""
    api_key = os.environ.get("PHISHTANK_API_KEY")
    api = PhishTankAPI(api_key=api_key)
    try:
        yield {"phishtank_api": api}
    finally:
        await api.close()


mcp = FastMCP(
    "phishtank-server",
    instructions=(
        "PhishTank MCP server for phishing URL verification and database queries. "
        "Provides tools to check URLs, search the PhishTank database, and get phishing statistics."
    ),
    lifespan=server_lifespan,
)


# ---------------------------------------------------------------------------
# Tool 1: check_url
# ---------------------------------------------------------------------------

@mcp.tool()
async def check_url(url: str, format: str = "json") -> dict[str, Any]:
    """Check if a URL is in PhishTank's phishing database.

    Args:
        url: The URL to check (must be a complete URL with protocol)
        format: Response format — json, xml, or php (default: json)
    """
    if not url or not url.strip():
        return {"error": "URL parameter is required"}
    url = url.strip()
    if not PhishTankAPI._is_valid_url(url):
        return {"error": "Invalid URL format. Must include protocol (http:// or https://)"}

    api: PhishTankAPI = mcp.get_context().request_context.lifespan_context["phishtank_api"]

    # Check cache first
    cache_key = f"url_check:{url}"
    cached = api._cache.get(cache_key)
    if cached is not None:
        return {"cached": True, "result": cached, "summary": PhishTankAPI._url_check_summary(cached)}

    result = await api.check_url(url, fmt=format)

    # Cache successful results
    if "error" not in result:
        api._cache.set(cache_key, result.get("result", result), ttl=300)

    return result


# ---------------------------------------------------------------------------
# Tool 2: check_multiple_urls
# ---------------------------------------------------------------------------

@mcp.tool()
async def check_multiple_urls(urls: list[str], delay: int = 1000) -> dict[str, Any]:
    """Check multiple URLs for phishing with intelligent rate limiting.

    Args:
        urls: Array of URLs to check (max 50)
        delay: Delay between requests in milliseconds (500-10000, default: 1000)
    """
    if not urls or not isinstance(urls, list):
        return {"error": "URLs array is required"}
    if len(urls) > 50:
        return {"error": "Maximum 50 URLs allowed per batch"}

    delay_seconds = max(delay, 500) / 1000.0
    results: list[dict[str, Any]] = []

    for i, raw_url in enumerate(urls):
        try:
            result = await check_url(url=raw_url)
            results.append({"url": raw_url, "success": True, "data": result})
        except Exception as e:
            results.append({"url": raw_url, "success": False, "error": str(e)})

        if i < len(urls) - 1:
            await asyncio.sleep(delay_seconds)

    success_count = sum(1 for r in results if r["success"])
    return {
        "batch_results": results,
        "summary": {
            "total": len(urls),
            "successful": success_count,
            "failed": len(urls) - success_count,
            "delay_used_ms": delay,
        },
    }


# ---------------------------------------------------------------------------
# Tool 3: get_recent_phish
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_recent_phish(limit: int = 100, include_offline: bool = False) -> dict[str, Any]:
    """Get recent verified phishing URLs from the PhishTank database.

    Args:
        limit: Number of entries to return (1-1000, default: 100)
        include_offline: Include offline phishing URLs (default: false)
    """
    limit = max(1, min(limit, 1000))
    api: PhishTankAPI = mcp.get_context().request_context.lifespan_context["phishtank_api"]

    try:
        entries = await api.download_database()
    except Exception as e:
        return {"error": f"Failed to download database: {e}"}

    if not include_offline:
        entries = [e for e in entries if e.get("online") == "yes"]

    # Sort by submission_time descending
    entries.sort(key=lambda e: e.get("submission_time", ""), reverse=True)
    entries = entries[:limit]

    return {
        "total_entries": len(entries),
        "include_offline": include_offline,
        "entries": entries,
        "summary": f"Retrieved {len(entries)} recent phishing URLs"
                   + (" (including offline)" if include_offline else " (online only)"),
    }


# ---------------------------------------------------------------------------
# Tool 4: search_phish_by_target
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_phish_by_target(
    target: str, limit: int = 50, verified_only: bool = True
) -> dict[str, Any]:
    """Search phishing URLs by target company/brand.

    Args:
        target: Target company or brand name (e.g., "PayPal", "Apple")
        limit: Number of results to return (1-500, default: 50)
        verified_only: Only return verified phishing URLs (default: true)
    """
    if not target or not target.strip():
        return {"error": "Target parameter is required"}

    target = target.strip().lower()
    limit = max(1, min(limit, 500))
    api: PhishTankAPI = mcp.get_context().request_context.lifespan_context["phishtank_api"]

    try:
        all_entries = await api.download_database()
    except Exception as e:
        return {"error": f"Failed to download database: {e}"}

    entries = [
        e for e in all_entries
        if target in (e.get("target") or "").lower()
        and (not verified_only or e.get("verified") == "yes")
    ]

    entries.sort(key=lambda e: e.get("submission_time", ""), reverse=True)
    entries = entries[:limit]

    return {
        "search_target": target,
        "verified_only": verified_only,
        "matches_found": len(entries),
        "entries": entries,
        "summary": f'Found {len(entries)} phishing URLs targeting "{target}"'
                   + (" (verified only)" if verified_only else ""),
    }


# ---------------------------------------------------------------------------
# Tool 5: get_phish_details
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_phish_details(phish_id: int) -> dict[str, Any]:
    """Get detailed information about a specific phish by its ID.

    Args:
        phish_id: PhishTank phish ID number
    """
    if not phish_id or phish_id <= 0:
        return {"error": "Valid phish_id is required"}

    api: PhishTankAPI = mcp.get_context().request_context.lifespan_context["phishtank_api"]

    try:
        entries = await api.download_database()
    except Exception as e:
        return {"error": f"Failed to download database: {e}"}

    entry = next((e for e in entries if e.get("phish_id") == phish_id), None)

    if not entry:
        return {
            "phish_id": phish_id,
            "found": False,
            "summary": f"Phish ID {phish_id} not found in database",
        }

    return {
        "phish_id": phish_id,
        "found": True,
        "details": entry,
        "summary": f"Details for phish ID {phish_id}: {entry.get('url')} "
                   f"(Target: {entry.get('target', 'Unknown')})",
    }


# ---------------------------------------------------------------------------
# Tool 6: get_phish_stats
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_phish_stats(days: int = 7, top_targets_limit: int = 10) -> dict[str, Any]:
    """Get statistics about phishing trends and top targeted brands.

    Args:
        days: Number of days to analyze (1-30, default: 7)
        top_targets_limit: Number of top targets to include (1-50, default: 10)
    """
    days = max(1, min(days, 30))
    top_targets_limit = max(1, min(top_targets_limit, 50))
    api: PhishTankAPI = mcp.get_context().request_context.lifespan_context["phishtank_api"]

    try:
        entries = await api.download_database()
    except Exception as e:
        return {"error": f"Failed to download database: {e}"}

    # Filter by date range
    cutoff = datetime.now(timezone.utc).timestamp() - (days * 86400)
    recent = [
        e for e in entries
        if _parse_timestamp(e.get("submission_time", "")) >= cutoff
    ]

    total_verified = sum(1 for e in recent if e.get("verified") == "yes")
    total_online = sum(1 for e in recent if e.get("online") == "yes")

    # Count top targets
    target_counts = Counter(e.get("target") for e in recent if e.get("target"))
    top_targets = [
        {"target": t, "count": c}
        for t, c in target_counts.most_common(top_targets_limit)
    ]

    from datetime import timedelta
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

    return {
        "statistics": {
            "total_phish": len(recent),
            "total_verified": total_verified,
            "total_online": total_online,
            "top_targets": top_targets,
            "date_range": {
                "from": cutoff_date.strftime("%Y-%m-%d"),
                "to": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            },
        },
        "analysis_period_days": days,
        "summary": f"Analyzed {len(recent)} phishing submissions over {days} days. "
                   f"{total_verified} verified, {total_online} currently online.",
    }


def _parse_timestamp(ts: str) -> float:
    """Parse a PhishTank submission_time string to a Unix timestamp."""
    try:
        # PhishTank uses ISO-8601 format, e.g. "2026-04-09T12:34:56+00:00"
        dt = datetime.fromisoformat(ts)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


# ---------------------------------------------------------------------------
# Tool 7: search_phish_by_date
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_phish_by_date(
    start_date: str, end_date: str, limit: int = 100
) -> dict[str, Any]:
    """Search phishing URLs by submission date range.

    Args:
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        limit: Number of results to return (1-500, default: 100)
    """
    if not start_date or not end_date:
        return {"error": "Both start_date and end_date are required"}

    # Validate format
    for label, d in [("start_date", start_date), ("end_date", end_date)]:
        try:
            parsed = datetime.strptime(d, "%Y-%m-%d")
        except ValueError:
            return {"error": f"Invalid {label} format. Use YYYY-MM-DD"}

    start_ts = datetime.strptime(start_date, "%Y-%m-%d").timestamp()
    end_ts = datetime.strptime(end_date, "%Y-%m-%d").timestamp() + 86400  # include full end day

    if start_ts > end_ts:
        return {"error": "Start date must be before end date"}

    limit = max(1, min(limit, 500))
    api: PhishTankAPI = mcp.get_context().request_context.lifespan_context["phishtank_api"]

    try:
        all_entries = await api.download_database()
    except Exception as e:
        return {"error": f"Failed to download database: {e}"}

    entries = [
        e for e in all_entries
        if start_ts <= _parse_timestamp(e.get("submission_time", "")) < end_ts
    ]
    entries.sort(key=lambda e: e.get("submission_time", ""), reverse=True)
    entries = entries[:limit]

    return {
        "date_range": {"start": start_date, "end": end_date},
        "matches_found": len(entries),
        "entries": entries,
        "summary": f"Found {len(entries)} phishing URLs submitted between {start_date} and {end_date}",
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
