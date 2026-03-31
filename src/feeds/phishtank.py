"""PhishTank API client for phishing URL feeds.

PhishTank is a community-driven phishing URL database.
API docs: https://www.phishtank.com/api_info.php
"""

import asyncio
from datetime import datetime
from typing import Any

import aiohttp
from structlog import get_logger

from src.config import get_settings
from src.feeds.normalizer import FeedNormalizer, ThreatIndicatorData

logger = get_logger()


class PhishTankClient:
    """Async client for PhishTank API.

    Rate limits:
    - Unauthenticated: 1 request per minute
    - Authenticated: Higher limits (requires API key)
    """

    BASE_URL = "https://data.phishtank.com/data"
    FEED_URL = "https://data.phishtank.com/data/online-valid.json"

    # Rate limiting
    MIN_REQUEST_INTERVAL = 60  # seconds (1 request per minute unauthenticated)

    def __init__(self, api_key: str | None = None):
        """Initialize PhishTank client.

        Args:
            api_key: Optional PhishTank API key for higher rate limits
        """
        self.api_key = api_key or get_settings().phishtank_api_key
        self.normalizer = FeedNormalizer()
        self._last_request_time: datetime | None = None
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        if self._last_request_time:
            elapsed = (datetime.utcnow() - self._last_request_time).total_seconds()
            if elapsed < self.MIN_REQUEST_INTERVAL:
                wait_time = self.MIN_REQUEST_INTERVAL - elapsed
                logger.debug("Rate limiting PhishTank request", wait_seconds=wait_time)
                await asyncio.sleep(wait_time)

    async def fetch_feed(self, limit: int | None = None) -> list[ThreatIndicatorData]:
        """Fetch all online/verified phishing URLs from PhishTank.

        Args:
            limit: Maximum number of entries to fetch (None = all)

        Returns:
            List of normalized threat indicators

        Raises:
            PhishTankError: If API request fails
        """
        await self._rate_limit()

        session = await self._get_session()

        try:
            # Build URL - authenticated users can use their API key
            if self.api_key:
                url = f"{self.BASE_URL}/{self.api_key}/online-valid.json"
            else:
                url = self.FEED_URL

            logger.info("Fetching PhishTank feed", url=url, limit=limit)

            async with session.get(url) as response:
                self._last_request_time = datetime.utcnow()

                if response.status == 429:
                    raise PhishTankError("Rate limit exceeded", status_code=429)

                if response.status != 200:
                    text = await response.text()
                    raise PhishTankError(
                        f"API error: {response.status} - {text}",
                        status_code=response.status,
                    )

                data = await response.json()

            # Limit results if specified
            if limit:
                data = data[:limit]

            # Normalize all entries
            indicators = self.normalizer.normalize_batch("phishtank", data)

            logger.info(
                "PhishTank fetch complete",
                fetched=len(data),
                normalized=len(indicators),
            )

            return indicators

        except aiohttp.ClientError as e:
            self._last_request_time = datetime.utcnow()
            raise PhishTankError(f"Network error: {e}") from e
        except Exception as e:
            self._last_request_time = datetime.utcnow()
            if isinstance(e, PhishTankError):
                raise
            raise PhishTankError(f"Unexpected error: {e}") from e

    async def check_url(self, url: str) -> dict[str, Any] | None:
        """Check if a specific URL is in PhishTank database.

        Note: This uses a different endpoint and may have different rate limits.

        Args:
            url: URL to check

        Returns:
            PhishTank data for the URL or None if not found
        """
        await self._rate_limit()

        session = await self._get_session()

        try:
            # PhishTank check URL endpoint
            check_url = "https://checkurl.phishtank.com/checkurl/"
            params = {"url": url}

            if self.api_key:
                params["app_key"] = self.api_key

            async with session.post(check_url, data=params) as response:
                self._last_request_time = datetime.utcnow()

                if response.status == 429:
                    raise PhishTankError("Rate limit exceeded", status_code=429)

                if response.status != 200:
                    return None

                data = await response.json()

            if data.get("results") and data["results"].get("in_database"):
                return data["results"]

            return None

        except aiohttp.ClientError as e:
            logger.warning("PhishTank URL check failed", url=url, error=str(e))
            return None

    async def get_feed_stats(self) -> dict[str, Any]:
        """Get statistics about the PhishTank feed.

        Returns:
            Dictionary with feed statistics
        """
        try:
            indicators = await self.fetch_feed(limit=10)  # Small fetch to check health
            return {
                "source": "phishtank",
                "status": "healthy",
                "sample_size": len(indicators),
                "last_check": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "source": "phishtank",
                "status": "error",
                "error": str(e),
                "last_check": datetime.utcnow().isoformat(),
            }


class PhishTankError(Exception):
    """Exception raised for PhishTank API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        """Initialize error.

        Args:
            message: Error message
            status_code: HTTP status code if applicable
        """
        super().__init__(message)
        self.status_code = status_code
