"""URLhaus API client for malicious URL feeds.

URLhaus by abuse.ch provides a curated list of malicious URLs.
API docs: https://urlhaus-api.abuse.ch/
"""

import asyncio
from datetime import datetime
from typing import Any

import aiohttp
from structlog import get_logger

from src.config import get_settings
from src.feeds.normalizer import FeedNormalizer, ThreatIndicatorData

logger = get_logger()


class URLhausError(Exception):
    """Exception raised for URLhaus API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        """Initialize error.

        Args:
            message: Error message
            status_code: HTTP status code if applicable
        """
        super().__init__(message)
        self.status_code = status_code


class URLhausClient:
    """Async client for URLhaus API.

    Rate limits:
    - Public API: No explicit rate limit documented
    - Recommended: Do not fetch more than 1000 URLs at a time
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, limit: int = 100):
        """Initialize URLhaus client.

        Args:
            limit: Maximum number of URLs to fetch
        """
        self.limit = limit
        self.normalizer = FeedNormalizer()
        self._session: aiohttp.ClientSession | None = None
        self._last_request_time: datetime | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _rate_limit(self) -> None:
        """Wait before making a request to respect rate limits."""
        await asyncio.sleep(1)

    async def fetch_feed(self, limit: int | None = None) -> list[ThreatIndicatorData]:
        """Fetch recent malicious URLs from URLhaus.

        Args:
            limit: Maximum number of URLs to fetch (None = all)

        Returns:
            List of normalized threat indicators

        Raises:
            URLhausError: If API request fails
        """
        limit = limit or self.limit
        session = await self._get_session()

        await self._rate_limit()

        try:
            # URLhaus supports tag filtering
            params = {"limit": limit}

            logger.info("Fetching URLhaus feed", limit=limit)

            async with session.get(f"{self.BASE_URL}/urls/recent/", params=params) as response:
                self._last_request_time = datetime.utcnow()

                if response.status == 429:
                    raise URLhausError("Rate limit exceeded", status_code=429)

                if response.status != 200:
                    text = await response.text()
                    raise URLhausError(
                        f"API error: {response.status} - {text}",
                        status_code=response.status,
                    )

                data = await response.json()
                urls = data.get("urls", [])

                # Limit results if specified
                if limit:
                    urls = urls[:limit]

                # Normalize all entries
                indicators = []
                for item in urls:
                    try:
                        indicator = self.normalizer.normalize_urlhaus(item)
                        if indicator:
                            indicators.append(indicator)
                    except Exception:
                        # Skip entries that fail to normalize
                        continue

                logger.info(
                    "URLhaus fetch complete",
                    fetched=len(urls),
                    normalized=len(indicators),
                )

                return indicators

        except aiohttp.ClientError as e:
            logger.warning("URLhaus request failed", error=str(e))
            return []
        except Exception as e:
            logger.exception("URLhaus fetch error", error=str(e))
            return []

    async def fetch_by_tag(self, tag: str, limit: int = 100) -> list[ThreatIndicatorData]:
        """Fetch URLs by tag from URLhaus.

        Args:
            tag: Tag to filter by (e.g., ' Trickbot', 'Emotet')
            limit: Maximum number of URLs to fetch

        Returns:
            List of normalized threat indicators
        """
        session = await self._get_session()

        await self._rate_limit()

        try:
            params = {"tag": tag, "limit": limit}

            logger.info("Fetching URLhaus by tag", tag=tag, limit=limit)

            async with session.get(f"{self.BASE_URL}/urls/tag/", params=params) as response:
                self._last_request_time = datetime.utcnow()

                if response.status != 200:
                    text = await response.text()
                    raise URLhausError(
                        f"API error: {response.status} - {text}",
                        status_code=response.status,
                    )

                data = await response.json()
                urls = data.get("urls", [])

                indicators = []
                for item in urls:
                    try:
                        indicator = self.normalizer.normalize_urlhaus(item)
                        if indicator:
                            indicators.append(indicator)
                    except Exception:
                        continue

                logger.info(
                    "URLhaus tag fetch complete",
                    tag=tag,
                    fetched=len(urls),
                    normalized=len(indicators),
                )

                return indicators

        except aiohttp.ClientError as e:
            logger.warning("URLhaus tag request failed", tag=tag, error=str(e))
            return []

    async def check_url(self, url: str) -> dict[str, Any] | None:
        """Check if a specific URL is in URLhaus database.

        Args:
            url: URL to check

        Returns:
            URLhaus entry if found, None otherwise
        """
        session = await self._get_session()

        await self._rate_limit()

        try:
            async with session.post(
                f"{self.BASE_URL}/url/",
                data={"url": url},
            ) as response:
                if response.status != 200:
                    return None

                data = await response.json()
                return data

        except aiohttp.ClientError:
            return None

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> "URLhausClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    def get_feed_stats(self) -> dict[str, Any]:
        """Get statistics about the feed.

        Returns:
            Dictionary with feed statistics
        """
        return {
            "source": "urlhaus",
            "status": "operational",
            "last_check": self._last_request_time.isoformat() if self._last_request_time else None,
        }
