"""Feed aggregator that coordinates all threat feed sources.

Provides parallel fetching and error handling.
"""

import asyncio
from datetime import datetime
from typing import Any

from structlog import get_logger

from src.config import get_settings
from src.feeds.normalizer import FeedNormalizer, ThreatIndicatorData
from src.feeds.phishtank import PhishTankClient, PhishTankError
from src.feeds.urlhaus import URLhausClient, URLhausError
from src.feeds.reddit_monitor import RedditMonitor, RedditError

logger = get_logger()


class FeedAggregatorError(Exception):
    """Exception raised for feed aggregator errors."""

    def __init__(self, message: str, source: str | None = None):
        """Initialize error.

        Args:
            message: Error message
            source: Feed source that caused the error
        """
        super().__init__(message)
        self.source = source


class FeedAggregator:
    """Coordinates fetching from multiple threat feed sources.

    Provides:
    - Parallel fetching from all configured sources
    - Error handling with circuit breaker pattern
    - Feed status tracking
    """

    # Circuit breaker config
    MAX_ERRORS = 5
    RECOVERY_TIMEOUT = 300  # 5 minutes

    def __init__(self):
        """Initialize feed aggregator."""
        self.settings = get_settings()
        self.normalizer = FeedNormalizer()

        # Feed clients
        self._phishtank: PhishTankClient | None = None
        self._urlhaus: URLhausClient | None = None
        self._reddit: RedditMonitor | None = None

        # Circuit breaker state per source
        self._error_counts: dict[str, int] = {}
        self._circuit_open: dict[str, bool] = {}
        self._last_failure: dict[str, datetime | None] = {}

    @property
    def phishtank(self) -> PhishTankClient:
        """Get or create PhishTank client."""
        if self._phishtank is None:
            self._phishtank = PhishTankClient()
        return self._phishtank

    @property
    def urlhaus(self) -> URLhausClient:
        """Get or create URLhaus client."""
        if self._urlhaus is None:
            self._urlhaus = URLhausClient()
        return self._urlhaus

    @property
    def reddit(self) -> RedditMonitor:
        """Get or create Reddit monitor."""
        if self._reddit is None:
            self._reddit = RedditMonitor()
        return self._reddit

    def _is_circuit_open(self, source: str) -> bool:
        """Check if circuit breaker is open for a source.

        Args:
            source: Feed source name

        Returns:
            True if circuit is open (should skip)
        """
        if not self._circuit_open.get(source, False):
            return False

        # Check if recovery timeout has passed
        last_failure = self._last_failure.get(source)
        if last_failure:
            elapsed = (datetime.utcnow() - last_failure).total_seconds()
            if elapsed > self.RECOVERY_TIMEOUT:
                # Half-open: try again
                self._circuit_open[source] = False
                self._error_counts[source] = 0
                logger.info(f"Circuit breaker recovered for {source}")
                return False

        return True

    def _record_success(self, source: str) -> None:
        """Record successful fetch.

        Args:
            source: Feed source name
        """
        self._error_counts[source] = 0
        self._circuit_open[source] = False

    def _record_failure(self, source: str, error: Exception) -> None:
        """Record failed fetch.

        Args:
            source: Feed source name
            error: Exception that occurred
        """
        self._error_counts[source] = self._error_counts.get(source, 0) + 1
        self._last_failure[source] = datetime.utcnow()

        if self._error_counts[source] >= self.MAX_ERRORS:
            self._circuit_open[source] = True
            logger.warning(
                f"Circuit breaker opened for {source}",
                error_count=self._error_counts[source],
            )

    async def fetch_all_sources(
        self,
        sources: list[str] | None = None,
        limit_per_source: int = 100,
    ) -> list[ThreatIndicatorData]:
        """Fetch indicators from all sources in parallel.

        Args:
            sources: List of sources to fetch (None = all)
            limit_per_source: Max indicators per source

        Returns:
            List of all normalized indicators
        """
        sources = sources or ["phishtank", "urlhaus", "reddit"]
        tasks = []

        for source in sources:
            if self._is_circuit_open(source):
                logger.info(f"Skipping {source} - circuit breaker open")
                continue

            if source == "phishtank":
                tasks.append(self._fetch_phishtank(limit_per_source))
            elif source == "urlhaus":
                tasks.append(self._fetch_urlhaus(limit_per_source))
            elif source == "reddit":
                tasks.append(self._fetch_reddit(limit_per_source))

        if not tasks:
            logger.warning("All feed sources have circuit breakers open")
            return []

        # Run all fetches in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_indicators = []
        for source, result in zip(sources, results):
            if isinstance(result, Exception):
                logger.error(f"Feed fetch failed for {source}", error=str(result))
                self._record_failure(source, result)
            elif isinstance(result, list):
                all_indicators.extend(result)
                self._record_success(source)
                logger.info(f"Fetched {len(result)} indicators from {source}")

        logger.info(
            "Feed aggregation complete",
            total_indicators=len(all_indicators),
            sources_fetched=len([r for r in results if isinstance(r, list)]),
        )

        return all_indicators

    async def _fetch_phishtank(self, limit: int) -> list[ThreatIndicatorData]:
        """Fetch from PhishTank."""
        try:
            async with self.phishtank as client:
                return await client.fetch_feed(limit=limit)
        except PhishTankError:
            raise

    async def _fetch_urlhaus(self, limit: int) ->list[ThreatIndicatorData]:
        """Fetch from URLhaus."""
        try:
            async with self.urlhaus as client:
                return await client.fetch_feed(limit=limit)
        except URLhausError:
            raise

    async def _fetch_reddit(self, limit: int) ->list[ThreatIndicatorData]:
        """Fetch from Reddit."""
        try:
            return await self.reddit.fetch_feed(limit=limit)
        except RedditError:
            raise

    async def fetch_source(self, source: str, limit: int = 100) -> list[ThreatIndicatorData]:
        """Fetch from a single source.

        Args:
            source: Feed source name
            limit: Maximum indicators to fetch

        Returns:
            List of normalized indicators
        """
        if self._is_circuit_open(source):
            logger.warning(f"Circuit breaker open for {source}")
            return []

        try:
            if source == "phishtank":
                return await self._fetch_phishtank(limit)
            elif source == "urlhaus":
                return await self._fetch_urlhaus(limit)
            elif source == "reddit":
                return await self._fetch_reddit(limit)
            else:
                raise FeedAggregatorError(f"Unknown source: {source}")

        except Exception as e:
            self._record_failure(source, e)
            raise

    def get_source_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all feed sources.

        Returns:
            Dictionary mapping source names to status info
        """
        statuses = {}

        for source in ["phishtank", "urlhaus", "reddit"]:
            statuses[source] = {
                "circuit_open": self._circuit_open.get(source, False),
                "error_count": self._error_counts.get(source, 0),
                "last_failure": self._last_failure.get(source).isoformat() if self._last_failure.get(source) else None,
            }

        return statuses

    async def close(self) -> None:
        """Close all feed clients."""
        if self._phishtank:
            await self._phishtank.close()
        if self._urlhaus:
            await self._urlhaus.close()

    async def __aenter__(self) -> "FeedAggregator":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
