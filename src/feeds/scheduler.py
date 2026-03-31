"""Feed scheduler for periodic threat feed updates.

Implements scheduled updates with circuit breaker pattern.
"""

import asyncio
from datetime import datetime
from typing import Any

from structlog import get_logger

from src.config import get_settings
from src.feeds.aggregator import FeedAggregator, FeedAggregatorError
from src.feeds.normalizer import ThreatIndicatorData

logger = get_logger()


class FeedScheduler:
    """Schedules periodic updates from threat feeds.

    Features:
    - Configurable update intervals
    - Circuit breaker for failing sources
    - Manual trigger support
    """

    def __init__(self, update_interval: int = 3600):
        """Initialize feed scheduler.

        Args:
            update_interval: Update interval in seconds (default: 1 hour)
        """
        self.update_interval = update_interval
        self.aggregator = FeedAggregator()
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_update: datetime | None = None

    async def start(self) -> None:
        """Start the scheduled feed updates."""
        if self._running:
            logger.warning("Feed scheduler already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_scheduler())
        logger.info("Feed scheduler started", interval=self.update_interval)

    async def stop(self) -> None:
        """Stop the scheduled feed updates."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Feed scheduler stopped")

    async def _run_scheduler(self) -> None:
        """Run the scheduler loop."""
        while self._running:
            try:
                await self._update_feeds()
            except Exception as e:
                logger.error("Feed update failed", error=str(e))

            # Wait for next update
            await asyncio.sleep(self.update_interval)

    async def _update_feeds(self) -> None:
        """Update all feeds."""
        logger.info("Starting scheduled feed update")

        try:
            indicators = await self.aggregator.fetch_all_sources()
            self._last_update = datetime.utcnow()

            logger.info(
                "Feed update complete",
                total_indicators=len(indicators),
            )
        except FeedAggregatorError as e:
            logger.error("Feed aggregator error", error=str(e))
            raise

    async def trigger_update(self) -> list[ThreatIndicatorData]:
        """Manually trigger a feed update.

        Returns:
            List of fetched indicators
        """
        logger.info("Manual feed update triggered")
        await self._update_feeds()
        return await self.aggregator.fetch_all_sources()

    def get_status(self) -> dict[str, Any]:
        """Get scheduler status.

        Returns:
            Dictionary with scheduler status
        """
        return {
            "running": self._running,
            "update_interval": self.update_interval,
            "last_update": self._last_update.isoformat() if self._last_update else None,
        }
