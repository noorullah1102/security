"""Feed API routes for threat indicators and feed status management."""

import csv
import io
from datetime import datetime
from typing import Annotated, Any

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from structlog import get_logger

from src.api.middleware.auth import verify_api_key
from src.api.schemas.common import SuccessResponse
from src.db.database import DatabaseManager
from src.db.repository import FeedStatusRepository, ThreatIndicatorRepository
from src.feeds.aggregator import FeedAggregator
from src.feeds.normalizer import ThreatIndicatorData

logger = get_logger()

router = APIRouter(prefix="/api/v1/feeds", tags=["Feeds"])


# Response models
class ThreatIndicatorResponse(BaseModel):
    """Threat indicator from feed response."""

    id: str
    source: str
    url: str
    threat_type: str
    first_seen: datetime
    last_seen: datetime
    target_brand: str | None = None
    confidence: float = 1.0
    extra_data: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class SourceStatusResponse(BaseModel):
    """Feed status for feed sources."""

    source: str
    status: str
    last_update: datetime | None
    last_attempt: datetime | None
    indicator_count: int
    error_count: int
    last_error: str | None


class FeedRefreshResponse(BaseModel):
    """Response for feed refresh."""

    message: str
    sources: list[str]
    indicators_fetched: int


class ThreatIndicatorListResponse(BaseModel):
    """List of threat indicators."""

    indicators: list[ThreatIndicatorResponse]
    total: int
    limit: int
    offset: int


def get_indicator_repository() -> ThreatIndicatorRepository:
    """Get threat indicator repository instance."""
    db = DatabaseManager.get_database()
    return ThreatIndicatorRepository(db)


def get_feed_status_repository() -> FeedStatusRepository:
    """Get feed status repository instance."""
    db = DatabaseManager.get_database()
    return FeedStatusRepository(db)


@router.get(
    "/indicators",
    response_model=ThreatIndicatorListResponse,
    summary="Get threat indicators",
)
async def get_indicators(
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[ThreatIndicatorRepository, Depends(get_indicator_repository)],
    source: str | None = Query(default=None, description="Filter by source"),
    threat_type: str | None = Query(default=None, description="Filter by threat type"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ThreatIndicatorListResponse:
    """Get cached threat indicators from feeds.

    Supports filtering by source (phishtank, urlhaus, reddit) and threat type.
    """
    indicators = repo.get_recent(
        source=source,
        threat_type=threat_type,
        limit=limit,
    )

    return ThreatIndicatorListResponse(
        indicators=[
            ThreatIndicatorResponse(
                id=ind.id,
                source=ind.source,
                url=ind.url,
                threat_type=ind.threat_type,
                first_seen=ind.first_seen,
                last_seen=ind.last_seen,
                target_brand=ind.target_brand,
                confidence=ind.confidence,
                extra_data=ind.extra_data or {},
                tags=ind.tags or [],
            )
            for ind in indicators
        ],
        total=len(indicators),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/status",
    response_model=list[SourceStatusResponse],
    summary="Get feed status",
)
async def get_feed_status(
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[FeedStatusRepository, Depends(get_feed_status_repository)],
) -> list[SourceStatusResponse]:
    """Get health status for all feed sources."""
    statuses = repo.get_all_status()

    return [
        SourceStatusResponse(
            source=fs.source,
            status=fs.status,
            last_update=fs.last_update,
            last_attempt=fs.last_attempt,
            indicator_count=fs.indicator_count or 0,
            error_count=fs.error_count or 0,
            last_error=fs.last_error,
        )
        for fs in statuses
    ]


@router.post(
    "/refresh",
    response_model=FeedRefreshResponse,
    summary="Manually refresh feeds",
)
async def refresh_feeds(
    api_key: Annotated[str, Depends(verify_api_key)],
    sources: list[str] | None = Query(default=None, description="Sources to refresh"),
) -> FeedRefreshResponse:
    """Manually trigger feed refresh.

    If sources not specified, refreshes all sources.
    """
    aggregator = FeedAggregator()

    try:
        indicators = await aggregator.fetch_all_sources(sources=sources)

        return FeedRefreshResponse(
            message="Feed refresh completed",
            sources=sources or ["phishtank", "urlhaus", "reddit"],
            indicators_fetched=len(indicators),
        )
    except Exception as e:
        logger.error("Feed refresh failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Feed refresh failed: {e}",
        )
    finally:
        await aggregator.close()


class LiveFeedEntry(BaseModel):
    """Single live feed entry."""
    url: str
    source: str
    threat_type: str = "phishing"
    first_seen: str | None = None


class LiveFeedResponse(BaseModel):
    """Response from live feed fetch."""
    entries: list[LiveFeedEntry]
    total: int
    sources_queried: list[str]


@router.get(
    "/live",
    response_model=LiveFeedResponse,
    summary="Get live threat URLs from free feeds",
)
async def get_live_feed(
    api_key: Annotated[str, Depends(verify_api_key)],
    source: str | None = Query(default=None, description="Filter by source"),
    limit: int = Query(default=100, ge=1, le=500),
) -> LiveFeedResponse:
    """Fetch live threat URLs directly from free feeds (no API keys needed).

    Sources: URLhaus (plain text), OpenPhish (feed.txt), PhishTank (CSV or cache).
    Each source is fetched independently — one failure doesn't affect others.
    """
    entries: list[LiveFeedEntry] = []
    sources_queried: list[str] = []
    timeout = aiohttp.ClientTimeout(total=20, connect=8)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # URLhaus — plain text URL list (no auth needed)
        if not source or source == "urlhaus":
            sources_queried.append("urlhaus")
            try:
                async with session.get("https://urlhaus.abuse.ch/downloads/text_online/") as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        urls = [
                            line.strip() for line in text.strip().split("\n")
                            if line.strip() and not line.startswith("#")
                        ]
                        for url in urls[:limit]:
                            entries.append(LiveFeedEntry(url=url, source="urlhaus", threat_type="malware_download"))
                        logger.info("Live URLhaus fetched", count=min(len(urls), limit))
            except Exception as e:
                logger.warning("Live URLhaus fetch failed", error=str(e))

        # OpenPhish — feed.txt (no auth needed)
        if not source or source == "openphish":
            sources_queried.append("openphish")
            try:
                async with session.get("https://openphish.com/feed.txt") as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        urls = [line.strip() for line in text.strip().split("\n") if line.strip()]
                        for url in urls[:limit]:
                            entries.append(LiveFeedEntry(url=url, source="openphish", threat_type="phishing"))
                        logger.info("Live OpenPhish fetched", count=len(urls[:limit]))
            except Exception as e:
                logger.warning("Live OpenPhish fetch failed", error=str(e))

        # PhishTank — try CSV (often 403), fall back to disk cache
        if not source or source == "phishtank":
            sources_queried.append("phishtank")
            phishtank_ok = False
            try:
                feed_urls = [
                    "https://data.phishtank.com/data/online-valid.csv",
                    "http://data.phishtank.com/data/online-valid.csv",
                ]
                for feed_url in feed_urls:
                    try:
                        async with session.get(feed_url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                reader = csv.DictReader(io.StringIO(text))
                                count = 0
                                for row in reader:
                                    if row.get("url") and count < limit:
                                        entries.append(LiveFeedEntry(
                                            url=row["url"],
                                            source="phishtank",
                                            threat_type="phishing",
                                            first_seen=row.get("submission_time"),
                                        ))
                                        count += 1
                                phishtank_ok = True
                                logger.info("Live PhishTank fetched from CSV", count=count)
                                break
                    except Exception:
                        continue
            except Exception as e:
                logger.warning("Live PhishTank CSV failed", error=str(e))

            # Fallback: load from disk cache if CSV failed
            if not phishtank_ok:
                try:
                    from pathlib import Path
                    import json
                    cache_file = Path("data") / "phishtank_cache.json"
                    if cache_file.exists():
                        with open(cache_file) as f:
                            cached_urls = json.load(f)
                        for url in cached_urls[:limit]:
                            entries.append(LiveFeedEntry(url=url, source="phishtank", threat_type="phishing"))
                        logger.info("PhishTank loaded from disk cache", count=min(len(cached_urls), limit))
                except Exception as e:
                    logger.warning("PhishTank disk cache failed", error=str(e))

    # Each source gets up to `limit` entries, no total cap
    return LiveFeedResponse(
        entries=entries,
        total=len(entries),
        sources_queried=sources_queried,
    )
