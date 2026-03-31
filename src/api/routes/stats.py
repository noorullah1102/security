"""Statistics API endpoints for dashboard."""

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from structlog import get_logger

from src.api.middleware.auth import verify_api_key
from src.db.database import DatabaseManager
from src.db.repository import ScanRepository, ThreatIndicatorRepository, FeedStatusRepository

logger = get_logger()
router = APIRouter(prefix="/api/v1/stats", tags=["Statistics"])


# Response Models
class StatsSummaryResponse(BaseModel):
    """Summary statistics response."""

    total_scans: int = Field(description="Total scans in period")
    phishing_detected: int = Field(description="Phishing URLs detected")
    safe_urls: int = Field(description="Safe URLs")
    suspicious_urls: int = Field(description="Suspicious URLs")
    avg_confidence: float = Field(description="Average confidence score")
    period_days: int = Field(description="Period in days")


class VerdictDistributionResponse(BaseModel):
    """Verdict distribution response."""

    verdict: str
    count: int
    percentage: float


class TrendDataPoint(BaseModel):
    """Single data point in trend."""

    date: str
    count: int
    verdict: str


class TrendsResponse(BaseModel):
    """Scan trends response."""

    period_days: int
    data: list[TrendDataPoint]


class TopBrandResponse(BaseModel):
    """Top targeted brand response."""

    brand: str
    count: int
    percentage: float


class FeedStatusResponse(BaseModel):
    """Feed status for dashboard."""

    source: str
    status: str
    last_update: str | None
    indicator_count: int
    error_count: int


class DashboardStatsResponse(BaseModel):
    """Combined dashboard statistics."""

    summary: StatsSummaryResponse
    verdict_distribution: list[VerdictDistributionResponse]
    top_brands: list[TopBrandResponse]
    feed_status: list[FeedStatusResponse]


def get_scan_repository() -> ScanRepository:
    """Get scan repository instance."""
    db = DatabaseManager.get_database()
    return ScanRepository(db)


def get_indicator_repository() -> ThreatIndicatorRepository:
    """Get threat indicator repository instance."""
    db = DatabaseManager.get_database()
    return ThreatIndicatorRepository(db)


def get_feed_status_repository() -> FeedStatusRepository:
    """Get feed status repository instance."""
    db = DatabaseManager.get_database()
    return FeedStatusRepository(db)


@router.get(
    "/summary",
    response_model=StatsSummaryResponse,
    summary="Get scan statistics summary",
)
async def get_stats_summary(
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
    days: int = 7,
) -> StatsSummaryResponse:
    """Get summary statistics for the past N days.

    Requires valid API key in X-API-Key header.
    """
    stats = repo.get_stats(days=days)
    return StatsSummaryResponse(
        total_scans=stats.get("total_scans", 0),
        phishing_detected=stats.get("phishing_detected", 0),
        safe_urls=stats.get("safe_urls", 0),
        suspicious_urls=stats.get("suspicious", 0),
        avg_confidence=stats.get("avg_confidence", 0.0),
        period_days=days,
    )


@router.get(
    "/verdicts",
    response_model=list[VerdictDistributionResponse],
    summary="Get verdict distribution",
)
async def get_verdict_distribution(
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
    days: int = 7,
) -> list[VerdictDistributionResponse]:
    """Get distribution of verdicts for the past N days."""
    stats = repo.get_stats(days=days)
    total = stats.get("total_scans", 0)

    if total == 0:
        return []

    return [
        VerdictDistributionResponse(
            verdict="phishing",
            count=stats.get("phishing_detected", 0),
            percentage=round(stats.get("phishing_detected", 0) / total * 100, 1),
        ),
        VerdictDistributionResponse(
            verdict="safe",
            count=stats.get("safe_urls", 0),
            percentage=round(stats.get("safe_urls", 0) / total * 100, 1),
        ),
        VerdictDistributionResponse(
            verdict="suspicious",
            count=stats.get("suspicious", 0),
            percentage=round(stats.get("suspicious", 0) / total * 100, 1),
        ),
    ]


@router.get(
    "/trends",
    response_model=TrendsResponse,
    summary="Get scan trends over time",
)
async def get_scan_trends(
    api_key: Annotated[str, Depends(verify_api_key)],
    days: int = 7,
) -> TrendsResponse:
    """Get scan count trends grouped by day.

    Returns daily counts for each verdict type.
    """
    # This would ideally be a database query with GROUP BY
    # For now, return placeholder data
    data_points = []
    for i in range(days):
        date = (datetime.utcnow() - timedelta(days=days - i - 1)).strftime("%Y-%m-%d")
        # Placeholder - would be replaced with actual DB query
        data_points.extend([
            TrendDataPoint(date=date, count=0, verdict="phishing"),
            TrendDataPoint(date=date, count=0, verdict="safe"),
            TrendDataPoint(date=date, count=0, verdict="suspicious"),
        ])

    return TrendsResponse(period_days=days, data=data_points)


@router.get(
    "/brands",
    response_model=list[TopBrandResponse],
    summary="Get top targeted brands",
)
async def get_top_brands(
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
    limit: int = 10,
) -> list[TopBrandResponse]:
    """Get most frequently targeted brands."""
    # This would query scan_history grouped by target_brand
    # For now, return empty list
    return []


@router.get(
    "/dashboard",
    response_model=DashboardStatsResponse,
    summary="Get all dashboard statistics",
)
async def get_dashboard_stats(
    api_key: Annotated[str, Depends(verify_api_key)],
    scan_repo: Annotated[ScanRepository, Depends(get_scan_repository)],
    feed_repo: Annotated[FeedStatusRepository, Depends(get_feed_status_repository)],
    days: int = 7,
) -> DashboardStatsResponse:
    """Get all statistics needed for dashboard in single request.

    Combines:
    - Summary stats
    - Verdict distribution
    - Top targeted brands
    - Feed status
    """
    # Get summary stats
    stats = scan_repo.get_stats(days=days)
    total = stats.get("total_scans", 0)

    summary = StatsSummaryResponse(
        total_scans=total,
        phishing_detected=stats.get("phishing_detected", 0),
        safe_urls=stats.get("safe_urls", 0),
        suspicious_urls=stats.get("suspicious", 0),
        avg_confidence=stats.get("avg_confidence", 0.0),
        period_days=days,
    )

    # Calculate verdict distribution
    verdicts = []
    if total > 0:
        verdicts = [
            VerdictDistributionResponse(
                verdict="phishing",
                count=stats.get("phishing_detected", 0),
                percentage=round(stats.get("phishing_detected", 0) / total * 100, 1),
            ),
            VerdictDistributionResponse(
                verdict="safe",
                count=stats.get("safe_urls", 0),
                percentage=round(stats.get("safe_urls", 0) / total * 100, 1),
            ),
            VerdictDistributionResponse(
                verdict="suspicious",
                count=stats.get("suspicious", 0),
                percentage=round(stats.get("suspicious", 0) / total * 100, 1),
            ),
        ]

    # Get feed status
    feed_statuses = feed_repo.get_all_status()
    feeds = [
        FeedStatusResponse(
            source=fs.source,
            status=fs.status,
            last_update=fs.last_update.isoformat() if fs.last_update else None,
            indicator_count=fs.indicator_count or 0,
            error_count=fs.error_count or 0,
        )
        for fs in feed_statuses
    ]

    return DashboardStatsResponse(
        summary=summary,
        verdict_distribution=verdicts,
        top_brands=[],  # Would query from DB
        feed_status=feeds,
    )
