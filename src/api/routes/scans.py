"""Scan history API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from datetime import datetime

from src.api.middleware.auth import verify_api_key
from src.db.database import DatabaseManager
from src.db.repository import ScanRepository

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class ScanResponse(BaseModel):
    """Single scan response."""

    id: str
    url: str
    verdict: str
    confidence: float
    severity: str | None = None
    features: dict = Field(default_factory=dict)
    ai_explanation: dict | None = None
    target_brand: str | None = None
    created_at: datetime


class ScanListResponse(BaseModel):
    """List of scans response."""

    scans: list[ScanResponse]
    total: int
    limit: int
    offset: int


def get_scan_repository() -> ScanRepository:
    """Get scan repository instance."""
    db = DatabaseManager.get_database()
    return ScanRepository(db)


@router.get(
    "/recent",
    response_model=ScanListResponse,
    summary="Get recent scans",
)
async def get_recent_scans(
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    verdict: str | None = Query(default=None, description="Filter by verdict"),
    severity: str | None = Query(default=None, description="Filter by severity"),
) -> ScanListResponse:
    """Get recent scan history.

    Supports filtering by verdict and severity.
    """
    scans = repo.get_recent(
        limit=limit,
        offset=offset,
        verdict=verdict,
        severity=severity,
    )

    return ScanListResponse(
        scans=[
            ScanResponse(
                id=scan.id,
                url=scan.url,
                verdict=scan.verdict,
                confidence=scan.confidence,
                severity=scan.severity,
                features=scan.features or {},
                ai_explanation=scan.ai_explanation,
                target_brand=scan.target_brand,
                created_at=scan.created_at,
            )
            for scan in scans
        ],
        total=len(scans),  # Would need separate count query
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan by ID",
)
async def get_scan_by_id(
    scan_id: str,
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
) -> ScanResponse:
    """Get a specific scan by its ID."""
    scan = repo.get_by_id(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        id=scan.id,
        url=scan.url,
        verdict=scan.verdict,
        confidence=scan.confidence,
        severity=scan.severity,
        features=scan.features or {},
        ai_explanation=scan.ai_explanation,
        target_brand=scan.target_brand,
        created_at=scan.created_at,
    )


@router.get(
    "/search",
    response_model=ScanListResponse,
    summary="Search scans by URL",
)
async def search_scans(
    api_key: Annotated[str, Depends(verify_api_key)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
    q: str = Query(description="Search query"),
    limit: int = Query(default=20, ge=1, le=100),
) -> ScanListResponse:
    """Search scan history by URL substring."""
    scans = repo.search(query=q, limit=limit)

    return ScanListResponse(
        scans=[
            ScanResponse(
                id=scan.id,
                url=scan.url,
                verdict=scan.verdict,
                confidence=scan.confidence,
                severity=scan.severity,
                features=scan.features or {},
                ai_explanation=scan.ai_explanation,
                target_brand=scan.target_brand,
                created_at=scan.created_at,
            )
            for scan in scans
        ],
        total=len(scans),
        limit=limit,
        offset=0,
    )
