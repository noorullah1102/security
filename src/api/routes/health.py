"""Health check endpoint."""

import time
from typing import Literal

from fastapi import APIRouter, status

from src.api.schemas.common import HealthResponse
from src.config import get_settings

router = APIRouter(tags=["System"])

# Track application start time
START_TIME = time.time()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health Check",
    description="Check the health status of the API and its dependencies",
)
async def health_check() -> HealthResponse:
    """Check system health status.

    Returns the health status of the API and its components.
    """
    settings = get_settings()
    uptime = time.time() - START_TIME

    # Check component health
    components = {
        "api": "ok",
        "database": "ok",  # Will be properly checked once DB is set up
        "claude_api": "not_configured" if not settings.anthropic_api_key else "ok",
    }

    # Determine overall status
    if all(v == "ok" for v in components.values()):
        overall_status: Literal["healthy", "unhealthy", "degraded"] = "healthy"
    elif any(v == "error" for v in components.values()):
        overall_status = "unhealthy"
    else:
        overall_status = "degraded"

    return HealthResponse(
        status=overall_status,
        components=components,
        version="1.0.0",
        uptime_seconds=uptime,
    )
