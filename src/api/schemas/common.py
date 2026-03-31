"""Common API schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: Literal["healthy", "unhealthy", "degraded"] = Field(
        ..., description="Overall system health status"
    )
    components: dict[str, str] = Field(
        default_factory=dict, description="Individual component statuses"
    )
    version: str = Field(..., description="Application version")
    uptime_seconds: float | None = Field(None, description="Application uptime in seconds")


class ErrorResponse(BaseModel):
    """Standard error response schema."""

    error: str = Field(..., description="Error type")
    detail: str | None = Field(None, description="Detailed error message")
    code: str = Field(..., description="Error code for programmatic handling")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")


class SuccessResponse(BaseModel):
    """Generic success response schema."""

    message: str = Field(..., description="Success message")
    data: dict[str, Any] | None = Field(None, description="Optional response data")
