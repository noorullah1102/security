"""API Key authentication middleware."""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from src.config import get_settings

# API Key header scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    request: Request,
    api_key: str | None = Depends(api_key_header),
) -> str:
    """Verify API key from request header.

    Args:
        request: The incoming request
        api_key: API key from X-API-Key header

    Returns:
        The verified API key

    Raises:
        HTTPException: If API key is missing or invalid
    """
    settings = get_settings()

    # Skip auth for health endpoint
    if request.url.path == "/health":
        return api_key or ""

    # Skip auth in development mode for docs
    if settings.is_development and request.url.path in ["/docs", "/openapi.json", "/redoc"]:
        return api_key or ""

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Include X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


def get_optional_api_key(
    api_key: str | None = Depends(api_key_header),
) -> str | None:
    """Get API key without requiring it.

    Useful for endpoints that work with or without authentication.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        The API key if provided, None otherwise
    """
    return api_key
