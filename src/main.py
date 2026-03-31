"""PhishRadar FastAPI Application."""

import structlog
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from src import __version__
from src.api.routes.health import router as health_router
from src.api.routes.analyze import router as analyze_router
from src.api.routes.feeds import router as feeds_router
from src.api.routes.scans import router as scans_router
from src.api.routes.stats import router as stats_router
from src.api.schemas.common import ErrorResponse
from src.config import get_settings

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager.

    Handles startup and shutdown events.
    """
    # Startup
    settings = get_settings()
    logger.info(
        "Starting PhishRadar",
        version=__version__,
        environment=settings.environment,
        log_level=settings.log_level,
    )

    # TODO: Start feed scheduler
    # from src.feeds.scheduler import FeedScheduler
    # scheduler = FeedScheduler()
    # await scheduler.start()

    yield

    # Shutdown
    logger.info("Shutting down PhishRadar")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    settings = get_settings()

    app = FastAPI(
        title="PhishRadar",
        description="""
        AI-Powered Phishing Threat Monitor

        PhishRadar detects phishing URLs using machine learning and provides
        human-readable threat explanations via Claude AI.

        ## Features
        - URL analysis with ML-based phishing detection
        - AI-powered threat explanations
        - Threat feed aggregation from multiple sources
        - Trend analysis and dashboard

        ## Authentication
        All endpoints require an API key in the `X-API-Key` header.
        """,
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.is_development else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routers
    app.include_router(health_router)
    app.include_router(analyze_router)
    app.include_router(feeds_router)
    app.include_router(scans_router)
    app.include_router(stats_router)

    # Serve static files for frontend
    frontend_dir = Path(__file__).parent.parent / "frontend"
    if frontend_dir.exists():
        app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    # Dashboard route
    @app.get("/", include_in_schema=False)
    async def dashboard():
        """Serve the dashboard HTML."""
        index_path = frontend_dir / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return {"message": "PhishRadar API is running. Frontend not built."}

    # Exception handlers
    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unhandled exceptions."""
        logger.exception(
            "Unhandled exception",
            path=request.url.path,
            method=request.method,
            error=str(exc),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="Internal Server Error",
                detail=str(exc) if settings.is_development else "An unexpected error occurred",
                code="INTERNAL_ERROR",
            ).model_dump(),
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        """Handle validation errors."""
        logger.warning(
            "Validation error",
            path=request.url.path,
            method=request.method,
            error=str(exc),
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error="Validation Error",
                detail=str(exc),
                code="VALIDATION_ERROR",
            ).model_dump(),
        )

    return app


# Create application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.is_development,
        log_level=settings.log_level.lower(),
    )
