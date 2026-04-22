"""Application configuration using pydantic-settings."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # API Authentication
    api_key: str = "dev-api-key"

    # Claude API
    anthropic_api_key: str | None = None

    # Reddit API
    reddit_client_id: str | None = None
    reddit_client_secret: str | None = None
    reddit_user_agent: str = "PhishRadar/1.0"

    # Database
    database_url: str = "sqlite:///./phishradar.db"

    # Application
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    environment: Literal["development", "staging", "production"] = "development"

    # Threat Feed APIs
    urlhaus_auth_key: str | None = None
    virustotal_api_key: str | None = None
    google_safebrowsing_api_key: str | None = None
    urlscan_api_key: str | None = None

    # Feed Settings
    feed_update_interval: int = 3600  # seconds

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
