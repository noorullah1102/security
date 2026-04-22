"""API schemas for URL analysis endpoints."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    """Request schema for single URL analysis."""

    url: str = Field(..., description="URL to analyze", min_length=1, max_length=2048)
    include_ai_explanation: bool = Field(
        True, description="Include AI-generated threat explanation"
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format."""
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class BatchAnalyzeRequest(BaseModel):
    """Request schema for batch URL analysis."""

    urls: list[str] = Field(
        ..., description="URLs to analyze", min_length=1, max_length=100
    )
    include_ai_explanation: bool = Field(
        False, description="Include AI explanations (disabled by default for batch)"
    )

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: list[str]) -> list[str]:
        """Validate all URLs in the batch."""
        for i, url in enumerate(v):
            url = url.strip()
            if not url.startswith(("http://", "https://")):
                raise ValueError(f"URL at index {i} must start with http:// or https://")
            v[i] = url
        return v


class URLFeaturesResponse(BaseModel):
    """URL features in response."""

    domain_age_days: int = Field(..., description="Days since domain registration")
    ssl_valid: bool = Field(..., description="Whether SSL certificate is valid")
    ssl_issuer: str | None = Field(None, description="SSL certificate issuer")
    redirect_count: int = Field(..., description="Number of HTTP redirects")
    redirect_chain: list[str] = Field(
        default_factory=list, description="URLs in redirect chain"
    )
    typosquat_target: str | None = Field(
        None, description="Target domain if typosquatting detected"
    )
    typosquat_distance: int = Field(
        0, description="Edit distance to typosquat target"
    )
    has_ip_address: bool = Field(..., description="URL uses IP address instead of domain")
    url_length: int = Field(..., description="Total URL length in characters")
    path_depth: int = Field(..., description="Number of path segments")
    has_suspicious_keywords: bool = Field(
        ..., description="URL contains suspicious keywords"
    )
    subdomain_count: int = Field(..., description="Number of subdomain levels")
    has_https: bool = Field(..., description="URL uses HTTPS protocol")
    suspicious_tld: bool = Field(..., description="Domain uses suspicious TLD")


class AIExplanationResponse(BaseModel):
    """AI-generated threat explanation."""

    summary: str = Field(..., description="One-sentence threat summary")
    explanation: str = Field(..., description="Detailed explanation of the threat")
    risk_factors: list[str] = Field(
        default_factory=list, description="List of identified risk factors"
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        ..., description="Threat severity level"
    )
    recommended_action: str = Field(..., description="Recommended action to take")
    target_brand: str | None = Field(
        None, description="Brand being impersonated, if any"
    )


class ThreatFeedInfoResponse(BaseModel):
    """Information about threat feed matches."""

    found_in_feeds: bool = Field(..., description="Whether URL was found in threat feeds")
    sources: list[str] = Field(
        default_factory=list, description="Threat feed sources that matched"
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Details from each source"
    )


class AnalyzeResponse(BaseModel):
    """Response schema for URL analysis."""

    url: str = Field(..., description="Analyzed URL")
    verdict: Literal["safe", "phishing", "suspicious"] = Field(
        ..., description="Analysis verdict"
    )
    confidence: float = Field(
        ..., description="Confidence score (0.0-1.0)", ge=0.0, le=1.0
    )
    features: URLFeaturesResponse = Field(..., description="Extracted URL features")
    feature_importance: dict[str, float] = Field(
        default_factory=dict, description="Feature importance scores"
    )
    matched_rules: list[str] = Field(
        default_factory=list, description="Rules that matched for this URL"
    )
    ai_explanation: AIExplanationResponse | None = Field(
        None, description="AI-generated explanation (if requested)"
    )
    threat_feed_info: ThreatFeedInfoResponse | None = Field(
        None, description="Threat feed information (if checked)"
    )
    prediction_source: str = Field(
        "ml_model", description="Source of prediction: 'threat_feed' or 'ml_model'"
    )
    analysis_timestamp: datetime = Field(..., description="Timestamp of analysis")
    cached: bool = Field(False, description="Whether result was served from cache")


class BatchAnalyzeResponse(BaseModel):
    """Response schema for batch URL analysis."""

    results: list[AnalyzeResponse] = Field(..., description="Analysis results for each URL")
    processed: int = Field(..., description="Number of URLs processed")
    failed: int = Field(..., description="Number of URLs that failed analysis")
    processing_time_ms: float = Field(..., description="Total processing time in milliseconds")
