"""Data models for URL analysis."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass
class URLFeatures:
    """Extracted features from a URL."""

    domain_age_days: int
    ssl_valid: bool
    ssl_issuer: str | None
    redirect_count: int
    typosquat_target: str | None
    has_ip_address: bool
    url_length: int
    path_depth: int
    subdomain_count: int
    has_https: bool
    has_suspicious_keywords: bool
    suspicious_tld: bool
    redirect_chain: list[str] = field(default_factory=list)
    typosquat_distance: int = 0

    def to_dict(self) -> dict:
        return {
            "domain_age_days": self.domain_age_days,
            "ssl_valid": self.ssl_valid,
            "ssl_issuer": self.ssl_issuer,
            "redirect_count": self.redirect_count,
            "redirect_chain": self.redirect_chain,
            "typosquat_target": self.typosquat_target,
            "typosquat_distance": self.typosquat_distance,
            "has_ip_address": self.has_ip_address,
            "url_length": self.url_length,
            "path_depth": self.path_depth,
            "subdomain_count": self.subdomain_count,
            "has_https": self.has_https,
            "has_suspicious_keywords": self.has_suspicious_keywords,
            "suspicious_tld": self.suspicious_tld,
        }

    def to_feature_vector(self) -> list[float]:
        """Convert to ML model input vector."""
        return [
            float(self.domain_age_days),
            float(self.ssl_valid),
            float(self.redirect_count),
            float(self.typosquat_distance),
            float(self.has_ip_address),
            float(self.url_length),
            float(self.path_depth),
            float(self.has_suspicious_keywords),
            float(self.subdomain_count),
            float(self.has_https),
            float(self.suspicious_tld),
        ]


@dataclass
class AnalysisResult:
    """Result of URL analysis."""

    url: str
    verdict: Literal["safe", "phishing", "suspicious"]
    confidence: float
    features: URLFeatures
    feature_importance: dict[str, float] = field(default_factory=dict)
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    matched_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "features": self.features.to_dict(),
            "feature_importance": self.feature_importance,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "matched_rules": self.matched_rules,
        }
