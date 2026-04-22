"""Data models for URL analysis."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from src.analyzer.threat_checker import ThreatCheckResult


@dataclass
class URLFeatures:
    """Extracted features from a URL."""

    domain_age_days: int = 0
    ssl_valid: bool = False
    ssl_issuer: str | None = None
    redirect_count: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    typosquat_target: str | None = None
    typosquat_distance: int = 0
    has_ip_address: bool = False
    url_length: int = 0
    path_depth: int = 0
    subdomain_count: int = 0
    has_https: bool = False
    has_suspicious_keywords: bool = False
    suspicious_tld: bool = False

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
    threat_feed_result: "ThreatCheckResult | None" = None
    prediction_source: str = "ml_model"  # "threat_feed" or "ml_model"

    def to_dict(self) -> dict:
        result = {
            "url": self.url,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "features": self.features.to_dict(),
            "feature_importance": self.feature_importance,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "matched_rules": self.matched_rules,
            "prediction_source": self.prediction_source,
        }

        if self.threat_feed_result:
            result["threat_feed_info"] = {
                "found_in_feeds": self.threat_feed_result.is_known_threat,
                "sources": self.threat_feed_result.sources,
                "details": {
                    k: v for k, v in self.threat_feed_result.details.items()
                    if v.get("found")
                },
            }

        return result
