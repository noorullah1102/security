# PhishRadar Data Models

## Database Schema (SQLite)

### Table: scan_history

Stores all URL scan results.

```sql
CREATE TABLE scan_history (
    id TEXT PRIMARY KEY,                    -- UUID
    url TEXT NOT NULL,                      -- Analyzed URL
    verdict TEXT NOT NULL,                  -- 'safe', 'phishing', 'suspicious'
    confidence REAL NOT NULL,               -- 0.0 to 1.0
    severity TEXT,                          -- 'low', 'medium', 'high', 'critical'
    features JSON NOT NULL,                 -- Extracted features (JSON)
    ai_explanation JSON,                    -- AI explanation (JSON, nullable)
    target_brand TEXT,                      -- Impersonated brand if detected
    created_at TIMESTAMP NOT NULL,          -- ISO 8601 timestamp
    user_id TEXT,                           -- User ID if authenticated
    ip_address TEXT                         -- Client IP for rate limiting
);

CREATE INDEX idx_scan_history_url ON scan_history(url);
CREATE INDEX idx_scan_history_verdict ON scan_history(verdict);
CREATE INDEX idx_scan_history_created_at ON scan_history(created_at);
CREATE INDEX idx_scan_history_severity ON scan_history(severity);
```

### Table: threat_indicators

Cache of indicators from external threat feeds.

```sql
CREATE TABLE threat_indicators (
    id TEXT PRIMARY KEY,                    -- UUID
    url TEXT NOT NULL,                      -- Malicious URL
    threat_type TEXT NOT NULL,              -- 'phishing', 'malware', etc.
    source TEXT NOT NULL,                   -- 'phishtank', 'urlhaus', 'reddit'
    source_id TEXT,                         -- Original ID from source
    first_seen TIMESTAMP NOT NULL,          -- When first observed
    last_seen TIMESTAMP NOT NULL,           -- Most recent observation
    target_brand TEXT,                      -- Impersonated brand
    confidence REAL NOT NULL DEFAULT 1.0,   -- Confidence level
    metadata JSON,                          -- Source-specific metadata
    tags JSON,                              -- Array of tags
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX idx_threat_indicators_url_source ON threat_indicators(url, source);
CREATE INDEX idx_threat_indicators_source ON threat_indicators(source);
CREATE INDEX idx_threat_indicators_first_seen ON threat_indicators(first_seen);
CREATE INDEX idx_threat_indicators_threat_type ON threat_indicators(threat_type);
```

### Table: feed_status

Tracks health of threat feed sources.

```sql
CREATE TABLE feed_status (
    source TEXT PRIMARY KEY,                -- 'phishtank', 'urlhaus', 'reddit'
    status TEXT NOT NULL,                   -- 'healthy', 'degraded', 'error'
    last_update TIMESTAMP,                  -- Last successful update
    last_attempt TIMESTAMP,                 -- Last update attempt
    indicator_count INTEGER DEFAULT 0,      -- Number of indicators
    error_count INTEGER DEFAULT 0,          -- Consecutive errors
    last_error TEXT,                        -- Last error message
    updated_at TIMESTAMP NOT NULL
);
```

### Table: api_keys

API key management.

```sql
CREATE TABLE api_keys (
    key TEXT PRIMARY KEY,                   -- API key (hashed)
    name TEXT NOT NULL,                     -- Friendly name
    user_id TEXT,                           -- Associated user
    is_active BOOLEAN DEFAULT TRUE,
    rate_limit INTEGER DEFAULT 100,         -- Requests per minute
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,                   -- Optional expiration
    last_used_at TIMESTAMP
);
```

### Table: explanation_cache

Caches AI explanations to reduce API costs.

```sql
CREATE TABLE explanation_cache (
    feature_hash TEXT PRIMARY KEY,          -- Hash of features
    explanation JSON NOT NULL,              -- Cached explanation
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_explanation_cache_expires ON explanation_cache(expires_at);
```

---

## Python Data Models

### URL Features

```python
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

@dataclass
class URLFeatures:
    """Extracted features from a URL."""
    domain_age_days: int
    ssl_valid: bool
    ssl_issuer: str | None
    redirect_count: int
    redirect_chain: list[str]
    typosquat_target: str | None
    typosquat_distance: int
    has_ip_address: bool
    url_length: int
    path_depth: int
    has_suspicious_keywords: bool
    subdomain_count: int
    has_https: bool
    suspicious_tld: bool

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
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
            "has_suspicious_keywords": self.has_suspicious_keywords,
            "subdomain_count": self.subdomain_count,
            "has_https": self.has_https,
            "suspicious_tld": self.suspicious_tld
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
            float(self.suspicious_tld)
        ]
```

### Analysis Result

```python
@dataclass
class AnalysisResult:
    """Result of URL analysis."""
    url: str
    verdict: Literal["safe", "phishing", "suspicious"]
    confidence: float
    features: URLFeatures
    feature_importance: dict[str, float]
    analysis_timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "features": self.features.to_dict(),
            "feature_importance": self.feature_importance,
            "analysis_timestamp": self.analysis_timestamp.isoformat()
        }
```

### Threat Indicator

```python
@dataclass
class ThreatIndicator:
    """Normalized threat indicator from external feeds."""
    id: str
    url: str
    threat_type: Literal["phishing", "malware", "spam", "other"]
    source: Literal["phishtank", "urlhaus", "abuse_ch", "reddit"]
    source_id: str | None
    first_seen: datetime
    last_seen: datetime
    target_brand: str | None
    confidence: float
    metadata: dict
    tags: list[str]

    @classmethod
    def from_phishtank(cls, data: dict) -> "ThreatIndicator":
        """Create from PhishTank API response."""
        ...

    @classmethod
    def from_urlhaus(cls, data: dict) -> "ThreatIndicator":
        """Create from URLhaus API response."""
        ...
```

### AI Explanation

```python
@dataclass
class ThreatExplanation:
    """AI-generated threat explanation."""
    summary: str
    explanation: str
    risk_factors: list[str]
    severity: Literal["low", "medium", "high", "critical"]
    recommended_action: str
    target_brand: str | None

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "explanation": self.explanation,
            "risk_factors": self.risk_factors,
            "severity": self.severity,
            "recommended_action": self.recommended_action,
            "target_brand": self.target_brand
        }
```

### Explainer Result

```python
@dataclass
class ExplainerResult:
    """Complete result including AI explanation."""
    url: str
    verdict: str
    confidence: float
    features: dict
    ai_explanation: ThreatExplanation
    analysis_timestamp: datetime
    cached: bool

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "features": self.features,
            "ai_explanation": self.ai_explanation.to_dict(),
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "cached": self.cached
        }
```

### Scan Record

```python
@dataclass
class ScanRecord:
    """Database record for scan history."""
    id: str
    url: str
    verdict: str
    confidence: float
    severity: str | None
    features: dict
    ai_explanation: dict | None
    target_brand: str | None
    created_at: datetime
    user_id: str | None
    ip_address: str | None

    @classmethod
    def from_row(cls, row: tuple) -> "ScanRecord":
        """Create from database row."""
        ...

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "features": self.features,
            "ai_explanation": self.ai_explanation,
            "target_brand": self.target_brand,
            "created_at": self.created_at.isoformat()
        }
```

---

## Pydantic Models (API Schemas)

```python
from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Literal

class AnalyzeRequest(BaseModel):
    """Request schema for URL analysis."""
    url: str = Field(..., description="URL to analyze")
    include_ai_explanation: bool = Field(True, description="Include AI explanation")

    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        if len(v) > 2048:
            raise ValueError('URL must be less than 2048 characters')
        return v

class BatchAnalyzeRequest(BaseModel):
    """Request schema for batch analysis."""
    urls: list[str] = Field(..., max_items=100, description="URLs to analyze")
    include_ai_explanation: bool = Field(False, description="Include AI explanations")

    @validator('urls')
    def validate_urls(cls, v):
        for url in v:
            if not url.startswith(('http://', 'https://')):
                raise ValueError(f'Invalid URL: {url}')
        return v

class ErrorResponse(BaseModel):
    """Error response schema."""
    error: str
    detail: str | None = None
    code: str
    timestamp: datetime

class ScanSummary(BaseModel):
    """Summary schema for scan listings."""
    id: str
    url: str
    verdict: Literal["safe", "phishing", "suspicious"]
    confidence: float
    severity: str | None
    created_at: datetime

class StatsSummary(BaseModel):
    """Statistics summary schema."""
    total_scans: int
    phishing_detected: int
    safe_urls: int
    suspicious: int
    avg_confidence: float
    verdict_distribution: dict[str, float]
    severity_distribution: dict[str, float]
    period: dict[str, str]
```

---

## Relationships

```
┌─────────────────┐
│   api_keys      │
│  (auth)         │
└────────┬────────┘
         │
         │ 1:N (via user_id)
         ▼
┌─────────────────┐      ┌─────────────────────┐
│  scan_history   │──────│ explanation_cache   │
│  (scans)        │      │ (feature_hash)      │
└─────────────────┘      └─────────────────────┘

┌─────────────────┐
│threat_indicators│
│  (feeds)        │
└────────┬────────┘
         │
         │ references
         ▼
┌─────────────────┐
│  feed_status    │
│  (health)       │
└─────────────────┘
```
