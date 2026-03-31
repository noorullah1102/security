# SPEC-002: URL Analyzer

## Metadata
| Field | Value |
|-------|-------|
| Module | URL Analyzer |
| Version | 1.0.0 |
| Status | Draft |
| Priority | P1 (Core) |

## Overview
Extracts features from URLs, runs them through a trained ML classifier, and produces a phishing verdict with confidence score.

## Functional Requirements

### FR-001: Feature Extraction
Extract the following features from input URLs:

| Feature | Type | Description |
|---------|------|-------------|
| `domain_age_days` | int | Days since domain registration (whois) |
| `ssl_valid` | bool | Has valid SSL certificate |
| `ssl_issuer` | str | SSL certificate issuer |
| `redirect_count` | int | Number of HTTP redirects |
| `redirect_chain` | list[str] | URLs in redirect chain |
| `typosquat_target` | str \| None | Legitimate domain if typosquatting detected |
| `typosquat_distance` | int | Levenshtein distance to target |
| `has_ip_address` | bool | URL contains IP instead of domain |
| `url_length` | int | Total URL length |
| `path_depth` | int | Number of path segments |
| `has_suspicious_keywords` | bool | Contains phishing keywords (login, verify, secure, etc.) |
| `subdomain_count` | int | Number of subdomains |
| `has_https` | bool | Uses HTTPS protocol |
| `suspicious_tld` | bool | TLD commonly used for phishing (.tk, .ml, etc.) |

### FR-002: Typosquatting Detection
- Compare domain against list of popular brands (top 1000 domains)
- Use Levenshtein distance for similarity matching
- Flag domains with distance ≤ 2 as potential typosquats
- Support homoglyph detection (e.g., а vs a)

### FR-003: SSL Certificate Analysis
- Check certificate validity and chain
- Extract issuer information
- Flag self-signed or recently issued certificates
- Check certificate transparency logs (optional enhancement)

### FR-004: Domain Age Lookup
- Query WHOIS for domain registration date
- Cache results to minimize WHOIS queries
- Flag domains registered < 30 days as suspicious

### FR-005: ML Classification
- Load pre-trained scikit-learn model
- Transform extracted features to model input format
- Return prediction with confidence probability
- Support model versioning and hot-reload

### FR-006: Rule-Based Heuristics
- Apply rule-based checks as additional signals
- Rules can override ML prediction in clear-cut cases
- Rules must be configurable without code changes

## Non-Functional Requirements

### NFR-001: Performance
- Feature extraction must complete within 5 seconds
- Classification must complete within 100ms
- Support batch analysis of up to 100 URLs

### NFR-002: Accuracy
- Model must achieve ≥ 90% precision
- Model must achieve ≥ 85% recall
- F1 score must be ≥ 0.87

### NFR-003: Explainability
- Feature importance must be available for each prediction
- SHAP values or feature contribution scores

## Data Models

```python
@dataclass
class URLFeatures:
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

@dataclass
class AnalysisResult:
    url: str
    verdict: Literal["safe", "phishing", "suspicious"]
    confidence: float  # 0.0 - 1.0
    features: URLFeatures
    feature_importance: dict[str, float]
    analysis_timestamp: datetime
```

## API Contract

```python
class URLAnalyzer:
    def __init__(self, model_path: str):
        """Load trained model from path."""

    async def analyze(self, url: str) -> AnalysisResult:
        """Analyze single URL."""

    async def analyze_batch(self, urls: list[str]) -> list[AnalysisResult]:
        """Analyze multiple URLs."""

    def extract_features(self, url: str) -> URLFeatures:
        """Extract features from URL (synchronous)."""

    def get_model_info(self) -> dict:
        """Return model metadata and version."""
```

## Dependencies
- `scikit-learn` - ML model
- `python-whois` - Domain age lookup
- `ssl` (stdlib) - SSL certificate analysis
- `tldextract` - Domain parsing
- `levenshtein` - String distance calculation

## Acceptance Criteria

| ID | Criteria |
|----|----------|
| AC-001 | Can extract all 14 features from any URL |
| AC-002 | Typosquatting detects apple.com variants (app1e, appl3, etc.) |
| AC-003 | SSL validation works for valid and invalid certificates |
| AC-004 | Domain age lookup returns correct days since registration |
| AC-005 | Model loads and produces predictions |
| AC-006 | Predictions include confidence scores |
| AC-007 | Feature importance is calculated and returned |
| AC-008 | Batch analysis processes multiple URLs |
| AC-009 | WHOIS results are cached |

## Training Pipeline

### Dataset Sources
- **Phishing URLs:** PhishTank, URLhaus, OpenPhish
- **Legitimate URLs:** Alexa Top 1M, Cisco Umbrella 1M
- **Target split:** 50% phishing, 50% legitimate

### Feature Engineering
1. Parse URL with `tldextract`
2. Query WHOIS for domain age
3. Check SSL certificate
4. Follow redirects
5. Calculate typosquatting distance
6. Extract lexical features

### Model Selection
- Primary: Random Forest Classifier
- Alternative: Gradient Boosting (XGBoost)
- Compare F1 scores, choose best performer

### Evaluation Metrics
```
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 = 2 * (Precision * Recall) / (Precision + Recall)
```

## Test Cases

1. **Feature Extraction Tests**
   - Known phishing URL returns expected features
   - Known legitimate URL returns expected features
   - Edge cases: IP URLs, very long URLs, Unicode domains

2. **Classification Tests**
   - Model correctly classifies test set
   - Confidence scores are calibrated
   - Feature importance is non-negative

3. **Integration Tests**
   - End-to-end analysis of real URLs
   - Batch analysis performance
