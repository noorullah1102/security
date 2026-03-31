# SPEC-003: AI Threat Explainer

## Metadata
| Field | Value |
|-------|-------|
| Module | AI Threat Explainer |
| Version | 1.0.0 |
| Status | Draft |
| Priority | P1 (Core) |

## Overview
Integrates Claude API to generate human-readable explanations of phishing threats, including severity ratings and recommended actions.

## Functional Requirements

### FR-001: Claude API Integration
- Use Anthropic SDK for Claude API calls
- Support claude-sonnet-4-6 as primary model
- Implement proper error handling for API failures
- Track token usage per request

### FR-002: Prompt Engineering
Design prompts that produce consistent, structured output:

```
System: You are a cybersecurity threat analyst. Analyze the following
URL analysis result and provide a clear, actionable explanation.

Input: {analysis_result_json}

Output Format (JSON):
{
  "summary": "One sentence threat summary",
  "explanation": "Detailed explanation of why this is dangerous",
  "risk_factors": ["factor1", "factor2", ...],
  "severity": "low|medium|high|critical",
  "recommended_action": "Specific action to take",
  "target_brand": "Brand being impersonated or null"
}
```

### FR-003: Structured Output Parsing
- Parse Claude response as JSON
- Validate all required fields present
- Handle malformed responses gracefully
- Provide fallback explanation if parsing fails

### FR-004: Severity Classification
Map threat indicators to severity levels:

| Severity | Criteria |
|----------|----------|
| Critical | Confirmed phishing, credentials targeted, active campaign |
| High | Strong phishing signals, typosquatting, recent domain |
| Medium | Suspicious features, needs manual review |
| Low | Minor concerns, likely safe but flagged |

### FR-005: Recommended Actions
Generate context-aware action recommendations:
- Block URL at firewall/proxy
- Report to IT security team
- Submit to PhishTank
- Warn user who submitted
- No action needed (for safe verdicts)

### FR-006: Response Caching
- Cache explanations for identical feature sets
- Use feature hash as cache key
- Cache TTL: 24 hours
- Reduce API costs and latency

### FR-007: Scan History Storage
- Store all scan results in SQLite
- Track: URL, timestamp, verdict, explanation, user (if authenticated)
- Support historical queries and analytics

## Non-Functional Requirements

### NFR-001: Response Time
- AI explanation must return within 10 seconds
- Use streaming for long explanations (optional)

### NFR-002: Cost Management
- Track daily/monthly API spend
- Implement budget alerts at 80% threshold
- Consider batch processing for bulk analyses

### NFR-003: Availability
- Graceful degradation if Claude API unavailable
- Return rule-based explanation as fallback

## Data Models

```python
@dataclass
class ThreatExplanation:
    summary: str
    explanation: str
    risk_factors: list[str]
    severity: Literal["low", "medium", "high", "critical"]
    recommended_action: str
    target_brand: str | None

@dataclass
class ExplainerResult:
    url: str
    verdict: str
    confidence: float
    features: dict
    ai_explanation: ThreatExplanation
    analysis_timestamp: datetime
    cached: bool

@dataclass
class ScanRecord:
    id: str
    url: str
    verdict: str
    confidence: float
    features: dict
    ai_explanation: dict
    created_at: datetime
    user_id: str | None
```

## API Contract

```python
class AIThreatExplainer:
    def __init__(self, api_key: str, cache_ttl: int = 86400):
        """Initialize with Claude API key."""

    async def explain(self, analysis_result: AnalysisResult) -> ExplainerResult:
        """Generate AI explanation for analysis result."""

    async def explain_batch(self, results: list[AnalysisResult]) -> list[ExplainerResult]:
        """Generate explanations for multiple results."""

    def get_usage_stats(self) -> dict:
        """Return API usage statistics."""

class ScanHistory:
    async def save(self, record: ScanRecord) -> str:
        """Save scan record, return ID."""

    async def get_by_url(self, url: str) -> ScanRecord | None:
        """Get most recent scan for URL."""

    async def get_recent(self, limit: int = 100) -> list[ScanRecord]:
        """Get recent scans."""

    async def get_stats(self) -> dict:
        """Get scan statistics."""
```

## Dependencies
- `anthropic` - Claude API SDK
- `sqlite3` (stdlib) - Scan history storage
- `hashlib` (stdlib) - Feature hashing for cache

## Prompt Templates

### Threat Analysis Prompt
```python
THREAT_ANALYSIS_PROMPT = """
You are a cybersecurity threat analyst specializing in phishing detection.

Analyze the following URL analysis result and provide a clear, actionable
explanation suitable for non-technical users.

Analysis Result:
{analysis_json}

Respond with valid JSON in this exact format:
{{
  "summary": "One sentence summary of the threat",
  "explanation": "2-3 sentences explaining why this URL is dangerous",
  "risk_factors": ["list", "of", "specific", "risk", "factors"],
  "severity": "low|medium|high|critical",
  "recommended_action": "Specific action to take",
  "target_brand": "Brand being impersonated or null if none"
}}
"""
```

### Safe URL Prompt
```python
SAFE_URL_PROMPT = """
You are a cybersecurity analyst. The following URL has been analyzed and
appears to be safe. Provide a brief confirmation.

Analysis Result:
{analysis_json}

Respond with valid JSON:
{{
  "summary": "URL appears safe",
  "explanation": "Brief explanation of why this URL is likely legitimate",
  "risk_factors": [],
  "severity": "low",
  "recommended_action": "No action required",
  "target_brand": null
}}
"""
```

## Acceptance Criteria

| ID | Criteria |
|----|----------|
| AC-001 | Claude API integration works with valid API key |
| AC-002 | Prompts produce valid JSON output |
| AC-003 | All required fields present in response |
| AC-004 | Severity is one of: low, medium, high, critical |
| AC-005 | Explanation is clear and actionable |
| AC-006 | Identical requests are cached |
| AC-007 | Scan history is persisted to SQLite |
| AC-008 | API failures return graceful fallback |
| AC-009 | Token usage is tracked |

## Test Cases

1. **Unit Tests**
   - Prompt template formatting
   - JSON response parsing
   - Cache key generation
   - Severity mapping

2. **Integration Tests**
   - Live Claude API call (mocked in CI)
   - Cache hit/miss behavior
   - SQLite storage operations

3. **Error Handling Tests**
   - Invalid API key
   - Rate limit exceeded
   - Malformed API response
   - SQLite connection failure
