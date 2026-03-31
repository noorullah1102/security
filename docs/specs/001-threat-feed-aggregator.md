# SPEC-001: Threat Feed Aggregator

## Metadata
| Field | Value |
|-------|-------|
| Module | Threat Feed Aggregator |
| Version | 1.0.0 |
| Status | Draft |
| Priority | P1 (Core) |

## Overview
Aggregates live phishing threat data from multiple external sources, normalizes it, and provides a unified interface for consumption by other modules.

## Functional Requirements

### FR-001: PhishTank Integration
- Pull phishing URL data from PhishTank API
- Support both fresh feeds and historical lookups
- Respect API rate limits (unauthenticated: 1 req/min, authenticated: higher)
- Parse and store: URL, submission date, verification status, target brand

### FR-002: URLhaus Integration
- Fetch malicious URLs from URLhaus API
- Support tag-based filtering (malware, phishing, etc.)
- Parse and store: URL, threat type, first seen, last seen, payload info

### FR-003: abuse.ch Integration
- Integrate with abuse.ch threat intelligence feeds
- Support URLhaus, MalwareBazaar, and ThreatFox as available
- Handle feed format variations

### FR-004: Reddit Monitoring (PRAW)
- Monitor r/cybersecurity for trending threat discussions
- Extract URLs and threat keywords from posts/comments
- Track post engagement (upvotes, comments) for trend scoring
- Rate limit to respect Reddit API constraints

### FR-005: Scheduled Updates
- Configurable update intervals per source (default: 1 hour)
- Support manual trigger via API
- Handle failures gracefully with retry logic (exponential backoff)
- Log all sync operations

### FR-006: Data Normalization
- Convert all feed data to unified `ThreatIndicator` schema
- Deduplicate entries across sources
- Track source provenance for each indicator

## Non-Functional Requirements

### NFR-001: Performance
- Feed fetch operations must complete within 60 seconds
- Support parallel fetching from multiple sources

### NFR-002: Reliability
- Individual source failures must not crash the system
- Implement circuit breaker pattern for failing sources

### NFR-003: Rate Limiting
- Respect all external API rate limits
- Implement local rate limiting as safety measure

## Data Models

```python
@dataclass
class ThreatIndicator:
    id: str                    # UUID
    url: str                   # The malicious URL
    threat_type: str           # phishing, malware, etc.
    source: str                # phishtank, urlhaus, reddit
    first_seen: datetime
    last_seen: datetime
    target_brand: str | None   # Impersonated brand if detected
    confidence: float          # 0.0 - 1.0
    metadata: dict             # Source-specific data
    tags: list[str]            # Categorization tags
```

## API Contract

### Internal Module Interface

```python
class ThreatFeedAggregator:
    async def fetch_all_sources() -> list[ThreatIndicator]
    async def fetch_source(source: str) -> list[ThreatIndicator]
    async def get_cached_indicators(since: datetime) -> list[ThreatIndicator]
    def get_source_status() -> dict[str, SourceStatus]
```

## Dependencies
- `aiohttp` - Async HTTP client
- `praw` - Reddit API wrapper
- `asyncio` - Async scheduling

## Acceptance Criteria

| ID | Criteria |
|----|----------|
| AC-001 | Can fetch and parse PhishTank feed successfully |
| AC-002 | Can fetch and parse URLhaus feed successfully |
| AC-003 | Can monitor r/cybersecurity and extract URLs |
| AC-004 | All feeds normalized to ThreatIndicator schema |
| AC-005 | Duplicate URLs across sources are merged |
| AC-006 | Failed source fetches are logged and retried |
| AC-007 | Rate limits are never exceeded |
| AC-008 | Scheduled updates run at configured intervals |

## Test Cases

1. **Unit Tests**
   - Parse PhishTank JSON response correctly
   - Parse URLhaus JSON response correctly
   - Normalize various threat types to unified schema
   - Deduplication logic works correctly

2. **Integration Tests**
   - Live fetch from PhishTank (mocked in CI)
   - Live fetch from URLhaus (mocked in CI)
   - Reddit API integration (mocked)

3. **Error Handling Tests**
   - API timeout handling
   - Rate limit response handling
   - Invalid JSON handling
   - Network failure recovery
