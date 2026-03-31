# SPEC-005: REST API

## Metadata
| Field | Value |
|-------|-------|
| Module | REST API |
| Version | 1.0.0 |
| Status | Draft |
| Priority | P1 (Core) |

## Overview
FastAPI-based REST API providing URL analysis, threat intelligence, and dashboard data endpoints with automatic Swagger documentation.

## Functional Requirements

### FR-001: URL Analysis Endpoint
- Accept URL for analysis
- Return full analysis with AI explanation
- Support synchronous and async processing modes

### FR-002: Batch Analysis Endpoint
- Accept multiple URLs (max 100)
- Process in parallel
- Return results as array

### FR-003: Scan History Endpoints
- Get recent scans
- Get scan by ID
- Search scans by URL

### FR-004: Statistics Endpoints
- Summary statistics
- Time-series trend data
- Top targeted brands

### FR-005: Threat Feed Endpoints
- Get cached indicators
- Get feed source status
- Trigger manual feed refresh

### FR-006: Health Check
- `/health` endpoint for monitoring
- Return component status (API, DB, external services)

### FR-007: Authentication
- API key authentication (header: `X-API-Key`)
- Optional: JWT for user-level auth
- Rate limiting per API key

### FR-008: Error Handling
- Consistent error response format
- Proper HTTP status codes
- Detailed error messages in development

## API Endpoints

### Core Analysis

```
POST /api/v1/analyze
  Request:
    {
      "url": "https://example.com",
      "include_ai_explanation": true
    }
  Response:
    {
      "url": "https://example.com",
      "verdict": "phishing",
      "confidence": 0.94,
      "features": { ... },
      "ai_explanation": { ... },
      "analysis_timestamp": "2026-03-26T10:00:00Z"
    }
```

```
POST /api/v1/analyze/batch
  Request:
    {
      "urls": ["https://url1.com", "https://url2.com"],
      "include_ai_explanation": false
    }
  Response:
    {
      "results": [ ... ],
      "processed": 2,
      "failed": 0
    }
```

### Scan History

```
GET /api/v1/scans/recent?limit=20&offset=0
  Response:
    {
      "scans": [ ... ],
      "total": 1234,
      "limit": 20,
      "offset": 0
    }
```

```
GET /api/v1/scans/{scan_id}
  Response:
    {
      "id": "uuid",
      "url": "https://example.com",
      ...
    }
```

```
GET /api/v1/scans/search?q=suspicious-domain.com
  Response:
    {
      "scans": [ ... ],
      "query": "suspicious-domain.com"
    }
```

### Statistics

```
GET /api/v1/stats/summary
  Response:
    {
      "total_scans": 12345,
      "phishing_detected": 2345,
      "safe_urls": 9500,
      "suspicious": 500,
      "avg_confidence": 0.87,
      "period": {
        "start": "2026-03-19",
        "end": "2026-03-26"
      }
    }
```

```
GET /api/v1/stats/trends?period=7d
  Response:
    {
      "data": [
        {"date": "2026-03-19", "scans": 150, "phishing": 30},
        {"date": "2026-03-20", "scans": 165, "phishing": 35},
        ...
      ],
      "period": "7d"
    }
```

```
GET /api/v1/stats/brands?limit=10
  Response:
    {
      "brands": [
        {"name": "PayPal", "count": 150},
        {"name": "Microsoft", "count": 120},
        ...
      ]
    }
```

### Threat Feeds

```
GET /api/v1/feeds/indicators?since=2026-03-20
  Response:
    {
      "indicators": [ ... ],
      "count": 543,
      "sources": ["phishtank", "urlhaus", "reddit"]
    }
```

```
GET /api/v1/feeds/status
  Response:
    {
      "sources": [
        {
          "name": "phishtank",
          "status": "healthy",
          "last_update": "2026-03-26T09:00:00Z",
          "indicator_count": 1234
        },
        ...
      ]
    }
```

```
POST /api/v1/feeds/refresh
  Request:
    {
      "source": "phishtank"  // or null for all
    }
  Response:
    {
      "status": "refreshing",
      "sources": ["phishtank"]
    }
```

### System

```
GET /health
  Response:
    {
      "status": "healthy",
      "components": {
        "api": "ok",
        "database": "ok",
        "claude_api": "ok"
      },
      "version": "1.0.0"
    }
```

## Request/Response Schemas

### Error Response
```python
class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    code: str
    timestamp: datetime
```

### Analysis Request
```python
class AnalyzeRequest(BaseModel):
    url: str
    include_ai_explanation: bool = True

    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v
```

### Analysis Response
```python
class AnalyzeResponse(BaseModel):
    url: str
    verdict: Literal["safe", "phishing", "suspicious"]
    confidence: float
    features: dict
    ai_explanation: dict | None
    analysis_timestamp: datetime
```

## HTTP Status Codes

| Code | Usage |
|------|-------|
| 200 | Success |
| 201 | Resource created |
| 400 | Bad request (invalid input) |
| 401 | Unauthorized (missing/invalid API key) |
| 404 | Resource not found |
| 422 | Validation error |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
| 503 | Service unavailable (external API down) |

## Rate Limiting

| Endpoint | Limit |
|----------|-------|
| `/api/v1/analyze` | 100/minute |
| `/api/v1/analyze/batch` | 10/minute |
| `/api/v1/scans/*` | 200/minute |
| `/api/v1/stats/*` | 200/minute |
| `/api/v1/feeds/*` | 60/minute |

## Dependencies
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `pydantic` - Data validation
- `slowapi` - Rate limiting

## Acceptance Criteria

| ID | Criteria |
|----|----------|
| AC-001 | All endpoints return correct HTTP status codes |
| AC-002 | Swagger docs available at `/docs` |
| AC-003 | Request validation rejects invalid input |
| AC-004 | API key authentication works |
| AC-005 | Rate limiting enforced |
| AC-006 | Error responses follow consistent format |
| AC-007 | Batch endpoint processes multiple URLs |
| AC-008 | Health check returns component status |

## Test Cases

1. **Endpoint Tests**
   - Each endpoint returns expected response
   - Invalid requests return 400/422
   - Missing auth returns 401

2. **Integration Tests**
   - Full analysis flow works end-to-end
   - Batch analysis processes all URLs
   - Statistics reflect actual scan data

3. **Performance Tests**
   - Response time under load
   - Rate limiting kicks in at threshold
