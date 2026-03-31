# PhishRadar API Specification

## Base URL
```
Development: http://localhost:8000
Production: https://api.phishradar.io
```

## Authentication
All API requests require an API key in the header:
```
X-API-Key: your-api-key-here
```

## Content Type
All requests and responses use JSON:
```
Content-Type: application/json
```

---

## Endpoints

### Analyze URL

**POST** `/api/v1/analyze`

Analyze a single URL for phishing indicators.

#### Request Body
```json
{
  "url": "https://suspicious-domain.com/login",
  "include_ai_explanation": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| url | string | Yes | URL to analyze (must include protocol) |
| include_ai_explanation | boolean | No | Include AI-generated explanation (default: true) |

#### Success Response (200)
```json
{
  "url": "https://suspicious-domain.com/login",
  "verdict": "phishing",
  "confidence": 0.94,
  "features": {
    "domain_age_days": 3,
    "ssl_valid": false,
    "ssl_issuer": null,
    "redirect_count": 2,
    "redirect_chain": [
      "https://suspicious-domain.com/login",
      "https://tracker.evil.com/capture",
      "https://target-clone.com/fake-login"
    ],
    "typosquat_target": null,
    "typosquat_distance": 0,
    "has_ip_address": false,
    "url_length": 45,
    "path_depth": 1,
    "has_suspicious_keywords": true,
    "subdomain_count": 0,
    "has_https": true,
    "suspicious_tld": false
  },
  "ai_explanation": {
    "summary": "This URL exhibits strong phishing indicators targeting credential theft.",
    "explanation": "The domain was registered only 3 days ago, lacks a valid SSL certificate, and redirects through multiple intermediate servers before reaching a fake login page. The path contains 'login' which is commonly used in phishing campaigns.",
    "risk_factors": [
      "Domain registered less than 30 days ago",
      "No valid SSL certificate",
      "Multiple HTTP redirects detected",
      "Suspicious path keywords present"
    ],
    "severity": "high",
    "recommended_action": "Block this URL immediately and report to IT security team",
    "target_brand": null
  },
  "analysis_timestamp": "2026-03-26T10:30:45Z",
  "cached": false
}
```

#### Error Response (400)
```json
{
  "error": "Invalid URL",
  "detail": "URL must start with http:// or https://",
  "code": "INVALID_URL",
  "timestamp": "2026-03-26T10:30:45Z"
}
```

---

### Batch Analyze URLs

**POST** `/api/v1/analyze/batch`

Analyze multiple URLs in a single request.

#### Request Body
```json
{
  "urls": [
    "https://google.com",
    "https://suspicious-domain.com/login",
    "https://app1e-id-verify.com"
  ],
  "include_ai_explanation": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| urls | string[] | Yes | URLs to analyze (max 100) |
| include_ai_explanation | boolean | No | Include AI explanations (default: false) |

#### Success Response (200)
```json
{
  "results": [
    {
      "url": "https://google.com",
      "verdict": "safe",
      "confidence": 0.98,
      "features": { "..." },
      "ai_explanation": null,
      "analysis_timestamp": "2026-03-26T10:31:00Z"
    },
    {
      "url": "https://suspicious-domain.com/login",
      "verdict": "phishing",
      "confidence": 0.94,
      "features": { "..." },
      "ai_explanation": null,
      "analysis_timestamp": "2026-03-26T10:31:01Z"
    },
    {
      "url": "https://app1e-id-verify.com",
      "verdict": "phishing",
      "confidence": 0.91,
      "features": {
        "typosquat_target": "apple.com",
        "typosquat_distance": 1,
        "..."
      },
      "ai_explanation": null,
      "analysis_timestamp": "2026-03-26T10:31:02Z"
    }
  ],
  "processed": 3,
  "failed": 0,
  "processing_time_ms": 2340
}
```

---

### Get Recent Scans

**GET** `/api/v1/scans/recent`

Retrieve recent scan results.

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | integer | 20 | Number of results (max 100) |
| offset | integer | 0 | Pagination offset |
| verdict | string | null | Filter by verdict (safe/phishing/suspicious) |
| severity | string | null | Filter by severity (low/medium/high/critical) |

#### Success Response (200)
```json
{
  "scans": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "url": "https://suspicious-domain.com/login",
      "verdict": "phishing",
      "confidence": 0.94,
      "severity": "high",
      "created_at": "2026-03-26T10:30:45Z"
    }
  ],
  "total": 1234,
  "limit": 20,
  "offset": 0
}
```

---

### Get Scan by ID

**GET** `/api/v1/scans/{scan_id}`

Retrieve a specific scan result by ID.

#### Path Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| scan_id | string (UUID) | Scan identifier |

#### Success Response (200)
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://suspicious-domain.com/login",
  "verdict": "phishing",
  "confidence": 0.94,
  "features": { "..." },
  "ai_explanation": { "..." },
  "created_at": "2026-03-26T10:30:45Z"
}
```

#### Error Response (404)
```json
{
  "error": "Scan not found",
  "detail": "No scan exists with ID 550e8400-e29b-41d4-a716-446655440000",
  "code": "SCAN_NOT_FOUND",
  "timestamp": "2026-03-26T10:35:00Z"
}
```

---

### Search Scans

**GET** `/api/v1/scans/search`

Search scan history by URL substring.

#### Query Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| q | string | Yes | Search query (URL substring) |
| limit | integer | No | Max results (default: 20) |

#### Success Response (200)
```json
{
  "scans": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "url": "https://suspicious-domain.com/login",
      "verdict": "phishing",
      "confidence": 0.94,
      "created_at": "2026-03-26T10:30:45Z"
    }
  ],
  "query": "suspicious",
  "total": 5
}
```

---

### Get Statistics Summary

**GET** `/api/v1/stats/summary`

Retrieve aggregate statistics.

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | 7d | Time period (1d, 7d, 30d, all) |

#### Success Response (200)
```json
{
  "total_scans": 12345,
  "phishing_detected": 2345,
  "safe_urls": 9500,
  "suspicious": 500,
  "avg_confidence": 0.87,
  "verdict_distribution": {
    "safe": 77.0,
    "phishing": 19.0,
    "suspicious": 4.0
  },
  "severity_distribution": {
    "low": 80.0,
    "medium": 12.0,
    "high": 6.0,
    "critical": 2.0
  },
  "period": {
    "start": "2026-03-19",
    "end": "2026-03-26"
  }
}
```

---

### Get Trend Data

**GET** `/api/v1/stats/trends`

Retrieve time-series data for dashboard charts.

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | 7d | Time period (1d, 7d, 30d) |
| interval | string | day | Aggregation interval (hour, day) |

#### Success Response (200)
```json
{
  "data": [
    {
      "date": "2026-03-19",
      "total_scans": 150,
      "phishing": 30,
      "safe": 115,
      "suspicious": 5
    },
    {
      "date": "2026-03-20",
      "total_scans": 165,
      "phishing": 35,
      "safe": 125,
      "suspicious": 5
    }
  ],
  "period": "7d",
  "interval": "day"
}
```

---

### Get Top Targeted Brands

**GET** `/api/v1/stats/brands`

Retrieve most impersonated brands.

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | integer | 10 | Number of brands (max 50) |
| period | string | 30d | Time period |

#### Success Response (200)
```json
{
  "brands": [
    {"name": "PayPal", "count": 150, "percentage": 23.5},
    {"name": "Microsoft", "count": 120, "percentage": 18.8},
    {"name": "Google", "count": 95, "percentage": 14.9},
    {"name": "Amazon", "count": 80, "percentage": 12.5},
    {"name": "Apple", "count": 65, "percentage": 10.2}
  ],
  "total_phishing": 638,
  "period": "30d"
}
```

---

### Get Threat Indicators

**GET** `/api/v1/feeds/indicators`

Retrieve cached threat indicators from feeds.

#### Query Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| since | string | null | ISO datetime for filtering |
| source | string | null | Filter by source (phishtank/urlhaus/reddit) |
| limit | integer | 100 | Max results (max 1000) |

#### Success Response (200)
```json
{
  "indicators": [
    {
      "id": "indicator-001",
      "url": "http://phishing-site.com/login",
      "threat_type": "phishing",
      "source": "phishtank",
      "first_seen": "2026-03-25T08:00:00Z",
      "last_seen": "2026-03-26T10:00:00Z",
      "target_brand": "PayPal",
      "confidence": 0.95,
      "tags": ["credential_harvesting", "paypal"]
    }
  ],
  "count": 100,
  "sources": ["phishtank", "urlhaus", "reddit"],
  "cached_at": "2026-03-26T10:00:00Z"
}
```

---

### Get Feed Status

**GET** `/api/v1/feeds/status`

Retrieve health status of threat feed sources.

#### Success Response (200)
```json
{
  "sources": [
    {
      "name": "phishtank",
      "status": "healthy",
      "last_update": "2026-03-26T09:00:00Z",
      "indicator_count": 1234,
      "error_count": 0
    },
    {
      "name": "urlhaus",
      "status": "healthy",
      "last_update": "2026-03-26T09:00:00Z",
      "indicator_count": 5678,
      "error_count": 0
    },
    {
      "name": "reddit",
      "status": "degraded",
      "last_update": "2026-03-26T06:00:00Z",
      "indicator_count": 89,
      "error_count": 3,
      "last_error": "Rate limit exceeded"
    }
  ],
  "overall_status": "degraded"
}
```

---

### Trigger Feed Refresh

**POST** `/api/v1/feeds/refresh`

Manually trigger a feed refresh.

#### Request Body
```json
{
  "source": "phishtank"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| source | string | No | Specific source to refresh (null = all) |

#### Success Response (202)
```json
{
  "status": "refreshing",
  "sources": ["phishtank"],
  "job_id": "refresh-job-123"
}
```

---

### Health Check

**GET** `/health`

Check system health status.

#### Success Response (200)
```json
{
  "status": "healthy",
  "components": {
    "api": "ok",
    "database": "ok",
    "claude_api": "ok",
    "feeds": "degraded"
  },
  "version": "1.0.0",
  "uptime_seconds": 86400
}
```

#### Degraded Response (503)
```json
{
  "status": "unhealthy",
  "components": {
    "api": "ok",
    "database": "error",
    "claude_api": "ok",
    "feeds": "ok"
  },
  "version": "1.0.0",
  "errors": ["Database connection failed"]
}
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_URL | 400 | URL format is invalid |
| INVALID_REQUEST | 400 | Request body validation failed |
| UNAUTHORIZED | 401 | Missing or invalid API key |
| RATE_LIMITED | 429 | Rate limit exceeded |
| SCAN_NOT_FOUND | 404 | Requested scan does not exist |
| INTERNAL_ERROR | 500 | Internal server error |
| SERVICE_UNAVAILABLE | 503 | External service unavailable |

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/api/v1/analyze` | 100 requests | 1 minute |
| `/api/v1/analyze/batch` | 10 requests | 1 minute |
| `/api/v1/scans/*` | 200 requests | 1 minute |
| `/api/v1/stats/*` | 200 requests | 1 minute |
| `/api/v1/feeds/*` | 60 requests | 1 minute |

Rate limit headers are included in all responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1648291200
```
