# PhishRadar Architecture

## System Overview

PhishRadar is an AI-powered phishing threat monitoring system that aggregates threat intelligence, analyzes URLs using machine learning, and provides human-readable explanations via Claude AI.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          External Clients                            │
│                    (Browser / API Consumers)                         │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         FastAPI REST API                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ /analyze │ │ /scans   │ │ /stats   │ │ /feeds   │ │ /health  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└──────────┬──────────────────────────┬───────────────────────────────┘
           │                          │
           ▼                          ▼
┌──────────────────────┐    ┌──────────────────────┐
│   URL Analyzer       │    │  AI Threat Explainer │
│  ┌────────────────┐  │    │  ┌────────────────┐  │
│  │ Feature        │  │    │  │ Claude API     │  │
│  │ Extraction     │  │    │  │ Client         │  │
│  └────────┬───────┘  │    │  └────────┬───────┘  │
│           ▼          │    │           ▼          │
│  ┌────────────────┐  │    │  ┌────────────────┐  │
│  │ ML Classifier  │  │    │  │ Prompt         │  │
│  │ (scikit-learn) │  │    │  │ Templates      │  │
│  └────────────────┘  │    │  └────────────────┘  │
└──────────────────────┘    └──────────────────────┘
           │                          │
           └──────────┬───────────────┘
                      ▼
           ┌──────────────────────┐
           │   Threat Feed        │
           │   Aggregator         │
           │  ┌────────────────┐  │
           │  │ PhishTank      │  │
           │  │ URLhaus        │  │
           │  │ abuse.ch       │  │
           │  │ Reddit (PRAW)  │  │
           │  └────────────────┘  │
           └──────────┬───────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │   SQLite Database    │
           │  ┌────────────────┐  │
           │  │ scan_history   │  │
           │  │ threat_cache   │  │
           │  │ feed_status    │  │
           │  └────────────────┘  │
           └──────────────────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │   Dashboard (HTML)   │
           │   Tailwind + JS      │
           └──────────────────────┘
```

## Component Details

### 1. REST API Layer (FastAPI)
**Responsibility:** HTTP interface for all system functionality

- Exposes endpoints for URL analysis, scan history, statistics, and feed management
- Handles authentication via API keys
- Implements rate limiting
- Generates automatic Swagger documentation

**Key Files:**
- `src/api/main.py` - FastAPI application
- `src/api/routes/` - Endpoint handlers
- `src/api/schemas/` - Pydantic models

### 2. URL Analyzer Module
**Responsibility:** Feature extraction and ML-based classification

- Extracts 14+ features from URLs (domain age, SSL, redirects, typosquatting)
- Runs features through trained scikit-learn classifier
- Returns verdict with confidence score and feature importance

**Key Files:**
- `src/analyzer/features.py` - Feature extraction
- `src/analyzer/classifier.py` - ML model wrapper
- `src/analyzer/typosquat.py` - Typosquatting detection

### 3. AI Threat Explainer Module
**Responsibility:** Generate human-readable threat explanations

- Calls Claude API with structured prompts
- Parses and validates JSON responses
- Caches explanations to reduce API costs
- Falls back to rule-based explanations on API failure

**Key Files:**
- `src/explainer/claude_client.py` - Claude API integration
- `src/explainer/prompts.py` - Prompt templates
- `src/explainer/cache.py` - Response caching

### 4. Threat Feed Aggregator Module
**Responsibility:** Collect and normalize threat intelligence

- Fetches data from PhishTank, URLhaus, abuse.ch
- Monitors Reddit r/cybersecurity via PRAW
- Normalizes to unified ThreatIndicator schema
- Runs scheduled updates (configurable intervals)

**Key Files:**
- `src/feeds/phishtank.py` - PhishTank client
- `src/feeds/urlhaus.py` - URLhaus client
- `src/feeds/reddit_monitor.py` - Reddit monitor
- `src/feeds/normalizer.py` - Data normalization

### 5. Database Layer (SQLite)
**Responsibility:** Persistent storage for scans and cache

- Stores scan history with full analysis results
- Caches threat feed indicators
- Tracks feed source status and health

**Key Files:**
- `src/db/models.py` - SQLAlchemy models
- `src/db/repository.py` - Data access layer
- `src/db/migrations/` - Schema migrations

### 6. Dashboard Frontend
**Responsibility:** Web UI for visualization

- Displays recent scans, statistics, and trends
- Charts using Chart.js
- Real-time updates via polling

**Key Files:**
- `frontend/index.html` - Main page
- `frontend/js/app.js` - Application logic
- `frontend/js/charts.js` - Chart configurations

## Data Flow

### URL Analysis Flow
```
1. Client POST /api/v1/analyze with URL
2. API validates request, extracts URL
3. URL Analyzer extracts features:
   a. Parse URL with tldextract
   b. Query WHOIS for domain age
   c. Check SSL certificate
   d. Follow redirects
   e. Calculate typosquatting distance
   f. Extract lexical features
4. ML Classifier produces verdict + confidence
5. AI Explainer generates explanation (if requested)
6. Result saved to scan_history
7. Response returned to client
```

### Threat Feed Update Flow
```
1. Scheduler triggers update (hourly)
2. Aggregator fetches from each source in parallel:
   a. PhishTank API
   b. URLhaus API
   c. abuse.ch feeds
   d. Reddit API
3. Responses normalized to ThreatIndicator
4. Duplicates merged across sources
5. Indicators cached in threat_cache table
6. Feed status updated in feed_status table
```

## Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Python 3.11+ | Security tooling standard, ML ecosystem |
| Web Framework | FastAPI | Async support, auto docs, type safety |
| ML Framework | scikit-learn | Lightweight, interpretable models |
| AI API | Claude (Anthropic) | High-quality explanations, structured output |
| Database | SQLite → PostgreSQL | SQLite for MVP, PostgreSQL for scale |
| Frontend | HTML + Tailwind + JS | Simple, no build step, fast iteration |
| Reddit API | PRAW | Well-maintained, feature-complete |

## Security Considerations

### API Security
- API key authentication for all endpoints
- Rate limiting to prevent abuse
- Input validation on all user-supplied data
- No execution of user-supplied code

### Data Security
- API keys stored in environment variables
- No logging of sensitive URL content
- HTTPS required for all external calls

### External Service Security
- Verify SSL certificates for all API calls
- Implement circuit breakers for failing services
- No credential storage for external services

## Scalability Notes

### Current (MVP)
- Single FastAPI process
- SQLite database
- In-memory cache
- Suitable for: 100-1000 scans/day

### Future Scaling
- Multiple FastAPI workers (gunicorn + uvicorn)
- PostgreSQL database
- Redis cache layer
- Queue-based feed updates (Celery)
- Suitable for: 10,000+ scans/day
