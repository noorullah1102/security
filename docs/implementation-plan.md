# PhishRadar Implementation Plan

## Overview

This document outlines the phased implementation approach for PhishRadar. Each phase builds on the previous, delivering working functionality at each milestone.

---

## Phase 1: Foundation

**Duration:** 3-4 days
**Goal:** Working FastAPI application with basic URL analysis

### Tasks

#### 1.1 Project Setup
- [ ] Initialize project structure
- [ ] Create virtual environment
- [ ] Add dependencies to requirements.txt
- [ ] Configure environment variables (.env)
- [ ] Set up logging

```
phishradar/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── api/
│   ├── analyzer/
│   ├── explainer/
│   ├── feeds/
│   └── db/
├── tests/
├── frontend/
├── docs/
├── requirements.txt
├── .env.example
└── README.md
```

#### 1.2 FastAPI Skeleton
- [ ] Create FastAPI app in `src/main.py`
- [ ] Add health check endpoint `/health`
- [ ] Configure CORS middleware
- [ ] Set up exception handlers
- [ ] Add basic API key middleware

```python
# src/main.py
from fastapi import FastAPI

app = FastAPI(
    title="PhishRadar",
    description="AI-Powered Phishing Threat Monitor",
    version="1.0.0"
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}
```

#### 1.3 URL Feature Extraction
- [ ] Create `src/analyzer/features.py`
- [ ] Implement domain parsing with `tldextract`
- [ ] Implement SSL certificate checking
- [ ] Implement redirect following
- [ ] Implement lexical feature extraction
- [ ] Create feature extraction tests

```python
# src/analyzer/features.py
class FeatureExtractor:
    def extract(self, url: str) -> URLFeatures:
        # Parse URL
        # Check SSL
        # Follow redirects
        # Extract lexical features
        return URLFeatures(...)
```

#### 1.4 Basic Rule-Based Detection
- [ ] Create `src/analyzer/rules.py`
- [ ] Implement typosquatting detection
- [ ] Implement suspicious keyword detection
- [ ] Implement suspicious TLD detection
- [ ] Create verdict aggregation logic

#### 1.5 Database Setup
- [ ] Create SQLite database
- [ ] Implement `scan_history` table
- [ ] Create `src/db/repository.py`
- [ ] Add connection pooling

### Deliverables
- Working FastAPI application
- `/health` endpoint
- Feature extraction module (tested)
- Rule-based detection working
- SQLite database operational

### Verification
```bash
# Start server
uvicorn src.main:app --reload

# Test health
curl http://localhost:8000/health

# Test feature extraction (unit test)
pytest tests/analyzer/test_features.py
```

---

## Phase 2: ML Classifier

**Duration:** 4-5 days
**Goal:** Trained ML model integrated into analysis pipeline

### Tasks

#### 2.1 Dataset Preparation
- [ ] Download PhishTank dataset
- [ ] Download legitimate URL dataset (Alexa/Cisco)
- [ ] Create dataset preprocessing script
- [ ] Balance classes (50/50 split)
- [ ] Create train/test split (80/20)

```python
# scripts/prepare_dataset.py
def prepare_dataset():
    phishing = load_phishtank_data()
    legitimate = load_alexa_data()
    dataset = balance_and_merge(phishing, legitimate)
    return train_test_split(dataset)
```

#### 2.2 Feature Engineering Pipeline
- [ ] Create `src/ml/features.py`
- [ ] Implement feature vectorization
- [ ] Handle missing values
- [ ] Normalize/scale features
- [ ] Save feature pipeline

#### 2.3 Model Training
- [ ] Create `src/ml/train.py`
- [ ] Train Random Forest classifier
- [ ] Train Gradient Boosting classifier
- [ ] Compare models
- [ ] Calculate metrics (precision, recall, F1)

```python
# src/ml/train.py
def train_model(X_train, y_train):
    rf = RandomForestClassifier()
    rf.fit(X_train, y_train)
    evaluate(rf, X_test, y_test)
    save_model(rf, "models/classifier.pkl")
```

#### 2.4 Model Integration
- [ ] Create `src/analyzer/classifier.py`
- [ ] Load trained model on startup
- [ ] Implement prediction method
- [ ] Add feature importance extraction
- [ ] Handle prediction errors

#### 2.5 Analysis Endpoint
- [ ] Create `/api/v1/analyze` endpoint
- [ ] Integrate feature extraction + classifier
- [ ] Return structured response
- [ ] Save results to database

```python
# src/api/routes/analyze.py
@router.post("/api/v1/analyze")
async def analyze_url(request: AnalyzeRequest):
    features = extractor.extract(request.url)
    result = classifier.predict(features)
    await save_scan(result)
    return result
```

### Deliverables
- Prepared dataset (balanced, split)
- Trained model file (`models/classifier.pkl`)
- Evaluation metrics documented
- `/api/v1/analyze` endpoint working
- Predictions with confidence scores

### Verification
```bash
# Train model
python -m src.ml.train

# Test endpoint
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-domain.com"}'

# Check metrics
pytest tests/ml/test_classifier.py
```

---

## Phase 3: AI Threat Explainer

**Duration:** 3-4 days
**Goal:** Claude API integration with structured explanations

### Tasks

#### 3.1 Claude API Client
- [ ] Create `src/explainer/claude_client.py`
- [ ] Configure Anthropic SDK
- [ ] Implement error handling
- [ ] Add retry logic
- [ ] Track token usage

```python
# src/explainer/claude_client.py
from anthropic import Anthropic

class ClaudeClient:
    def __init__(self, api_key: str):
        self.client = Anthropic(api_key=api_key)

    async def explain(self, analysis: AnalysisResult) -> ThreatExplanation:
        ...
```

#### 3.2 Prompt Engineering
- [ ] Create `src/explainer/prompts.py`
- [ ] Design threat analysis prompt
- [ ] Design safe URL prompt
- [ ] Test prompt variations
- [ ] Document prompt templates

#### 3.3 Response Parsing
- [ ] Create `src/explainer/parser.py`
- [ ] Parse JSON response
- [ ] Validate all fields
- [ ] Handle malformed responses
- [ ] Create fallback explanation

#### 3.4 Caching Layer
- [ ] Create `explanation_cache` table
- [ ] Implement feature hashing
- [ ] Add cache lookup/save
- [ ] Set TTL (24 hours)

#### 3.5 Integration
- [ ] Update `/api/v1/analyze` to include AI explanation
- [ ] Add `include_ai_explanation` parameter
- [ ] Track API usage
- [ ] Implement graceful degradation

### Deliverables
- Claude API client working
- Prompt templates documented
- Response parsing validated
- Explanation caching operational
- `/api/v1/analyze` with AI explanation

### Verification
```bash
# Test with AI explanation
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-domain.com", "include_ai_explanation": true}'

# Check cache
sqlite3 phishradar.db "SELECT * FROM explanation_cache LIMIT 1"
```

---

## Phase 4: Threat Feeds & Reddit

**Duration:** 4-5 days
**Goal:** Live threat intelligence aggregation

### Tasks

#### 4.1 PhishTank Integration
- [ ] Create `src/feeds/phishtank.py`
- [ ] Implement API client
- [ ] Handle authentication
- [ ] Parse response format
- [ ] Implement rate limiting

#### 4.2 URLhaus Integration
- [ ] Create `src/feeds/urlhaus.py`
- [ ] Implement API client
- [ ] Parse response format
- [ ] Extract relevant fields

#### 4.3 Reddit Integration
- [ ] Create `src/feeds/reddit_monitor.py`
- [ ] Configure PRAW
- [ ] Monitor r/cybersecurity
- [ ] Extract URLs from posts
- [ ] Track engagement metrics

#### 4.4 Data Normalization
- [ ] Create `src/feeds/normalizer.py`
- [ ] Convert all sources to `ThreatIndicator`
- [ ] Implement deduplication
- [ ] Track source provenance

#### 4.5 Scheduler
- [ ] Create `src/feeds/scheduler.py`
- [ ] Implement periodic updates (hourly)
- [ ] Add manual trigger endpoint
- [ ] Handle failures gracefully

#### 4.6 Feed Endpoints
- [ ] Create `/api/v1/feeds/indicators`
- [ ] Create `/api/v1/feeds/status`
- [ ] Create `/api/v1/feeds/refresh`

### Deliverables
- PhishTank integration working
- URLhaus integration working
- Reddit monitoring working
- Unified `ThreatIndicator` format
- Scheduled updates
- Feed management endpoints

### Verification
```bash
# Trigger feed refresh
curl -X POST http://localhost:8000/api/v1/feeds/refresh

# Check indicators
curl http://localhost:8000/api/v1/feeds/indicators?limit=10

# Check status
curl http://localhost:8000/api/v1/feeds/status
```

---

## Phase 5: Dashboard & Polish

**Duration:** 3-4 days
**Goal:** User-friendly dashboard and production-ready code

### Tasks

#### 5.1 Dashboard Frontend
- [ ] Create `frontend/index.html`
- [ ] Add Tailwind CSS (CDN)
- [ ] Implement stats cards
- [ ] Implement scan table
- [ ] Implement charts (Chart.js)

```html
<!-- frontend/index.html -->
<!DOCTYPE html>
<html>
<head>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <!-- Dashboard components -->
</body>
</html>
```

#### 5.2 Statistics Endpoints
- [ ] Create `/api/v1/stats/summary`
- [ ] Create `/api/v1/stats/trends`
- [ ] Create `/api/v1/stats/brands`
- [ ] Optimize queries

#### 5.3 Batch Analysis
- [ ] Create `/api/v1/analyze/batch`
- [ ] Implement parallel processing
- [ ] Add progress tracking
- [ ] Handle partial failures

#### 5.4 Documentation
- [ ] Complete API documentation
- [ ] Write README.md
- [ ] Add architecture diagram
- [ ] Create usage examples

#### 5.5 Testing
- [ ] Write unit tests for all modules
- [ ] Write integration tests
- [ ] Test ML model evaluation
- [ ] Mock external APIs

#### 5.6 Production Readiness
- [ ] Add proper logging
- [ ] Add error tracking
- [ ] Configure rate limiting
- [ ] Add input validation
- [ ] Security review

### Deliverables
- Working dashboard UI
- All statistics endpoints
- Batch analysis endpoint
- Complete test suite
- Documentation complete
- Production-ready code

### Verification
```bash
# Run all tests
pytest --cov=src

# Start dashboard
open http://localhost:8000/dashboard

# Test batch analysis
curl -X POST http://localhost:8000/api/v1/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "https://suspicious.com"]}'
```

---

## Timeline Summary

| Phase | Duration | Key Milestone |
|-------|----------|---------------|
| 1. Foundation | 3-4 days | Basic URL analysis working |
| 2. ML Classifier | 4-5 days | Trained model integrated |
| 3. AI Explainer | 3-4 days | Claude API explanations |
| 4. Threat Feeds | 4-5 days | Live threat intelligence |
| 5. Dashboard | 3-4 days | Production-ready system |

**Total:** 17-22 days

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Claude API costs | Caching, budget alerts, batch processing |
| External API failures | Circuit breakers, fallback data |
| Model accuracy | Continuous evaluation, retraining pipeline |
| Rate limiting | Local caching, request queuing |

---

## Success Criteria

- [ ] `/api/v1/analyze` correctly classifies URLs with ≥90% precision
- [ ] AI explanations are clear and actionable
- [ ] Threat feeds update hourly without manual intervention
- [ ] Dashboard displays real-time statistics
- [ ] All tests pass with ≥80% code coverage
- [ ] Documentation is complete and accurate
