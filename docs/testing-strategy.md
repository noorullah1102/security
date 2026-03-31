# PhishRadar Testing Strategy

## Overview

This document outlines the testing approach for PhishRadar, ensuring reliability and correctness across all modules.

---

## Testing Pyramid

```
         ┌─────────────┐
         │    E2E      │  (Few)
         │   Tests     │
         ├─────────────┤
         │ Integration │  (Some)
         │   Tests     │
         ├─────────────┤
         │    Unit     │  (Many)
         │   Tests     │
         └─────────────┘
```

---

## Test Categories

### 1. Unit Tests

**Purpose:** Test individual functions and classes in isolation.

#### Module: URL Analyzer
```python
# tests/analyzer/test_features.py

import pytest
from src.analyzer.features import FeatureExtractor

class TestFeatureExtractor:
    @pytest.fixture
    def extractor(self):
        return FeatureExtractor()

    def test_extract_url_length(self, extractor):
        features = extractor.extract("https://example.com/path/to/page")
        assert features.url_length == 34

    def test_extract_path_depth(self, extractor):
        features = extractor.extract("https://example.com/a/b/c")
        assert features.path_depth == 3

    def test_extract_has_ip_address_true(self, extractor):
        features = extractor.extract("http://192.168.1.1/login")
        assert features.has_ip_address is True

    def test_extract_has_ip_address_false(self, extractor):
        features = extractor.extract("https://example.com")
        assert features.has_ip_address is False

    def test_extract_suspicious_keywords(self, extractor):
        features = extractor.extract("https://example.com/verify-account")
        assert features.has_suspicious_keywords is True

    def test_extract_subdomain_count(self, extractor):
        features = extractor.extract("https://a.b.c.example.com")
        assert features.subdomain_count == 3
```

#### Module: Typosquatting Detection
```python
# tests/analyzer/test_typosquat.py

import pytest
from src.analyzer.typosquat import TyposquatDetector

class TestTyposquatDetector:
    @pytest.fixture
    def detector(self):
        return TyposquatDetector(["google.com", "facebook.com", "apple.com"])

    def test_detect_exact_substitution(self, detector):
        result = detector.check("g00gle.com")
        assert result.target == "google.com"
        assert result.distance == 1

    def test_detect_character_omission(self, detector):
        result = detector.check("googl.com")
        assert result.target == "google.com"

    def test_no_match_legitimate(self, detector):
        result = detector.check("mywebsite.com")
        assert result.target is None

    def test_homoglyph_detection(self, detector):
        # Cyrillic 'а' vs Latin 'a'
        result = detector.check("аpple.com")
        assert result.target == "apple.com"
```

#### Module: ML Classifier
```python
# tests/ml/test_classifier.py

import pytest
import numpy as np
from src.analyzer.classifier import URLClassifier

class TestURLClassifier:
    @pytest.fixture
    def classifier(self):
        return URLClassifier.load("models/classifier.pkl")

    def test_predict_returns_verdict(self, classifier, sample_features):
        result = classifier.predict(sample_features)
        assert result.verdict in ["safe", "phishing", "suspicious"]

    def test_predict_returns_confidence(self, classifier, sample_features):
        result = classifier.predict(sample_features)
        assert 0.0 <= result.confidence <= 1.0

    def test_feature_importance_shape(self, classifier, sample_features):
        importance = classifier.get_feature_importance(sample_features)
        assert len(importance) == len(sample_features.to_feature_vector())

    def test_model_loaded_successfully(self, classifier):
        assert classifier.model is not None
        assert hasattr(classifier.model, 'predict')
```

#### Module: AI Explainer
```python
# tests/explainer/test_parser.py

import pytest
from src.explainer.parser import ResponseParser

class TestResponseParser:
    @pytest.fixture
    def parser(self):
        return ResponseParser()

    def test_parse_valid_json(self, parser):
        response = '''
        {
          "summary": "Test summary",
          "explanation": "Test explanation",
          "risk_factors": ["factor1"],
          "severity": "high",
          "recommended_action": "Block",
          "target_brand": "PayPal"
        }
        '''
        result = parser.parse(response)
        assert result.severity == "high"
        assert result.target_brand == "PayPal"

    def test_parse_invalid_json_returns_fallback(self, parser):
        result = parser.parse("not valid json")
        assert result.severity == "medium"
        assert "Unable to parse" in result.explanation

    def test_validate_required_fields(self, parser):
        response = '{"summary": "test"}'  # Missing fields
        result = parser.parse(response)
        assert result.recommended_action is not None  # Has default
```

### 2. Integration Tests

**Purpose:** Test module interactions and API endpoints.

#### API Endpoints
```python
# tests/api/test_analyze.py

import pytest
from fastapi.testclient import TestClient
from src.main import app

@pytest.fixture
def client():
    return TestClient(app)

class TestAnalyzeEndpoint:
    def test_analyze_valid_url(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={"url": "https://google.com"},
            headers={"X-API-Key": "test-key"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] in ["safe", "phishing", "suspicious"]
        assert "confidence" in data

    def test_analyze_invalid_url(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={"url": "not-a-url"},
            headers={"X-API-Key": "test-key"}
        )
        assert response.status_code == 422

    def test_analyze_missing_api_key(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={"url": "https://example.com"}
        )
        assert response.status_code == 401

    def test_analyze_with_ai_explanation(self, client, mock_claude):
        response = client.post(
            "/api/v1/analyze",
            json={"url": "https://suspicious.com", "include_ai_explanation": True},
            headers={"X-API-Key": "test-key"}
        )
        assert response.status_code == 200
        assert "ai_explanation" in response.json()
```

#### Database Operations
```python
# tests/db/test_repository.py

import pytest
from src.db.repository import ScanRepository

@pytest.fixture
def repository(tmp_path):
    db_path = tmp_path / "test.db"
    return ScanRepository(f"sqlite:///{db_path}")

class TestScanRepository:
    @pytest.mark.asyncio
    async def test_save_scan(self, repository, sample_scan):
        scan_id = await repository.save(sample_scan)
        assert scan_id is not None

    @pytest.mark.asyncio
    async def test_get_scan_by_id(self, repository, sample_scan):
        scan_id = await repository.save(sample_scan)
        result = await repository.get_by_id(scan_id)
        assert result.url == sample_scan.url

    @pytest.mark.asyncio
    async def test_get_recent_scans(self, repository, multiple_scans):
        for scan in multiple_scans:
            await repository.save(scan)
        results = await repository.get_recent(limit=10)
        assert len(results) == len(multiple_scans)
```

#### Threat Feed Integration
```python
# tests/feeds/test_aggregator.py

import pytest
from unittest.mock import AsyncMock, patch
from src.feeds.aggregator import ThreatFeedAggregator

class TestThreatFeedAggregator:
    @pytest.fixture
    def aggregator(self):
        return ThreatFeedAggregator()

    @pytest.mark.asyncio
    async def test_fetch_all_sources(self, aggregator, mock_all_feeds):
        indicators = await aggregator.fetch_all_sources()
        assert len(indicators) > 0
        for indicator in indicators:
            assert indicator.url is not None
            assert indicator.source in ["phishtank", "urlhaus", "reddit"]

    @pytest.mark.asyncio
    async def test_deduplication(self, aggregator, mock_duplicate_feeds):
        indicators = await aggregator.fetch_all_sources()
        urls = [i.url for i in indicators]
        assert len(urls) == len(set(urls))  # No duplicates

    @pytest.mark.asyncio
    async def test_source_failure_graceful(self, aggregator, mock_failing_source):
        # One source fails, others should still return data
        indicators = await aggregator.fetch_all_sources()
        assert len(indicators) > 0
```

### 3. ML Model Evaluation

**Purpose:** Validate model performance on held-out data.

```python
# tests/ml/test_evaluation.py

import pytest
from sklearn.metrics import precision_score, recall_score, f1_score
from src.ml.train import load_test_data, evaluate_model

class TestModelEvaluation:
    @pytest.fixture
    def test_data(self):
        return load_test_data("data/test_set.csv")

    def test_precision_threshold(self, test_data):
        model = load_model("models/classifier.pkl")
        y_pred = model.predict(test_data.X)
        precision = precision_score(test_data.y, y_pred)
        assert precision >= 0.90, f"Precision {precision} below 0.90 threshold"

    def test_recall_threshold(self, test_data):
        model = load_model("models/classifier.pkl")
        y_pred = model.predict(test_data.X)
        recall = recall_score(test_data.y, y_pred)
        assert recall >= 0.85, f"Recall {recall} below 0.85 threshold"

    def test_f1_threshold(self, test_data):
        model = load_model("models/classifier.pkl")
        y_pred = model.predict(test_data.X)
        f1 = f1_score(test_data.y, y_pred)
        assert f1 >= 0.87, f"F1 {f1} below 0.87 threshold"

    def test_confusion_matrix(self, test_data):
        model = load_model("models/classifier.pkl")
        y_pred = model.predict(test_data.X)
        cm = confusion_matrix(test_data.y, y_pred)
        # Log for analysis, not strict assertion
        print(f"Confusion Matrix:\n{cm}")
```

### 4. End-to-End Tests

**Purpose:** Test complete user flows.

```python
# tests/e2e/test_flows.py

import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def client():
    return TestClient(app)

class TestUserFlows:
    def test_complete_analysis_flow(self, client):
        # 1. Analyze a URL
        response = client.post(
            "/api/v1/analyze",
            json={"url": "https://phishing-test.com/login", "include_ai_explanation": True},
            headers={"X-API-Key": "test-key"}
        )
        assert response.status_code == 200
        scan_id = response.json()["id"]

        # 2. Retrieve scan from history
        response = client.get(f"/api/v1/scans/{scan_id}", headers={"X-API-Key": "test-key"})
        assert response.status_code == 200
        assert response.json()["url"] == "https://phishing-test.com/login"

        # 3. Check statistics include this scan
        response = client.get("/api/v1/stats/summary", headers={"X-API-Key": "test-key"})
        assert response.status_code == 200
        assert response.json()["total_scans"] >= 1

    def test_batch_analysis_flow(self, client):
        response = client.post(
            "/api/v1/analyze/batch",
            json={"urls": ["https://google.com", "https://phishing-test.com"]},
            headers={"X-API-Key": "test-key"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["processed"] == 2
        assert data["failed"] == 0
```

---

## Mocking Strategy

### External APIs

```python
# tests/conftest.py

import pytest
from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_claude():
    """Mock Claude API responses."""
    with patch("src.explainer.claude_client.Anthropic") as mock:
        client = mock.return_value
        client.messages.create = AsyncMock(return_value={
            "content": [{
                "text": '''{
                    "summary": "Test summary",
                    "explanation": "Test explanation",
                    "risk_factors": ["test"],
                    "severity": "medium",
                    "recommended_action": "Test action",
                    "target_brand": null
                }'''
            }]
        })
        yield client

@pytest.fixture
def mock_phishtank():
    """Mock PhishTank API responses."""
    with patch("src.feeds.phishtank.PhishtankClient") as mock:
        client = mock.return_value
        client.fetch = AsyncMock(return_value=[
            {"url": "http://phishing1.com", "target": "PayPal"},
            {"url": "http://phishing2.com", "target": "Google"},
        ])
        yield client

@pytest.fixture
def mock_whois():
    """Mock WHOIS lookups."""
    with patch("src.analyzer.features.whois.whois") as mock:
        mock.return_value = {
            "creation_date": datetime.now() - timedelta(days=365)
        }
        yield mock
```

### Database

```python
# tests/conftest.py

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

@pytest.fixture
def test_db(tmp_path):
    """Create isolated test database."""
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
```

---

## Test Configuration

### pytest.ini
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
addopts = -v --tb=short
markers =
    slow: marks tests as slow
    integration: marks integration tests
    e2e: marks end-to-end tests
```

### Requirements (dev)
```
pytest>=7.0.0
pytest-asyncio>=0.20.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
httpx>=0.24.0
```

---

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/analyzer/test_features.py

# Run specific test
pytest tests/analyzer/test_features.py::TestFeatureExtractor::test_extract_url_length

# Run only unit tests
pytest -m "not integration and not e2e"

# Run integration tests
pytest -m integration

# Run with verbose output
pytest -vv
```

---

## Coverage Goals

| Module | Target Coverage |
|--------|-----------------|
| src/analyzer/ | ≥ 90% |
| src/explainer/ | ≥ 85% |
| src/feeds/ | ≥ 80% |
| src/api/ | ≥ 85% |
| src/db/ | ≥ 80% |
| **Overall** | **≥ 85%** |

---

## CI Integration

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements-dev.txt
      - run: pytest --cov=src --cov-fail-under=85
```
