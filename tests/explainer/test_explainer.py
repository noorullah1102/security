"""Tests for AI Threat Explainer."""

import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.explainer.claude_client import (
    AIThreatExplainer,
    ThreatExplanation,
    ExplainerResult,
    UsageStats,
)
from src.explainer.prompts import (
    SYSTEM_PROMPT,
    build_threat_analysis_prompt,
    build_safe_url_prompt,
    parse_explanation_response,
    get_default_value,
)
from src.explainer.cache import ExplanationCache
from src.analyzer.models import AnalysisResult, URLFeatures


@pytest.fixture
def mock_features():
    """Create mock URL features for phishing."""
    return URLFeatures(
        domain_age_days=3,
        ssl_valid=False,
        ssl_issuer=None,
        redirect_count=2,
        typosquat_target="paypal.com",
        has_ip_address=False,
        url_length=75,
        path_depth=2,
        subdomain_count=1,
        has_https=True,
        has_suspicious_keywords=True,
        suspicious_tld=False,
        typosquat_distance=1,
    )


@pytest.fixture
def mock_safe_features():
    """Create mock URL features for safe URL."""
    return URLFeatures(
        domain_age_days=500,
        ssl_valid=True,
        ssl_issuer="Let's Encrypt",
        redirect_count=0,
        typosquat_target=None,
        has_ip_address=False,
        url_length=35,
        path_depth=1,
        subdomain_count=0,
        has_https=True,
        has_suspicious_keywords=False,
        suspicious_tld=False,
        typosquat_distance=0,
    )


@pytest.fixture
def mock_phishing_result(mock_features):
    """Create mock phishing analysis result."""
    return AnalysisResult(
        url="https://paypa1.com/verify",
        verdict="phishing",
        confidence=0.92,
        features=mock_features,
        matched_rules=["typosquatting", "suspicious_keywords"],
    )


@pytest.fixture
def mock_safe_result(mock_safe_features):
    """Create mock safe analysis result."""
    return AnalysisResult(
        url="https://google.com/search",
        verdict="safe",
        confidence=0.95,
        features=mock_features,
        matched_rules=[],
    )


class TestThreatExplanation:
    """Tests for ThreatExplanation dataclass."""

    def test_create_threat_explanation(self):
        """Test creating a threat explanation."""
        explanation = ThreatExplanation(
            summary="This is a phishing attempt",
            explanation="The URL typosquats paypal.com",
            risk_factors=["typosquatting", "suspicious keywords"],
            severity="high",
            recommended_action="Block this URL",
            target_brand="PayPal",
        )

        assert explanation.summary == "This is a phishing attempt"
        assert explanation.severity == "high"
        assert len(explanation.risk_factors) == 2

    def test_to_dict(self):
        """Test converting to dictionary."""
        explanation = ThreatExplanation(
            summary="Test",
            explanation="Test explanation",
            risk_factors=["factor1"],
            severity="medium",
            recommended_action="Review",
            target_brand=None,
        )

        data = explanation.to_dict()
        assert data["summary"] == "Test"
        assert data["target_brand"] is None


class TestUsageStats:
    """Tests for UsageStats dataclass."""

    def test_create_usage_stats(self):
        """Test creating usage stats."""
        stats = UsageStats(
            total_requests=10,
            total_tokens=5000,
            input_tokens=3000,
            output_tokens=2000,
        )

        assert stats.total_requests == 10
        assert stats.total_tokens == 5000

    def test_to_dict(self):
        """Test converting to dictionary."""
        stats = UsageStats(total_requests=5)
        data = stats.to_dict()

        assert data["total_requests"] == 5
        assert data["cache_hits"] == 0


class TestPrompts:
    """Tests for prompt templates."""

    def test_system_prompt_exists(self):
        """Test that system prompt is defined."""
        assert SYSTEM_PROMPT is not None
        assert "phishing" in SYSTEM_PROMPT.lower()
        assert "severity" in SYSTEM_PROMPT.lower()

    def test_build_threat_analysis_prompt(self, mock_phishing_result):
        """Test building threat analysis prompt."""
        prompt = build_threat_analysis_prompt(mock_phishing_result)

        assert mock_phishing_result.url in prompt
        assert "phishing" in prompt
        assert "paypal.com" in prompt
        assert "JSON" in prompt

    def test_build_safe_url_prompt(self, mock_safe_result):
        """Test building safe URL prompt."""
        prompt = build_safe_url_prompt(mock_safe_result)

        assert mock_safe_result.url in prompt
        assert "safe" in prompt.lower()

    def test_parse_valid_json_response(self):
        """Test parsing valid JSON response."""
        response = json.dumps({
            "summary": "Test summary",
            "explanation": "Test explanation",
            "risk_factors": ["factor1", "factor2"],
            "severity": "high",
            "recommended_action": "Block",
            "target_brand": "PayPal",
        })

        parsed = parse_explanation_response(response)

        assert parsed["summary"] == "Test summary"
        assert parsed["severity"] == "high"
        assert len(parsed["risk_factors"]) == 2

    def test_parse_markdown_json_response(self):
        """Test parsing JSON wrapped in markdown."""
        response = """```json
{
    "summary": "Test",
    "explanation": "Test explanation",
    "risk_factors": [],
    "severity": "low",
    "recommended_action": "None"
}
```"""

        parsed = parse_explanation_response(response)
        assert parsed["summary"] == "Test"

    def test_parse_invalid_json_returns_fallback(self):
        """Test that invalid JSON returns fallback."""
        response = "This is not valid JSON"

        parsed = parse_explanation_response(response)

        assert "Unable to generate" in parsed["summary"]
        assert parsed["severity"] == "medium"

    def test_parse_missing_fields_get_defaults(self):
        """Test that missing fields get default values."""
        response = json.dumps({
            "summary": "Test",
            # Missing other fields
        })

        parsed = parse_explanation_response(response)

        assert parsed["summary"] == "Test"
        assert parsed["severity"] == "medium"  # Default
        assert parsed["risk_factors"] == []  # Default

    def test_invalid_severity_corrected(self):
        """Test that invalid severity is corrected."""
        response = json.dumps({
            "summary": "Test",
            "explanation": "Test",
            "risk_factors": [],
            "severity": "extreme",  # Invalid
            "recommended_action": "Test",
        })

        parsed = parse_explanation_response(response)
        assert parsed["severity"] == "medium"

    def test_get_default_value(self):
        """Test getting default values."""
        assert get_default_value("summary") == "Analysis completed"
        assert get_default_value("severity") == "medium"
        assert get_default_value("nonexistent") is None


class TestExplanationCache:
    """Tests for explanation caching."""

    def test_cache_create(self, tmp_path):
        """Test creating cache."""
        cache = ExplanationCache(db_path=str(tmp_path / "test_cache.db"))
        stats = cache.get_stats()

        assert stats["total_entries"] == 0

    def test_cache_set_and_get(self, tmp_path):
        """Test caching and retrieving."""
        cache = ExplanationCache(db_path=str(tmp_path / "test_cache.db"))

        url = "https://example.com"
        features = {"domain_age_days": 100}
        explanation = {
            "summary": "Test",
            "explanation": "Test explanation",
            "risk_factors": [],
            "severity": "low",
            "recommended_action": "None",
        }

        # Cache it
        cache.set(url, features, explanation)

        # Retrieve it
        cached = cache.get(url, features)

        assert cached is not None
        assert cached["summary"] == "Test"

    def test_cache_miss(self, tmp_path):
        """Test cache miss."""
        cache = ExplanationCache(db_path=str(tmp_path / "test_cache.db"))

        result = cache.get("https://nonexistent.com", {"domain_age_days": 100})
        assert result is None

    def test_cache_different_features_different_key(self, tmp_path):
        """Test that different features produce different cache keys."""
        cache = ExplanationCache(db_path=str(tmp_path / "test_cache.db"))

        url = "https://example.com"
        explanation = {"summary": "Test", "severity": "low"}

        cache.set(url, {"domain_age_days": 100}, explanation)

        # Different features should miss
        result = cache.get(url, {"domain_age_days": 5})
        assert result is None

    def test_cache_stats(self, tmp_path):
        """Test cache statistics."""
        cache = ExplanationCache(db_path=str(tmp_path / "test_cache.db"))

        cache.set("https://a.com", {"domain_age": 100}, {"summary": "A"})
        cache.set("https://b.com", {"domain_age": 200}, {"summary": "B"})

        stats = cache.get_stats()
        assert stats["total_entries"] == 2
        assert stats["active_entries"] == 2


class TestAIThreatExplainer:
    """Tests for AIThreatExplainer class."""

    def test_explainer_without_api_key(self):
        """Test explainer gracefully handles missing API key."""
        explainer = AIThreatExplainer(api_key=None)

        assert not explainer.is_available()

    def test_fallback_explanation(self, mock_phishing_result):
        """Test fallback explanation generation."""
        explainer = AIThreatExplainer(api_key=None)

        import asyncio
        result = asyncio.run(explainer.explain(mock_phishing_result))

        assert result.verdict == "phishing"
        assert result.ai_explanation.severity in ["low", "medium", "high", "critical"]
        assert len(result.ai_explanation.risk_factors) > 0

    def test_get_usage_stats(self):
        """Test getting usage statistics."""
        explainer = AIThreatExplainer(api_key=None)
        stats = explainer.get_usage_stats()

        assert "total_requests" in stats
        assert "cache_stats" in stats


class TestExplainerResult:
    """Tests for ExplainerResult dataclass."""

    def test_create_explainer_result(self):
        """Test creating an explainer result."""
        explanation = ThreatExplanation(
            summary="Test",
            explanation="Test",
            risk_factors=[],
            severity="medium",
            recommended_action="Review",
        )

        result = ExplainerResult(
            url="https://example.com",
            verdict="suspicious",
            confidence=0.75,
            ai_explanation=explanation,
            analysis_timestamp=datetime.utcnow(),
            cached=False,
            tokens_used=100,
        )

        assert result.url == "https://example.com"
        assert result.cached is False
        assert result.tokens_used == 100

    def test_to_dict(self):
        """Test converting to dictionary."""
        explanation = ThreatExplanation(
            summary="Test",
            explanation="Test",
            risk_factors=["factor1"],
            severity="high",
            recommended_action="Block",
            target_brand="TestBrand",
        )

        result = ExplainerResult(
            url="https://example.com",
            verdict="phishing",
            confidence=0.9,
            ai_explanation=explanation,
            analysis_timestamp=datetime.utcnow(),
        )

        data = result.to_dict()

        assert data["url"] == "https://example.com"
        assert data["ai_explanation"]["target_brand"] == "TestBrand"
