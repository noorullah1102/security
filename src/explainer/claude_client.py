"""Claude API client for threat explanations."""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from anthropic import Anthropic, APIError, RateLimitError
from structlog import get_logger

from src.analyzer.models import AnalysisResult
from src.config import get_settings
from src.explainer.cache import ExplanationCache
from src.explainer.prompts import (
    SYSTEM_PROMPT,
    build_safe_url_prompt,
    build_threat_analysis_prompt,
    parse_explanation_response,
)

logger = get_logger()


@dataclass
class UsageStats:
    """API usage statistics."""

    total_requests: int = 0
    total_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    errors: int = 0
    last_request_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "total_tokens": self.total_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "errors": self.errors,
            "last_request_time": (
                self.last_request_time.isoformat() if self.last_request_time else None
            ),
        }


@dataclass
class ThreatExplanation:
    """AI-generated threat explanation."""

    summary: str
    explanation: str
    risk_factors: list[str]
    severity: str  # low, medium, high, critical
    recommended_action: str
    target_brand: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": self.summary,
            "explanation": self.explanation,
            "risk_factors": self.risk_factors,
            "severity": self.severity,
            "recommended_action": self.recommended_action,
            "target_brand": self.target_brand,
        }


@dataclass
class ExplainerResult:
    """Result of AI explanation."""

    url: str
    verdict: str
    confidence: float
    ai_explanation: ThreatExplanation
    analysis_timestamp: datetime
    cached: bool = False
    tokens_used: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "ai_explanation": self.ai_explanation.to_dict(),
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "cached": self.cached,
            "tokens_used": self.tokens_used,
        }


class AIThreatExplainer:
    """Generates AI-powered threat explanations using Claude API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-6-20250514",
        cache_ttl_hours: int = 24,
        max_tokens: int = 1024,
    ):
        """Initialize the explainer.

        Args:
            api_key: Anthropic API key (uses settings if not provided)
            model: Claude model to use
            cache_ttl_hours: Cache TTL in hours
            max_tokens: Maximum tokens in response
        """
        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model
        self.max_tokens = max_tokens

        self.client = None
        if self.api_key:
            self.client = Anthropic(api_key=self.api_key)
        else:
            logger.warning("No Anthropic API key configured, AI explanations disabled")

        self.cache = ExplanationCache(ttl_hours=cache_ttl_hours)
        self.usage_stats = UsageStats()

    def is_available(self) -> bool:
        """Check if Claude API is available.

        Returns:
            True if API key is configured and client is ready
        """
        return self.client is not None

    async def explain(self, result: AnalysisResult) -> ExplainerResult:
        """Generate AI explanation for analysis result.

        Args:
            result: Analysis result from URL analyzer

        Returns:
            ExplainerResult with AI-generated explanation
        """
        if not self.is_available():
            return self._fallback_explanation(result)

        # Check cache first
        features_dict = result.features.to_dict()
        cached = self.cache.get(result.url, features_dict)

        if cached:
            self.usage_stats.cache_hits += 1
            logger.info("Using cached explanation", url=result.url)

            return ExplainerResult(
                url=result.url,
                verdict=result.verdict,
                confidence=result.confidence,
                ai_explanation=ThreatExplanation(**cached),
                analysis_timestamp=result.analysis_timestamp,
                cached=True,
            )

        self.usage_stats.cache_misses += 1

        # Generate new explanation
        try:
            explanation, tokens_used = await self._generate_explanation(result)

            # Cache the result
            self.cache.set(result.url, features_dict, explanation.to_dict())

            return ExplainerResult(
                url=result.url,
                verdict=result.verdict,
                confidence=result.confidence,
                ai_explanation=explanation,
                analysis_timestamp=result.analysis_timestamp,
                cached=False,
                tokens_used=tokens_used,
            )

        except RateLimitError:
            logger.warning("Rate limit exceeded, using fallback")
            self.usage_stats.errors += 1
            return self._fallback_explanation(result)

        except APIError as e:
            logger.error("Claude API error", error=str(e))
            self.usage_stats.errors += 1
            return self._fallback_explanation(result)

        except Exception as e:
            logger.error("Unexpected error generating explanation", error=str(e))
            self.usage_stats.errors += 1
            return self._fallback_explanation(result)

    async def _generate_explanation(
        self, result: AnalysisResult
    ) -> tuple[ThreatExplanation, int]:
        """Generate explanation using Claude API.

        Args:
            result: Analysis result

        Returns:
            Tuple of (explanation, tokens_used)
        """
        # Build prompt based on verdict
        if result.verdict == "safe":
            prompt = build_safe_url_prompt(result)
        else:
            prompt = build_threat_analysis_prompt(result)

        start_time = time.time()
        self.usage_stats.total_requests += 1
        self.usage_stats.last_request_time = datetime.now(timezone.utc)

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        # Track token usage
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        self.usage_stats.input_tokens += input_tokens
        self.usage_stats.output_tokens += output_tokens
        self.usage_stats.total_tokens += input_tokens + output_tokens

        elapsed = time.time() - start_time
        logger.info(
            "Generated AI explanation",
            url=result.url,
            tokens=input_tokens + output_tokens,
            elapsed_ms=int(elapsed * 1000),
        )

        # Parse response
        response_text = response.content[0].text
        explanation_dict = parse_explanation_response(response_text)

        return (
            ThreatExplanation(**explanation_dict),
            input_tokens + output_tokens,
        )

    def _fallback_explanation(self, result: AnalysisResult) -> ExplainerResult:
        """Generate fallback explanation without API.

        Args:
            result: Analysis result

        Returns:
            ExplainerResult with rule-based explanation
        """
        # Generate explanation based on rules and features
        risk_factors = []

        if result.features.typosquat_target:
            risk_factors.append(f"Typosquatting detected: impersonating {result.features.typosquat_target}")

        if result.features.domain_age_days < 30:
            risk_factors.append(f"Recently registered domain ({result.features.domain_age_days} days old)")

        if not result.features.ssl_valid:
            risk_factors.append("Invalid or missing SSL certificate")

        if result.features.has_ip_address:
            risk_factors.append("URL uses IP address instead of domain name")

        if result.features.suspicious_tld:
            risk_factors.append("Uses suspicious top-level domain")

        if result.features.has_suspicious_keywords:
            risk_factors.append("Contains suspicious keywords commonly used in phishing")

        if result.features.redirect_count > 2:
            risk_factors.append(f"Multiple redirects ({result.features.redirect_count})")

        # Determine severity
        if result.verdict == "phishing":
            severity = "high"
            action = "Block this URL and report to your security team"
        elif result.verdict == "suspicious":
            severity = "medium"
            action = "Review this URL manually before proceeding"
        else:
            severity = "low"
            action = "No action required"

        explanation = ThreatExplanation(
            summary=f"This URL was classified as {result.verdict} with {result.confidence:.0%} confidence",
            explanation=(
                f"The URL {result.url} was analyzed using {len(result.matched_rules)} detection rules. "
                f"Based on the detected patterns, it was classified as {result.verdict}."
            ),
            risk_factors=risk_factors if risk_factors else ["No significant risk factors detected"],
            severity=severity,
            recommended_action=action,
            target_brand=result.features.typosquat_target,
        )

        return ExplainerResult(
            url=result.url,
            verdict=result.verdict,
            confidence=result.confidence,
            ai_explanation=explanation,
            analysis_timestamp=result.analysis_timestamp,
            cached=False,
        )

    def get_usage_stats(self) -> dict[str, Any]:
        """Get API usage statistics.

        Returns:
            Dictionary with usage stats
        """
        stats = self.usage_stats.to_dict()
        stats["cache_stats"] = self.cache.get_stats()
        return stats

    async def explain_batch(
        self, results: list[AnalysisResult]
    ) -> list[ExplainerResult]:
        """Generate explanations for multiple results.

        Args:
            results: List of analysis results

        Returns:
            List of explainer results
        """
        return [await self.explain(result) for result in results]
