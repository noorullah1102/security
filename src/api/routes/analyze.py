"""URL Analysis API endpoints."""

import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from structlog import get_logger

from src.api.middleware.auth import verify_api_key
from src.api.schemas.analyze import (
    AIExplanationResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    URLFeaturesResponse,
)
from src.analyzer.models import AnalysisResult
from src.analyzer.service import URLAnalyzer
from src.db.database import DatabaseManager
from src.db.repository import ScanRepository
from src.explainer.claude_client import AIThreatExplainer

router = APIRouter(prefix="/api/v1", tags=["Analysis"])
logger = get_logger()

# Initialize analyzer and explainer (will be dependency-injected later)
_analyzer: URLAnalyzer | None = None
_explainer: AIThreatExplainer | None = None


def get_analyzer() -> URLAnalyzer:
    """Get or create URL analyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = URLAnalyzer()
    return _analyzer


def get_explainer() -> AIThreatExplainer:
    """Get or create AI explainer instance."""
    global _explainer
    if _explainer is None:
        _explainer = AIThreatExplainer()
    return _explainer


def get_scan_repository() -> ScanRepository:
    """Get scan repository instance."""
    db = DatabaseManager.get_database()
    return ScanRepository(db)


async def _get_ai_explanation(
    result: AnalysisResult,
    explainer: AIThreatExplainer,
) -> AIExplanationResponse | None:
    """Get AI explanation for analysis result.

    Args:
        result: Analysis result from analyzer
        explainer: AI explainer instance

    Returns:
        AIExplanationResponse or None if unavailable
    """
    if not explainer.is_available():
        # Return fallback explanation
        severity = "high" if result.verdict == "phishing" else "medium"
        return AIExplanationResponse(
            summary=f"This URL was classified as {result.verdict}",
            explanation="AI explanation service unavailable. Manual review recommended.",
            risk_factors=[],
            severity=severity,
            recommended_action="Review URL manually",
            target_brand=result.features.typosquat_target,
        )

    try:
        explainer_result = await explainer.explain(result)
        explanation = explainer_result.ai_explanation

        return AIExplanationResponse(
            summary=explanation.summary,
            explanation=explanation.explanation,
            risk_factors=explanation.risk_factors,
            severity=explanation.severity,
            recommended_action=explanation.recommended_action,
            target_brand=explanation.target_brand,
        )
    except Exception:
        # Return fallback on error
        severity = "high" if result.verdict == "phishing" else "medium"
        return AIExplanationResponse(
            summary=f"This URL was classified as {result.verdict}",
            explanation="Unable to generate AI explanation. Manual review recommended.",
            risk_factors=[],
            severity=severity,
            recommended_action="Review URL manually",
            target_brand=result.features.typosquat_target,
        )


def _result_to_response(
    result: AnalysisResult,
    ai_explanation: AIExplanationResponse | None = None,
) -> AnalyzeResponse:
    """Convert AnalysisResult to API response.

    Args:
        result: Analysis result from analyzer
        ai_explanation: Pre-generated AI explanation (optional)

    Returns:
        AnalyzeResponse for API
    """
    features = URLFeaturesResponse(
        domain_age_days=result.features.domain_age_days,
        ssl_valid=result.features.ssl_valid,
        ssl_issuer=result.features.ssl_issuer,
        redirect_count=result.features.redirect_count,
        redirect_chain=result.features.redirect_chain,
        typosquat_target=result.features.typosquat_target,
        typosquat_distance=result.features.typosquat_distance,
        has_ip_address=result.features.has_ip_address,
        url_length=result.features.url_length,
        path_depth=result.features.path_depth,
        has_suspicious_keywords=result.features.has_suspicious_keywords,
        subdomain_count=result.features.subdomain_count,
        has_https=result.features.has_https,
        suspicious_tld=result.features.suspicious_tld,
    )

    return AnalyzeResponse(
        url=result.url,
        verdict=result.verdict,
        confidence=result.confidence,
        features=features,
        feature_importance=result.feature_importance,
        matched_rules=result.matched_rules,
        ai_explanation=ai_explanation,
        analysis_timestamp=result.analysis_timestamp,
        cached=False,
    )


def _save_scan(
    repo: ScanRepository,
    result: AnalysisResult,
    ai_explanation: AIExplanationResponse | None = None,
) -> str:
    """Save scan result to database.

    Args:
        repo: Scan repository
        result: Analysis result
        ai_explanation: AI explanation if available

    Returns:
        Scan ID
    """
    return repo.save(
        url=result.url,
        verdict=result.verdict,
        confidence=result.confidence,
        severity=ai_explanation.severity if ai_explanation else None,
        features={
            "domain_age_days": result.features.domain_age_days,
            "ssl_valid": result.features.ssl_valid,
            "redirect_count": result.features.redirect_count,
            "typosquat_target": result.features.typosquat_target,
            "typosquat_distance": result.features.typosquat_distance,
            "has_suspicious_keywords": result.features.has_suspicious_keywords,
            "url_length": result.features.url_length,
            "path_depth": result.features.path_depth,
            "subdomain_count": result.features.subdomain_count,
            "has_https": result.features.has_https,
            "suspicious_tld": result.features.suspicious_tld,
            "has_ip_address": result.features.has_ip_address,
        },
        ai_explanation=ai_explanation.model_dump() if ai_explanation else None,
        target_brand=result.features.typosquat_target,
    )


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL",
    description="Analyze a single URL for phishing indicators",
)
async def analyze_url(
    request: AnalyzeRequest,
    api_key: Annotated[str, Depends(verify_api_key)],
    analyzer: Annotated[URLAnalyzer, Depends(get_analyzer)],
    explainer: Annotated[AIThreatExplainer, Depends(get_explainer)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
) -> AnalyzeResponse:
    """Analyze a URL for phishing indicators.

    Analysis Flow:
    1. Check threat feeds FIRST (URLhaus, OpenPhish, Reddit, PhishTank, VirusTotal, Google Safe Browsing)
    2. If found in feeds → Return verdict with AI explanation
    3. If not found → Use ML model + rules for analysis

    Requires valid API key in X-API-Key header.

    Returns analysis including:
    - Verdict (safe/phishing/suspicious)
    - Confidence score
    - Extracted features
    - Feature importance
    - Matched detection rules
    - Optional AI-generated explanation
    - Feed check results (if found)
    """
    threat_checker = None
    try:
        # Step 1: Check threat feeds FIRST (fast)
        from src.analyzer.threat_checker import ThreatFeedChecker
        from datetime import datetime
        from src.analyzer.models import AnalysisResult, URLFeatures

        threat_checker = ThreatFeedChecker()
        threat_result = await threat_checker.check_all_sources(request.url)

        # Step 2: If found in feeds, return immediately with AI explanation
        if threat_result.is_known_threat:
            # Create minimal result from feed data
            features = URLFeatures(
                domain_age_days=0,
                ssl_valid=False,
                ssl_issuer=None,
                redirect_count=0,
                redirect_chain=[],
                typosquat_target=threat_result.target_brand,
                typosquat_distance=0,
                has_ip_address=False,
                url_length=len(request.url),
                path_depth=request.url.count('/') - 2,
                has_suspicious_keywords=True,
                subdomain_count=0,
                has_https=request.url.startswith('https'),
                suspicious_tld=False,
            )

            result = AnalysisResult(
                url=request.url,
                verdict="phishing",
                confidence=0.98,
                features=features,
                feature_importance={"threat_feed_match": 1.0},
                analysis_timestamp=datetime.utcnow(),
                matched_rules=[f"known_threat:{src}" for src in threat_result.sources],
                threat_feed_result=threat_result,
            )

            # Get AI explanation for feed result
            ai_explanation = None
            if request.include_ai_explanation:
                ai_explanation = await _get_ai_explanation(result, explainer)

            # Save to database
            _save_scan(repo, result, ai_explanation)

            return _result_to_response(result, ai_explanation)

        # Step 3: Not found in feeds, use full ML + rules analysis
        # Skip feeds in analyzer since we already checked them
        result = await analyzer.analyze_async(request.url, skip_feeds=True)

        # Get AI explanation if requested
        ai_explanation = None
        if request.include_ai_explanation:
            ai_explanation = await _get_ai_explanation(result, explainer)

        # Save to database
        _save_scan(repo, result, ai_explanation)

        return _result_to_response(result, ai_explanation)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Analysis failed", url=request.url, error=str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )
    finally:
        if threat_checker:
            await threat_checker.close()


@router.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch Analyze URLs",
    description="Analyze multiple URLs in a single request (max 100)",
)
async def analyze_batch(
    request: BatchAnalyzeRequest,
    api_key: Annotated[str, Depends(verify_api_key)],
    analyzer: Annotated[URLAnalyzer, Depends(get_analyzer)],
    explainer: Annotated[AIThreatExplainer, Depends(get_explainer)],
    repo: Annotated[ScanRepository, Depends(get_scan_repository)],
) -> BatchAnalyzeResponse:
    """Analyze multiple URLs for phishing indicators.

    Processes up to 100 URLs in a single request.
    AI explanations are disabled by default for performance.
    """
    start_time = time.time()
    results: list[AnalyzeResponse] = []
    failed = 0

    for url in request.urls:
        try:
            result = await analyzer.analyze_async(url)

            # Get AI explanation if requested
            ai_explanation = None
            if request.include_ai_explanation:
                ai_explanation = await _get_ai_explanation(result, explainer)

            # Save to database
            _save_scan(repo, result, ai_explanation)

            results.append(_result_to_response(result, ai_explanation))
        except Exception:
            # Log error but continue processing
            failed += 1
            continue

    processing_time = (time.time() - start_time) * 1000

    return BatchAnalyzeResponse(
        results=results,
        processed=len(results),
        failed=failed,
        processing_time_ms=processing_time,
    )
