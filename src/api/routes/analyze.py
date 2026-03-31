"""URL Analysis API endpoints."""

import time
from datetime import datetime
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status

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
    from src.db.models import ScanRecord

    scan = ScanRecord(
        id=str(uuid4()),
        url=result.url,
        verdict=result.verdict,
        confidence=result.confidence,
        severity=ai_explanation.severity if ai_explanation else None,
        features={
            "domain_age_days": result.features.domain_age_days,
            "ssl_valid": result.features.ssl_valid,
            "redirect_count": result.features.redirect_count,
            "typosquat_target": result.features.typosquat_target,
            "has_suspicious_keywords": result.features.has_suspicious_keywords,
            "url_length": result.features.url_length,
            "has_https": result.features.has_https,
        },
        ai_explanation=ai_explanation.model_dump() if ai_explanation else None,
        target_brand=result.features.typosquat_target,
        created_at=datetime.utcnow(),
    )

    repo.save(scan)
    return scan.id


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

    Requires valid API key in X-API-Key header.

    Returns analysis including:
    - Verdict (safe/phishing/suspicious)
    - Confidence score
    - Extracted features
    - Feature importance
    - Matched detection rules
    - Optional AI-generated explanation
    """
    try:
        result = analyzer.analyze(request.url)

        # Get AI explanation if requested
        ai_explanation = None
        if request.include_ai_explanation:
            ai_explanation = await _get_ai_explanation(result, explainer)

        # Save to database
        _save_scan(repo, result, ai_explanation)

        return _result_to_response(result, ai_explanation)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )


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
            result = analyzer.analyze(url)

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
