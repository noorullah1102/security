"""Prompt templates for AI threat explanations."""

from typing import Any

from src.analyzer.models import AnalysisResult


SYSTEM_PROMPT = """You are a cybersecurity threat analyst specializing in phishing detection. Your role is to:

1. Analyze URL scan results and explain threats in plain language
2. Identify specific risk factors that indicate phishing or malicious intent
3. Provide actionable recommendations for users and security teams
4. Assign appropriate severity levels based on threat indicators

Severity Guidelines:
- CRITICAL: Confirmed phishing, credentials targeted, active campaign, brand impersonation
- HIGH: Strong phishing signals, typosquatting, recent domain registration, no SSL
- MEDIUM: Suspicious features present, needs manual review
- LOW: Minor concerns, likely safe but flagged for completeness

Always respond with valid JSON in the exact format requested. Be concise but thorough."""


def build_threat_analysis_prompt(result: AnalysisResult) -> str:
    """Build the prompt for threat analysis.

    Args:
        result: Analysis result from URL analyzer

    Returns:
        Formatted prompt string
    """
    features = result.features

    return f"""Analyze this URL scan result and provide a security assessment.

URL: {result.url}
Verdict: {result.verdict}
Confidence: {result.confidence:.2%}

FEATURES:
- Domain Age: {features.domain_age_days} days
- SSL Valid: {features.ssl_valid}
- SSL Issuer: {features.ssl_issuer or 'Unknown'}
- Redirect Count: {features.redirect_count}
- Typosquat Target: {features.typosquat_target or 'None'}
- Typosquat Distance: {features.typosquat_distance}
- Uses IP Address: {features.has_ip_address}
- URL Length: {features.url_length} characters
- Path Depth: {features.path_depth}
- Subdomain Count: {features.subdomain_count}
- Uses HTTPS: {features.has_https}
- Has Suspicious Keywords: {features.has_suspicious_keywords}
- Suspicious TLD: {features.suspicious_tld}

MATCHED RULES: {', '.join(result.matched_rules) if result.matched_rules else 'None'}

Provide a security assessment in the following JSON format:
{{
    "summary": "One sentence summary of the threat",
    "explanation": "Detailed explanation of why this URL is dangerous or safe",
    "risk_factors": ["list", "of", "specific", "risk", "factors"],
    "severity": "low|medium|high|critical",
    "recommended_action": "Specific action to take",
    "target_brand": "Brand being impersonated or null"
}}

Respond ONLY with valid JSON, no additional text."""


def build_safe_url_prompt(result: AnalysisResult) -> str:
    """Build a simplified prompt for safe URLs.

    Args:
        result: Analysis result for a safe URL

    Returns:
        Formatted prompt string
    """
    return f"""Analyze this URL scan result. The URL appears to be safe.

URL: {result.url}
Verdict: {result.verdict}
Confidence: {result.confidence:.2%}

Provide a brief assessment in JSON format:
{{
    "summary": "One sentence confirming the URL is safe",
    "explanation": "Brief explanation of why this URL appears legitimate",
    "risk_factors": [],
    "severity": "low",
    "recommended_action": "No action needed",
    "target_brand": null
}}

Respond ONLY with valid JSON."""


def parse_explanation_response(response_text: str) -> dict[str, Any]:
    """Parse Claude's response into structured explanation.

    Args:
        response_text: Raw response text from Claude

    Returns:
        Parsed explanation dictionary
    """
    import json

    # Try to extract JSON from response
    text = response_text.strip()

    # Remove markdown code blocks if present
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]

    if text.endswith("```"):
        text = text[:-3]

    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Return fallback explanation
        return {
            "summary": "Unable to generate AI explanation",
            "explanation": response_text,
            "risk_factors": [],
            "severity": "medium",
            "recommended_action": "Review manually",
            "target_brand": None,
        }

    # Validate required fields
    required_fields = ["summary", "explanation", "risk_factors", "severity", "recommended_action"]
    for field in required_fields:
        if field not in data:
            data[field] = get_default_value(field)

    # Ensure target_brand exists
    if "target_brand" not in data:
        data["target_brand"] = None

    # Validate severity
    valid_severities = {"low", "medium", "high", "critical"}
    if data["severity"] not in valid_severities:
        data["severity"] = "medium"

    return data


def get_default_value(field: str) -> Any:
    """Get default value for a missing field.

    Args:
        field: Field name

    Returns:
        Default value for the field
    """
    defaults = {
        "summary": "Analysis completed",
        "explanation": "Unable to generate detailed explanation",
        "risk_factors": [],
        "severity": "medium",
        "recommended_action": "Review manually",
        "target_brand": None,
    }
    return defaults.get(field, None)
