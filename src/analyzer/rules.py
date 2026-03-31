"""Rule-based phishing detection."""

import re
from dataclasses import dataclass, field
from typing import Literal

from structlog import get_logger

from src.analyzer.models import URLFeatures

logger = get_logger()


@dataclass
class RuleResult:
    """Result from a single rule check."""

    rule_name: str
    triggered: bool
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    score: float = 0.0  # Contribution to phishing score


@dataclass
class RulesVerdict:
    """Aggregated verdict from all rules."""

    verdict: Literal["safe", "phishing", "suspicious"]
    confidence: float
    triggered_rules: list[str]
    risk_score: float
    rule_results: list[RuleResult] = field(default_factory=list)


# Popular brands commonly targeted by phishing
POPULAR_BRANDS = {
    "google": {"google.com", "gmail.com", "googleapis.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "twitter": {"twitter.com", "x.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "chase": {"chase.com", "jpmorgan.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citibank.com", "citi.com"},
    "yahoo": {"yahoo.com", "yahoomail.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "steam": {"steampowered.com"},
}

# Suspicious URL patterns
SUSPICIOUS_PATTERNS = [
    (r"@.*@", "Double @ symbol - credential injection attempt"),
    (r"//[^/]*@", "Credentials in URL"),
    (r"\.php\?.*=", "PHP script with query parameter"),
    (r"data:text/html", "Data URI with HTML content"),
    (r"javascript:", "JavaScript protocol"),
    (r"vbscript:", "VBScript protocol"),
    (r"file://", "Local file protocol"),
    (r"\\\\", "UNC path"),
]

# High-risk URL patterns
HIGH_RISK_PATTERNS = [
    (r"login.*\.(?:tk|ml|ga|cf|gq)", "Login page on free TLD"),
    (r"secure.*\.(?:tk|ml|ga|cf|gq)", "Secure page on free TLD"),
    (r"verify.*\.(?:tk|ml|ga|cf|gq)", "Verification page on free TLD"),
    (r"update.*\.(?:tk|ml|ga|cf|gq)", "Update page on free TLD"),
    (r"account.*\.(?:tk|ml|ga|cf|gq)", "Account page on free TLD"),
]


class RuleEngine:
    """Rule-based phishing detection engine."""

    def __init__(
        self,
        typosquat_threshold: int = 2,
        domain_age_suspicious_days: int = 30,
        max_url_length: int = 150,
    ):
        """Initialize the rule engine.

        Args:
            typosquat_threshold: Maximum Levenshtein distance for typosquatting
            domain_age_suspicious_days: Age below which domains are suspicious
            max_url_length: URL length above which URLs are suspicious
        """
        self.typosquat_threshold = typosquat_threshold
        self.domain_age_suspicious_days = domain_age_suspicious_days
        self.max_url_length = max_url_length

    def evaluate(self, features: URLFeatures, url: str) -> RulesVerdict:
        """Evaluate URL against all rules.

        Args:
            features: Extracted URL features
            url: Original URL string

        Returns:
            RulesVerdict with aggregated result
        """
        rule_results: list[RuleResult] = []

        # Run all rule checks
        rule_results.append(self._check_typosquatting(features))
        rule_results.append(self._check_domain_age(features))
        rule_results.append(self._check_ssl(features))
        rule_results.append(self._check_redirects(features))
        rule_results.append(self._check_ip_address(features))
        rule_results.append(self._check_url_length(features))
        rule_results.append(self._check_suspicious_keywords(features))
        rule_results.append(self._check_subdomains(features))
        rule_results.append(self._check_suspicious_tld(features))
        rule_results.append(self._check_suspicious_patterns(url))
        rule_results.append(self._check_protocol(features))

        # Aggregate results
        triggered_rules = [r.rule_name for r in rule_results if r.triggered]
        total_score = sum(r.score for r in rule_results if r.triggered)

        # Normalize score to 0-1 range
        max_possible_score = 15.0  # Maximum possible score from all rules
        normalized_score = min(total_score / max_possible_score, 1.0)

        # Determine verdict based on score
        verdict, confidence = self._score_to_verdict(normalized_score, len(triggered_rules))

        return RulesVerdict(
            verdict=verdict,
            confidence=confidence,
            triggered_rules=triggered_rules,
            risk_score=normalized_score,
            rule_results=rule_results,
        )

    def _check_typosquatting(self, features: URLFeatures) -> RuleResult:
        """Check for typosquatting."""
        if features.typosquat_target and features.typosquat_distance <= self.typosquat_threshold:
            return RuleResult(
                rule_name="typosquatting",
                triggered=True,
                severity="high",
                description=f"Domain typosquats {features.typosquat_target} (distance: {features.typosquat_distance})",
                score=3.0,
            )
        return RuleResult(
            rule_name="typosquatting",
            triggered=False,
            severity="low",
            description="No typosquatting detected",
        )

    def _check_domain_age(self, features: URLFeatures) -> RuleResult:
        """Check domain registration age."""
        if features.domain_age_days == 0:
            # Unknown age - slight concern
            return RuleResult(
                rule_name="domain_age",
                triggered=False,
                severity="low",
                description="Domain age unknown",
                score=0.5,
            )
        if features.domain_age_days < self.domain_age_suspicious_days:
            return RuleResult(
                rule_name="domain_age",
                triggered=True,
                severity="high",
                description=f"Domain registered {features.domain_age_days} days ago",
                score=2.5,
            )
        return RuleResult(
            rule_name="domain_age",
            triggered=False,
            severity="low",
            description=f"Domain age: {features.domain_age_days} days",
        )

    def _check_ssl(self, features: URLFeatures) -> RuleResult:
        """Check SSL certificate validity."""
        if not features.has_https:
            return RuleResult(
                rule_name="ssl_certificate",
                triggered=True,
                severity="medium",
                description="No HTTPS - insecure connection",
                score=1.5,
            )
        if not features.ssl_valid:
            return RuleResult(
                rule_name="ssl_certificate",
                triggered=True,
                severity="high",
                description="Invalid SSL certificate",
                score=2.0,
            )
        return RuleResult(
            rule_name="ssl_certificate",
            triggered=False,
            severity="low",
            description=f"Valid SSL from {features.ssl_issuer or 'unknown'}",
        )

    def _check_redirects(self, features: URLFeatures) -> RuleResult:
        """Check redirect chain."""
        if features.redirect_count >= 3:
            return RuleResult(
                rule_name="redirects",
                triggered=True,
                severity="high",
                description=f"Multiple redirects ({features.redirect_count})",
                score=2.0,
            )
        if features.redirect_count >= 1:
            return RuleResult(
                rule_name="redirects",
                triggered=True,
                severity="medium",
                description=f"URL redirects ({features.redirect_count} times)",
                score=1.0,
            )
        return RuleResult(
            rule_name="redirects",
            triggered=False,
            severity="low",
            description="No redirects",
        )

    def _check_ip_address(self, features: URLFeatures) -> RuleResult:
        """Check if URL uses IP address."""
        if features.has_ip_address:
            return RuleResult(
                rule_name="ip_address",
                triggered=True,
                severity="high",
                description="URL uses IP address instead of domain",
                score=2.5,
            )
        return RuleResult(
            rule_name="ip_address",
            triggered=False,
            severity="low",
            description="URL uses domain name",
        )

    def _check_url_length(self, features: URLFeatures) -> RuleResult:
        """Check URL length."""
        if features.url_length > self.max_url_length:
            return RuleResult(
                rule_name="url_length",
                triggered=True,
                severity="medium",
                description=f"Very long URL ({features.url_length} characters)",
                score=1.0,
            )
        return RuleResult(
            rule_name="url_length",
            triggered=False,
            severity="low",
            description=f"URL length: {features.url_length}",
        )

    def _check_suspicious_keywords(self, features: URLFeatures) -> RuleResult:
        """Check for suspicious keywords."""
        if features.has_suspicious_keywords:
            return RuleResult(
                rule_name="suspicious_keywords",
                triggered=True,
                severity="medium",
                description="URL contains suspicious keywords",
                score=1.5,
            )
        return RuleResult(
            rule_name="suspicious_keywords",
            triggered=False,
            severity="low",
            description="No suspicious keywords",
        )

    def _check_subdomains(self, features: URLFeatures) -> RuleResult:
        """Check subdomain count."""
        if features.subdomain_count >= 4:
            return RuleResult(
                rule_name="subdomains",
                triggered=True,
                severity="high",
                description=f"Excessive subdomains ({features.subdomain_count})",
                score=2.0,
            )
        if features.subdomain_count >= 2:
            return RuleResult(
                rule_name="subdomains",
                triggered=True,
                severity="medium",
                description=f"Multiple subdomains ({features.subdomain_count})",
                score=1.0,
            )
        return RuleResult(
            rule_name="subdomains",
            triggered=False,
            severity="low",
            description=f"Subdomain count: {features.subdomain_count}",
        )

    def _check_suspicious_tld(self, features: URLFeatures) -> RuleResult:
        """Check for suspicious TLD."""
        if features.suspicious_tld:
            return RuleResult(
                rule_name="suspicious_tld",
                triggered=True,
                severity="high",
                description="Domain uses suspicious TLD",
                score=2.0,
            )
        return RuleResult(
            rule_name="suspicious_tld",
            triggered=False,
            severity="low",
            description="TLD appears legitimate",
        )

    def _check_suspicious_patterns(self, url: str) -> RuleResult:
        """Check for suspicious URL patterns."""
        url_lower = url.lower()

        for pattern, description in HIGH_RISK_PATTERNS:
            if re.search(pattern, url_lower):
                return RuleResult(
                    rule_name="suspicious_pattern",
                    triggered=True,
                    severity="critical",
                    description=description,
                    score=3.5,
                )

        for pattern, description in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url_lower):
                return RuleResult(
                    rule_name="suspicious_pattern",
                    triggered=True,
                    severity="high",
                    description=description,
                    score=2.5,
                )

        return RuleResult(
            rule_name="suspicious_pattern",
            triggered=False,
            severity="low",
            description="No suspicious patterns",
        )

    def _check_protocol(self, features: URLFeatures) -> RuleResult:
        """Check URL protocol."""
        if not features.has_https:
            return RuleResult(
                rule_name="protocol",
                triggered=True,
                severity="medium",
                description="Uses insecure HTTP protocol",
                score=1.0,
            )
        return RuleResult(
            rule_name="protocol",
            triggered=False,
            severity="low",
            description="Uses HTTPS protocol",
        )

    def _score_to_verdict(
        self, score: float, triggered_count: int
    ) -> tuple[Literal["safe", "phishing", "suspicious"], float]:
        """Convert risk score to verdict.

        Args:
            score: Normalized risk score (0-1)
            triggered_count: Number of triggered rules

        Returns:
            Tuple of (verdict, confidence)
        """
        # High confidence phishing
        if score >= 0.6 or triggered_count >= 5:
            return "phishing", min(0.7 + score * 0.3, 0.99)

        # Suspicious - needs review
        if score >= 0.3 or triggered_count >= 2:
            return "suspicious", 0.5 + score * 0.3

        # Safe with low confidence if any rules triggered
        if triggered_count > 0:
            return "safe", 0.6 - score * 0.2

        # Safe with high confidence
        return "safe", 0.85 - score * 0.1
