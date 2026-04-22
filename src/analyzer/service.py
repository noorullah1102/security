"""URL Analyzer service combining threat feeds, ML classification, and rule-based detection."""

import asyncio
from datetime import datetime
from typing import Literal

from structlog import get_logger

from src.analyzer.features import FeatureExtractor
from src.analyzer.models import AnalysisResult, URLFeatures
from src.analyzer.rules import RuleEngine, RulesVerdict
from src.analyzer.threat_checker import ThreatFeedChecker, ThreatCheckResult

logger = get_logger()


class URLAnalyzer:
    """Main URL analyzer combining threat feeds, ML, and rule-based detection.

    Analysis Flow:
    1. Check threat feeds first (URLhaus, OpenPhish, Reddit, PhishTank)
    2. If found in feeds → Report as known threat with source
    3. If not found → Use ML model + rules for prediction
    4. Always extract domain details
    """

    def __init__(
        self,
        feature_extractor: FeatureExtractor | None = None,
        rule_engine: RuleEngine | None = None,
        use_ml: bool = True,
        ml_weight: float = 0.6,
        check_feeds: bool = True,
    ):
        """Initialize the URL analyzer.

        Args:
            feature_extractor: Feature extraction module
            rule_engine: Rule-based detection engine
            use_ml: Whether to use ML classifier (default: True)
            ml_weight: Weight given to ML vs rules (0-1, default: 0.6)
            check_feeds: Whether to check threat feeds first (default: True)
        """
        self.feature_extractor = feature_extractor or FeatureExtractor()
        self.rule_engine = rule_engine or RuleEngine()
        self.use_ml = use_ml
        self.ml_weight = ml_weight
        self.check_feeds_enabled = check_feeds
        self.ml_classifier = None
        self.fast_feature_extractor = None
        self.threat_checker = ThreatFeedChecker()

        # Load ML classifier if enabled
        if self.use_ml:
            self._load_ml_classifier()

    def _load_ml_classifier(self) -> None:
        """Load ML classifier from disk."""
        # Try Kaggle-trained model first (best performance with real data)
        try:
            from src.ml.train_with_kaggle import KaggleFeatureExtractor
            import joblib

            model_path = "models/classifier_kaggle.pkl"
            if joblib.load:
                import os
                if os.path.exists(model_path):
                    self.ml_classifier = joblib.load(model_path)
                    self.fast_feature_extractor = KaggleFeatureExtractor()
                    self._model_type = "kaggle"
                    logger.info("Kaggle-trained ML classifier loaded successfully", path=model_path)
                    return
        except Exception as e:
            logger.debug("Kaggle model not available", error=str(e))

        # Try real-data model next
        try:
            from src.ml.train_real import URLClassifier, FastFeatureExtractor

            classifier = URLClassifier(model_path="models/classifier_real.pkl")
            if classifier.load():
                self.ml_classifier = classifier
                self.fast_feature_extractor = FastFeatureExtractor()
                self._model_type = "real"
                logger.info("Real-data ML classifier loaded successfully")
                return
        except Exception as e:
            logger.debug("Real-data model not available", error=str(e))

        # Fall back to synthetic model
        try:
            from src.ml.train_fast import URLClassifier as SyntheticClassifier

            classifier = SyntheticClassifier()
            if classifier.load():
                self.ml_classifier = classifier
                self._model_type = "synthetic"
                logger.info("Synthetic ML classifier loaded successfully")
                return
        except Exception as e:
            logger.warning("Failed to load ML classifier", error=str(e))

        logger.warning("No ML classifier found, using rules only")
        self.use_ml = False

    def analyze(self, url: str, skip_feeds: bool = False) -> AnalysisResult:
        """Analyze a URL for phishing indicators.

        Flow:
        1. Check threat feeds (URLhaus, OpenPhish, Reddit, PhishTank)
        2. If found → Return as known threat
        3. If not found → Use ML + rules
        4. Extract domain details

        Args:
            url: URL to analyze
            skip_feeds: Skip threat feed check (for testing)

        Returns:
            AnalysisResult with verdict, confidence, and features
        """
        logger.info("Analyzing URL", url=url)

        # Extract features (full analysis with network calls for domain details)
        features = self.feature_extractor.extract(url)

        # Initialize threat check result
        threat_result = None

        # Step 1: Check threat feeds first
        if self.check_feeds_enabled and not skip_feeds:
            try:
                threat_result = asyncio.run(self.threat_checker.check_all_sources(url))

                if threat_result.is_known_threat:
                    logger.info(
                        "URL found in threat feeds",
                        url=url,
                        sources=threat_result.sources
                    )
                    # Return as known threat with high confidence
                    return AnalysisResult(
                        url=url,
                        verdict="phishing",
                        confidence=0.98,
                        features=features,
                        feature_importance={"threat_feed_match": 1.0},
                        analysis_timestamp=datetime.utcnow(),
                        matched_rules=[f"known_threat:{src}" for src in threat_result.sources],
                        threat_feed_result=threat_result,
                    )
            except Exception as e:
                logger.warning("Threat feed check failed", error=str(e))

        # Step 2: Not found in feeds, use ML + rules
        rules_verdict = self.rule_engine.evaluate(features, url)

        # Get ML prediction if available
        ml_verdict = None
        ml_confidence = 0.0
        ml_feature_importance = {}

        if self.use_ml and self.ml_classifier is not None:
            try:
                # Use fast feature extractor for real-data model, or fall back
                if self.fast_feature_extractor is not None:
                    # Kaggle or real-data model with lexical features
                    fast_features = self.fast_feature_extractor.extract(url)
                    feature_vector = self.fast_feature_extractor.to_vector(fast_features)
                else:
                    # Synthetic model with full features
                    feature_vector = features.to_feature_vector()

                # Handle sklearn model (from Kaggle training) vs URLClassifier
                if hasattr(self.ml_classifier, 'predict_proba'):
                    # Sklearn model - returns probability
                    import numpy as np
                    feature_vector_np = np.array(feature_vector).reshape(1, -1)
                    proba = self.ml_classifier.predict_proba(feature_vector_np)[0]
                    phishing_proba = proba[1] if len(proba) > 1 else proba[0]
                    ml_verdict = "phishing" if phishing_proba > 0.5 else "safe"
                    ml_confidence = float(max(phishing_proba, 1 - phishing_proba))

                    # Get feature importance if available
                    if hasattr(self.ml_classifier, 'feature_importances_'):
                        ml_feature_importance = {
                            f"feature_{i}": float(imp)
                            for i, imp in enumerate(self.ml_classifier.feature_importances_)
                        }
                    else:
                        ml_feature_importance = {}
                else:
                    # URLClassifier - has custom predict method
                    ml_verdict, ml_confidence = self.ml_classifier.predict(feature_vector)
                    ml_feature_importance = self.ml_classifier.get_feature_importance()
            except Exception as e:
                logger.warning("ML prediction failed", error=str(e))
                ml_verdict = None

        # Combine verdicts
        final_verdict, final_confidence = self._combine_verdicts(
            rules_verdict, ml_verdict, ml_confidence
        )

        # Combine feature importance from both sources
        feature_importance = self._combine_feature_importance(
            features, rules_verdict, ml_feature_importance
        )

        return AnalysisResult(
            url=url,
            verdict=final_verdict,
            confidence=final_confidence,
            features=features,
            feature_importance=feature_importance,
            analysis_timestamp=datetime.utcnow(),
            matched_rules=rules_verdict.triggered_rules,
            threat_feed_result=threat_result,
        )

    async def analyze_async(self, url: str, skip_feeds: bool = False) -> AnalysisResult:
        """Async version of analyze for use in async contexts.

        Args:
            url: URL to analyze
            skip_feeds: Skip threat feed check

        Returns:
            AnalysisResult
        """
        logger.info("Analyzing URL (async)", url=url)

        # Extract features
        features = self.feature_extractor.extract(url)

        # Initialize threat check result
        threat_result = None

        # Check threat feeds
        if self.check_feeds_enabled and not skip_feeds:
            try:
                threat_result = await self.threat_checker.check_all_sources(url)

                if threat_result.is_known_threat:
                    logger.info(
                        "URL found in threat feeds",
                        url=url,
                        sources=threat_result.sources
                    )
                    return AnalysisResult(
                        url=url,
                        verdict="phishing",
                        confidence=0.98,
                        features=features,
                        feature_importance={"threat_feed_match": 1.0},
                        analysis_timestamp=datetime.utcnow(),
                        matched_rules=[f"known_threat:{src}" for src in threat_result.sources],
                        threat_feed_result=threat_result,
                    )
            except Exception as e:
                logger.warning("Threat feed check failed", error=str(e))

        # Use ML + rules
        rules_verdict = self.rule_engine.evaluate(features, url)

        ml_verdict = None
        ml_confidence = 0.0
        ml_feature_importance = {}

        if self.use_ml and self.ml_classifier is not None:
            try:
                if self.fast_feature_extractor is not None:
                    fast_features = self.fast_feature_extractor.extract(url)
                    feature_vector = self.fast_feature_extractor.to_vector(fast_features)
                else:
                    feature_vector = features.to_feature_vector()

                # Handle sklearn model (from Kaggle training) vs URLClassifier
                if hasattr(self.ml_classifier, 'predict_proba'):
                    # Sklearn model - returns probability
                    import numpy as np
                    feature_vector_np = np.array(feature_vector).reshape(1, -1)
                    proba = self.ml_classifier.predict_proba(feature_vector_np)[0]
                    phishing_proba = proba[1] if len(proba) > 1 else proba[0]
                    ml_verdict = "phishing" if phishing_proba > 0.5 else "safe"
                    ml_confidence = float(max(phishing_proba, 1 - phishing_proba))

                    if hasattr(self.ml_classifier, 'feature_importances_'):
                        ml_feature_importance = {
                            f"feature_{i}": float(imp)
                            for i, imp in enumerate(self.ml_classifier.feature_importances_)
                        }
                    else:
                        ml_feature_importance = {}
                else:
                    # URLClassifier - has custom predict method
                    ml_verdict, ml_confidence = self.ml_classifier.predict(feature_vector)
                    ml_feature_importance = self.ml_classifier.get_feature_importance()
            except Exception as e:
                logger.warning("ML prediction failed", error=str(e))
                ml_verdict = None

        final_verdict, final_confidence = self._combine_verdicts(
            rules_verdict, ml_verdict, ml_confidence
        )

        feature_importance = self._combine_feature_importance(
            features, rules_verdict, ml_feature_importance
        )

        return AnalysisResult(
            url=url,
            verdict=final_verdict,
            confidence=final_confidence,
            features=features,
            feature_importance=feature_importance,
            analysis_timestamp=datetime.utcnow(),
            matched_rules=rules_verdict.triggered_rules,
            threat_feed_result=threat_result,
        )

    def analyze_batch(self, urls: list[str]) -> list[AnalysisResult]:
        """Analyze multiple URLs.

        Args:
            urls: List of URLs to analyze

        Returns:
            List of AnalysisResult objects
        """
        logger.info("Analyzing batch of URLs", count=len(urls))
        return [self.analyze(url) for url in urls]

    def _combine_verdicts(
        self,
        rules_verdict: RulesVerdict,
        ml_verdict: str | None,
        ml_confidence: float,
    ) -> tuple[Literal["safe", "phishing", "suspicious"], float]:
        """Combine rule-based and ML verdicts.

        Args:
            rules_verdict: Verdict from rule engine
            ml_verdict: Verdict from ML classifier (or None)
            ml_confidence: Confidence from ML classifier

        Returns:
            Tuple of (final_verdict, final_confidence)
        """
        # If no ML verdict, use rules only
        if ml_verdict is None:
            return rules_verdict.verdict, rules_verdict.confidence

        # Convert ML verdict to score (0-1, where higher = more likely phishing)
        ml_score = ml_confidence if ml_verdict == "phishing" else 1 - ml_confidence

        # Convert rules verdict to score
        rules_score = rules_verdict.risk_score

        # Weighted combination
        combined_score = (
            self.ml_weight * ml_score + (1 - self.ml_weight) * rules_score
        )

        # Determine final verdict based on combined score
        if combined_score >= 0.6:
            final_verdict = "phishing"
            final_confidence = min(0.7 + combined_score * 0.29, 0.99)
        elif combined_score >= 0.3:
            final_verdict = "suspicious"
            final_confidence = 0.5 + combined_score * 0.2
        else:
            final_verdict = "safe"
            final_confidence = 0.7 + (1 - combined_score) * 0.25

        # If rules detected critical patterns, override to phishing
        if "suspicious_pattern" in rules_verdict.triggered_rules:
            final_verdict = "phishing"
            final_confidence = max(final_confidence, 0.9)

        return final_verdict, final_confidence

    def _combine_feature_importance(
        self,
        features: URLFeatures,
        rules_verdict: RulesVerdict,
        ml_importance: dict[str, float],
    ) -> dict[str, float]:
        """Combine feature importance from rules and ML model.

        Args:
            features: Extracted features
            rules_verdict: Result from rule engine
            ml_importance: Feature importance from ML model

        Returns:
            Combined feature importance dictionary
        """
        # Get rule-based importance
        rules_importance = self._calculate_rule_importance(rules_verdict)

        # If no ML importance, use rules only
        if not ml_importance:
            return rules_importance

        # Combine with ML weight
        combined = {}
        all_features = set(rules_importance.keys()) | set(ml_importance.keys())

        for feature in all_features:
            rule_val = rules_importance.get(feature, 0.0)
            ml_val = ml_importance.get(feature, 0.0)
            combined[feature] = (
                self.ml_weight * ml_val + (1 - self.ml_weight) * rule_val
            )

        # Normalize
        max_val = max(combined.values()) if combined else 1.0
        if max_val > 0:
            combined = {k: v / max_val for k, v in combined.items()}

        return combined

    def _calculate_rule_importance(self, rules_verdict: RulesVerdict) -> dict[str, float]:
        """Calculate feature importance based on rule contributions.

        Args:
            rules_verdict: Result from rule engine

        Returns:
            Dictionary of feature names to importance scores
        """
        # Map rule names to features they depend on
        rule_feature_map = {
            "typosquatting": ["typosquat_distance"],
            "domain_age": ["domain_age_days"],
            "ssl_certificate": ["ssl_valid", "has_https"],
            "redirects": ["redirect_count"],
            "ip_address": ["has_ip_address"],
            "url_length": ["url_length"],
            "suspicious_keywords": ["has_suspicious_keywords"],
            "subdomains": ["subdomain_count"],
            "suspicious_tld": ["suspicious_tld"],
            "protocol": ["has_https"],
        }

        # Initialize importance scores
        importance: dict[str, float] = {name: 0.0 for name in [
            "domain_age_days", "ssl_valid", "redirect_count", "typosquat_distance",
            "has_ip_address", "url_length", "path_depth", "has_suspicious_keywords",
            "subdomain_count", "has_https", "suspicious_tld",
        ]}

        # Add contribution from each triggered rule
        for rule_result in rules_verdict.rule_results:
            if rule_result.triggered:
                related_features = rule_feature_map.get(rule_result.rule_name, [])
                for feature_name in related_features:
                    if feature_name in importance:
                        importance[feature_name] += rule_result.score / max(len(related_features), 1)

        # Normalize importance scores
        max_importance = max(importance.values()) if importance else 1.0
        if max_importance > 0:
            importance = {k: v / max_importance for k, v in importance.items()}

        return importance
