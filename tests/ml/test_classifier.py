"""Tests for ML classifier."""

import pytest
from pathlib import Path
import joblib
import numpy as np

from src.ml.train_fast import URLClassifier, generate_synthetic_dataset, features_to_array


class TestURLClassifier:
    """Tests for URLClassifier class."""

    @pytest.fixture
    def classifier(self):
        """Create a classifier instance with loaded model."""
        clf = URLClassifier()
        clf.load()
        return clf

    @pytest.fixture
    def phishing_features(self):
        """Feature vector typical of phishing URLs."""
        return [
            5,      # domain_age_days (young)
            False,  # ssl_valid
            3,      # redirect_count (multiple)
            2,      # typosquat_distance (close match)
            False,  # has_ip_address
            120,    # url_length (long)
            4,      # path_depth (deep)
            True,   # has_suspicious_keywords
            3,      # subdomain_count (many)
            False,  # has_https
            True,   # suspicious_tld
        ]

    @pytest.fixture
    def legitimate_features(self):
        """Feature vector typical of legitimate URLs."""
        return [
            500,    # domain_age_days (old)
            True,   # ssl_valid
            0,      # redirect_count (none)
            0,      # typosquat_distance (no match)
            False,  # has_ip_address
            45,     # url_length (short)
            2,      # path_depth (normal)
            False,  # has_suspicious_keywords
            1,      # subdomain_count (few)
            True,   # has_https
            False,  # suspicious_tld
        ]

    def test_model_file_exists(self):
        """Test that trained model file exists."""
        model_path = Path("models/classifier.pkl")
        assert model_path.exists(), "Model file not found - run training first"

    def test_load_model(self, classifier):
        """Test that model loads successfully."""
        assert classifier.model is not None

    def test_predict_phishing(self, classifier, phishing_features):
        """Test prediction for phishing URL features."""
        verdict, confidence = classifier.predict(phishing_features)

        assert verdict == "phishing"
        assert 0.0 <= confidence <= 1.0
        assert confidence >= 0.7  # High confidence for clear phishing

    def test_predict_legitimate(self, classifier, legitimate_features):
        """Test prediction for legitimate URL features."""
        verdict, confidence = classifier.predict(legitimate_features)

        assert verdict == "safe"
        assert 0.0 <= confidence <= 1.0
        assert confidence >= 0.7  # High confidence for clear legitimate

    def test_predict_returns_valid_confidence(self, classifier, phishing_features):
        """Test that confidence is always in valid range."""
        for _ in range(10):
            verdict, confidence = classifier.predict(phishing_features)
            assert 0.0 <= confidence <= 1.0

    def test_get_feature_importance(self, classifier):
        """Test feature importance extraction."""
        importance = classifier.get_feature_importance()

        assert isinstance(importance, dict)
        assert len(importance) == 11  # 11 features

        # Check all features have importance values
        expected_features = {
            "domain_age_days", "ssl_valid", "redirect_count",
            "typosquat_distance", "has_ip_address", "url_length",
            "path_depth", "has_suspicious_keywords", "subdomain_count",
            "has_https", "suspicious_tld",
        }
        assert set(importance.keys()) == expected_features

        # Importance values should be non-negative
        for val in importance.values():
            assert val >= 0.0

    def test_feature_importance_sums_to_one(self, classifier):
        """Test that feature importance values sum to 1."""
        importance = classifier.get_feature_importance()
        total = sum(importance.values())

        # Should sum to approximately 1.0
        assert 0.99 <= total <= 1.01

    def test_predict_without_loaded_model_raises(self):
        """Test that prediction fails without loaded model."""
        clf = URLClassifier(model_path="nonexistent.pkl")

        with pytest.raises(ValueError, match="Model not loaded"):
            clf.predict([0] * 11)

    def test_predict_proba(self, classifier, phishing_features):
        """Test probability prediction."""
        proba = classifier.predict_proba(phishing_features)

        assert isinstance(proba, float)
        assert 0.0 <= proba <= 1.0
        # Phishing features should have high phishing probability
        assert proba >= 0.5


class TestSyntheticDataset:
    """Tests for synthetic dataset generation."""

    def test_generate_dataset_size(self):
        """Test dataset generation produces correct size."""
        samples, labels = generate_synthetic_dataset(num_samples=1000, seed=42)

        assert len(samples) == 1000
        assert len(labels) == 1000

    def test_generate_dataset_balanced(self):
        """Test dataset is balanced (50/50 split)."""
        samples, labels = generate_synthetic_dataset(num_samples=1000, seed=42)

        phishing_count = sum(labels)
        legitimate_count = len(labels) - phishing_count

        # Should be exactly 50/50 for even num_samples
        assert phishing_count == 500
        assert legitimate_count == 500

    def test_features_to_array_shape(self):
        """Test feature array conversion."""
        samples, labels = generate_synthetic_dataset(num_samples=100, seed=42)
        X = features_to_array(samples)

        assert X.shape == (100, 11)

    def test_phishing_features_have_patterns(self):
        """Test that phishing samples have suspicious patterns."""
        samples, labels = generate_synthetic_dataset(num_samples=1000, seed=42)

        # Get phishing samples
        phishing_samples = [s for s, l in zip(samples, labels) if l == 1]

        # Check patterns typical of phishing
        young_domains = sum(1 for s in phishing_samples if s.domain_age_days < 30)
        suspicious_keywords = sum(1 for s in phishing_samples if s.has_suspicious_keywords)

        # Most phishing should have young domains
        assert young_domains >= len(phishing_samples) * 0.9
        # Most phishing should have suspicious keywords
        assert suspicious_keywords >= len(phishing_samples) * 0.7

    def test_legitimate_features_have_patterns(self):
        """Test that legitimate samples have safe patterns."""
        samples, labels = generate_synthetic_dataset(num_samples=1000, seed=42)

        # Get legitimate samples
        legit_samples = [s for s, l in zip(samples, labels) if l == 0]

        # Check patterns typical of legitimate URLs
        old_domains = sum(1 for s in legit_samples if s.domain_age_days >= 100)
        valid_ssl = sum(1 for s in legit_samples if s.ssl_valid)
        https = sum(1 for s in legit_samples if s.has_https)

        # Most legitimate should have old domains
        assert old_domains >= len(legit_samples) * 0.9
        # Most legitimate should have valid SSL
        assert valid_ssl >= len(legit_samples) * 0.9
        # Most legitimate should use HTTPS
        assert https >= len(legit_samples) * 0.9

    def test_reproducibility(self):
        """Test that same seed produces same dataset."""
        samples1, labels1 = generate_synthetic_dataset(num_samples=100, seed=42)
        samples2, labels2 = generate_synthetic_dataset(num_samples=100, seed=42)

        X1 = features_to_array(samples1)
        X2 = features_to_array(samples2)

        np.testing.assert_array_equal(X1, X2)
        assert labels1 == labels2


class TestModelMetrics:
    """Tests for model performance metrics."""

    def test_metrics_file_exists(self):
        """Test that metrics file exists."""
        metrics_path = Path("models/metrics.json")
        assert metrics_path.exists(), "Metrics file not found"

    def test_metrics_meet_requirements(self):
        """Test that model metrics meet the requirements."""
        import json

        with open("models/metrics.json") as f:
            metrics = json.load(f)

        # Get the best model (gradient_boosting or random_forest)
        best_model = "gradient_boosting" if "gradient_boosting" in metrics else "random_forest"
        model_metrics = metrics[best_model]

        # Check requirements from SPEC-002
        assert model_metrics["precision"] >= 0.90, f"Precision {model_metrics['precision']:.2%} < 90%"
        assert model_metrics["recall"] >= 0.85, f"Recall {model_metrics['recall']:.2%} < 85%"
        assert model_metrics["f1"] >= 0.87, f"F1 {model_metrics['f1']:.2f} < 0.87"
