"""Fast ML model training without network calls.

Uses synthetic data based on realistic phishing patterns to train
the classifier without needing WHOIS lookups or SSL checks.
"""

import json
import random
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
)
from sklearn.model_selection import train_test_split

from structlog import get_logger

logger = get_logger()


@dataclass
class SyntheticFeatures:
    """Synthetic features without network calls."""

    domain_age_days: int
    ssl_valid: bool
    redirect_count: int
    typosquat_distance: int
    has_ip_address: bool
    url_length: int
    path_depth: int
    has_suspicious_keywords: bool
    subdomain_count: int
    has_https: bool
    suspicious_tld: bool


class URLClassifier:
    """ML classifier for phishing detection."""

    FEATURE_NAMES = [
        "domain_age_days",
        "ssl_valid",
        "redirect_count",
        "typosquat_distance",
        "has_ip_address",
        "url_length",
        "path_depth",
        "has_suspicious_keywords",
        "subdomain_count",
        "has_https",
        "suspicious_tld",
    ]

    def __init__(self, model_path: str = "models/classifier.pkl"):
        """Initialize classifier.

        Args:
            model_path: Path to saved model
        """
        self.model_path = Path(model_path)
        self.model = None

    def load(self) -> bool:
        """Load trained model from disk.

        Returns:
            True if model loaded successfully
        """
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)
            logger.info("Model loaded", path=str(self.model_path))
            return True
        return False

    def save(self) -> None:
        """Save trained model to disk."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        logger.info("Model saved", path=str(self.model_path))

    def predict(self, features: list[float]) -> tuple[str, float]:
        """Predict phishing verdict for URL features.

        Args:
            features: Feature vector (11 features)

        Returns:
            Tuple of (verdict, confidence)
        """
        if self.model is None:
            raise ValueError("Model not loaded")

        X = np.array([features])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]

        # Get confidence (probability of predicted class)
        confidence = float(max(probabilities))

        verdict = "phishing" if prediction == 1 else "safe"

        return verdict, confidence

    def predict_proba(self, features: list[float]) -> float:
        """Get phishing probability.

        Args:
            features: Feature vector (11 features)

        Returns:
            Probability of phishing (0-1)
        """
        if self.model is None:
            raise ValueError("Model not loaded")

        X = np.array([features])
        proba = self.model.predict_proba(X)[0]
        return float(proba[1])  # Probability of class 1 (phishing)

    def get_feature_importance(self) -> dict[str, float]:
        """Get feature importance from the model.

        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.model is None or not hasattr(self.model, "feature_importances_"):
            return {}

        return dict(zip(self.FEATURE_NAMES, self.model.feature_importances_.tolist()))


def generate_synthetic_dataset(
    num_samples: int = 10000,
    seed: int = 42,
) -> tuple[list[SyntheticFeatures], list[int]]:
    """Generate synthetic dataset with realistic phishing patterns.

    Args:
        num_samples: Total number of samples (split 50/50 phishing/legitimate)
        seed: Random seed for reproducibility

    Returns:
        Tuple of (features list, labels list)
    """
    random.seed(seed)
    np.random.seed(seed)

    samples: list[SyntheticFeatures] = []
    labels: list[int] = []

    num_phishing = num_samples // 2
    num_legitimate = num_samples - num_phishing

    # Generate phishing samples with realistic patterns
    for _ in range(num_phishing):
        # Phishing URLs typically have:
        # - Young domains (0-30 days)
        # - Often no valid SSL or self-signed
        # - Multiple redirects
        # - Typosquatting
        # - IP addresses instead of domains
        # - Longer URLs
        # - Suspicious keywords
        # - Many subdomains
        # - Suspicious TLDs

        features = SyntheticFeatures(
            domain_age_days=random.randint(0, 30),
            ssl_valid=random.random() < 0.2,  # 20% have valid SSL
            redirect_count=random.randint(1, 5),
            typosquat_distance=random.randint(1, 3),
            has_ip_address=random.random() < 0.3,  # 30% use IP
            url_length=random.randint(50, 200),
            path_depth=random.randint(2, 6),
            has_suspicious_keywords=random.random() < 0.8,  # 80% have keywords
            subdomain_count=random.randint(2, 5),
            has_https=random.random() < 0.5,  # 50% use HTTPS
            suspicious_tld=random.random() < 0.4,  # 40% suspicious TLD
        )
        samples.append(features)
        labels.append(1)  # Phishing

    # Generate legitimate samples
    for _ in range(num_legitimate):
        # Legitimate URLs typically have:
        # - Older domains (100+ days)
        # - Valid SSL
        # - Few or no redirects
        # - No typosquatting
        # - Domain names, not IPs
        # - Shorter URLs
        # - Few/no suspicious keywords
        # - Few subdomains
        # - Standard TLDs

        features = SyntheticFeatures(
            domain_age_days=random.randint(100, 5000),
            ssl_valid=random.random() < 0.95,  # 95% have valid SSL
            redirect_count=random.randint(0, 2),
            typosquat_distance=0,
            has_ip_address=False,
            url_length=random.randint(15, 80),
            path_depth=random.randint(0, 3),
            has_suspicious_keywords=random.random() < 0.1,  # 10% have keywords
            subdomain_count=random.randint(0, 2),
            has_https=random.random() < 0.95,  # 95% use HTTPS
            suspicious_tld=False,
        )
        samples.append(features)
        labels.append(0)  # Legitimate

    # Shuffle the dataset
    combined = list(zip(samples, labels))
    random.shuffle(combined)
    samples, labels = zip(*combined)

    return list(samples), list(labels)


def features_to_array(samples: list[SyntheticFeatures]) -> np.ndarray:
    """Convert samples to feature array.

    Args:
        samples: List of SyntheticFeatures

    Returns:
        NumPy array of shape (n_samples, 11)
    """
    return np.array([
        [
            s.domain_age_days,
            float(s.ssl_valid),
            s.redirect_count,
            s.typosquat_distance,
            float(s.has_ip_address),
            s.url_length,
            s.path_depth,
            float(s.has_suspicious_keywords),
            s.subdomain_count,
            float(s.has_https),
            float(s.suspicious_tld),
        ]
        for s in samples
    ])


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> tuple[object, dict]:
    """Train and evaluate models, return the best one.

    Args:
        X_train: Training features
        y_train: Training labels
        X_test: Test features
        y_test: Test labels

    Returns:
        Tuple of (best_model, metrics_dict)
    """
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1,
        ),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42,
        ),
    }

    best_model = None
    best_f1 = 0
    metrics = {}

    for name, model in models.items():
        logger.info("Training model", model=name)

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        accuracy = accuracy_score(y_test, y_pred)

        metrics[name] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
        }

        logger.info(
            "Model results",
            model=name,
            precision=f"{precision:.4f}",
            recall=f"{recall:.4f}",
            f1=f"{f1:.4f}",
            accuracy=f"{accuracy:.4f}",
        )

        if f1 > best_f1:
            best_f1 = f1
            best_model = model

    return best_model, metrics


def main():
    """Main training routine."""
    print("=" * 60)
    print("PhishRadar ML Model Training (Fast)")
    print("=" * 60)

    # Generate dataset
    print("\n[1/4] Generating synthetic dataset...")
    samples, labels = generate_synthetic_dataset(num_samples=10000)
    print(f"   Generated {len(samples)} samples")
    print(f"   Phishing: {sum(labels)}")
    print(f"   Legitimate: {len(labels) - sum(labels)}")

    # Convert to arrays
    print("\n[2/4] Preparing data...")
    X = features_to_array(samples)
    y = np.array(labels)
    print(f"   Feature matrix shape: {X.shape}")
    print(f"   Labels shape: {y.shape}")

    # Split data
    print("\n[3/4] Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training samples: {len(X_train)}")
    print(f"   Test samples: {len(X_test)}")

    # Train models
    print("\n[4/4] Training models...")
    best_model, metrics = train_model(X_train, y_train, X_test, y_test)

    # Save model
    model_dir = Path("models")
    model_dir.mkdir(parents=True, exist_ok=True)

    classifier = URLClassifier(model_path=model_dir / "classifier.pkl")
    classifier.model = best_model
    classifier.save()

    print(f"\nBest model saved to {model_dir / 'classifier.pkl'}")

    # Save metrics
    with open(model_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Print results
    y_pred = best_model.predict(X_test)

    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)

    best_name = "gradient_boosting" if best_model.__class__.__name__ == "GradientBoostingClassifier" else "random_forest"
    print(f"\nBest Model: {best_name}")
    print(f"Accuracy:  {metrics[best_name]['accuracy']:.4f}")
    print(f"Precision: {metrics[best_name]['precision']:.4f}")
    print(f"Recall:    {metrics[best_name]['recall']:.4f}")
    print(f"F1 Score:  {metrics[best_name]['f1']:.4f}")

    # Check if metrics meet requirements
    meets_precision = metrics[best_name]['precision'] >= 0.90
    meets_recall = metrics[best_name]['recall'] >= 0.85
    meets_f1 = metrics[best_name]['f1'] >= 0.87

    print(f"\nRequirements Check:")
    print(f"  Precision >= 90%: {'PASS' if meets_precision else 'FAIL'} ({metrics[best_name]['precision']*100:.1f}%)")
    print(f"  Recall >= 85%:    {'PASS' if meets_recall else 'FAIL'} ({metrics[best_name]['recall']*100:.1f}%)")
    print(f"  F1 >= 0.87:       {'PASS' if meets_f1 else 'FAIL'} ({metrics[best_name]['f1']:.2f})")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(f"  TN: {cm[0][0]:4d}  FP: {cm[0][1]:4d}")
    print(f"  FN: {cm[1][0]:4d}  TP: {cm[1][1]:4d}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Feature importance
    print("\nFeature Importance:")
    importance = dict(zip(URLClassifier.FEATURE_NAMES, best_model.feature_importances_))
    for name, imp in sorted(importance.items(), key=lambda x: -x[1]):
        print(f"  {name:25s}: {imp:.4f}")


if __name__ == "__main__":
    main()
