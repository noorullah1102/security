"""ML model training script."""

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from src.analyzer.features import FeatureExtractor
from src.analyzer.models import URLFeatures
from src.ml.dataset import DatasetGenerator, URLSample


class URLClassifier:
    """ML classifier for phishing detection."""

    def __init__(self, model_path: str = "models/classifier.pkl"):
        """Initialize classifier.

        Args:
            model_path: Path to saved model
        """
        self.model_path = Path(model_path)
        self.model = None
        self.feature_names = [
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

    def load(self) -> None:
        """Load trained model from disk."""
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)

    def save(self) -> None:
        """Save trained model to disk."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def predict(self, features: URLFeatures) -> tuple[str, float]:
        """Predict phishing verdict for URL features.

        Args:
            features: Extracted URL features

        Returns:
            Tuple of (verdict, confidence)
        """
        if self.model is None:
            raise ValueError("Model not loaded")

        X = np.array([features.to_feature_vector()])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]

        # Get confidence (probability of predicted class)
        confidence = max(probabilities)

        verdict = "phishing" if prediction == 1 else "safe"

        return verdict, float(confidence)

    def get_feature_importance(self, features: URLFeatures) -> dict[str, float]:
        """Get feature importance for a prediction.

        Args:
            features: Extracted URL features

        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.model is None:
            return {}

        # Get feature importances from model
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
        else:
            return {}

        return dict(zip(self.feature_names, importances))


def prepare_training_data(
    samples: list[URLSample],
) -> tuple[np.ndarray, np.ndarray]:
    """Prepare training data from samples.

    Args:
        samples: List of URL samples

    Returns:
            Tuple of (X, y) arrays
    """
    extractor = FeatureExtractor()
    X = []
    y = []

    for sample in samples:
        try:
            features = extractor.extract(sample.url)
            X.append(features.to_feature_vector())
            y.append(1 if sample.label == "phishing" else 0)
        except Exception as e:
            print(f"Failed to extract features for {sample.url}: {e}")
            continue

    return np.array(X), np.array(y)


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> tuple[Any, dict]:
    """Train and evaluate model.

    Args:
        X_train: Training features
        y_train: Training labels
        X_test: Test features
        y_test: Test labels

    Returns:
            Tuple of (best_model, metrics)
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
        print(f"\nTraining {name}...")

        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)

        metrics[name] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

        print(f"\n{name} Results:")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall: {recall:.4f}")
        print(f"  F1 Score: {f1:.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model = model

    return best_model, metrics


def main():
    """Main training routine."""
    print("=" * 60)
    print("PhishRadar ML Model Training")
    print("=" * 60)

    # Generate dataset
    print("\n[1/4] Generating dataset...")
    generator = DatasetGenerator(seed=42)
    samples = generator.generate_dataset(num_phishing=5000, num_legitimate=5000)

    print(f"   Generated {len(samples)} samples")
    print(f"   Phishing: {sum(1 for s in samples if s.label == 'phishing')}")
    print(f"   Legitimate: {sum(1 for s in samples if s.label == 'legitimate')}")

    # Prepare features
    print("\n[2/4] Extracting features...")
    X, y = prepare_training_data(samples)
    print(f"   Feature matrix shape: {X.shape}")
    print(f"   Labels shape: {y.shape}")

    # Split data
    print("\n[3/4] Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training samples: {len(X_train)}")
    print(f"   Test samples: {len(X_test)}")

    # Train model
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

    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)

    # Print confusion matrix
    y_pred = best_model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))


if __name__ == "__main__":
    main()
