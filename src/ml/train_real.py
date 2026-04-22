"""Train ML model using real phishing and legitimate URLs.

Uses only lexical features (no network calls) for fast training.
"""

import json
import random
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import tldextract
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from structlog import get_logger

logger = get_logger()


# Suspicious TLDs commonly used for phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
    ".xyz", ".top", ".club", ".online", ".site",  # Cheap TLDs
    ".work", ".click", ".link", ".info", ".biz",  # Often abused
    ".cc", ".ru", ".cn", ".pw", ".loan", ".win",  # High abuse rates
}

# Suspicious keywords often found in phishing URLs
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "confirmation",
    "password", "passwd", "pwd", "credential", "auth", "authenticate",
    "banking", "bank", "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "alert", "warning", "suspended", "locked", "unlock",
    "verify-account", "secure-login", "account-update", "action-required",
    "webscr", "cmd", "dispatch", "session", "token", "access",
}

# Popular domains for typosquat detection
POPULAR_DOMAINS = [
    "google", "facebook", "amazon", "apple", "microsoft",
    "paypal", "netflix", "twitter", "instagram", "linkedin",
    "bankofamerica", "chase", "wellsfargo", "citi", "yahoo",
    "outlook", "hotmail", "gmail", "office", "onedrive",
    "ebay", "walmart", "target", "bestbuy", "costco",
]


@dataclass
class LexicalFeatures:
    """Lexical features extracted from URL (no network calls)."""
    url_length: int
    path_depth: int
    has_https: bool
    subdomain_count: int
    has_ip_address: bool
    suspicious_tld: bool
    has_suspicious_keywords: bool
    typosquat_distance: int
    digit_ratio: float
    special_char_ratio: float
    path_length: int
    query_length: int
    num_dots: int
    num_hyphens: int
    has_at_symbol: bool
    has_double_slash: bool
    uses_shortener: bool


class FastFeatureExtractor:
    """Extract lexical features from URLs without network calls."""

    URL_SHORTENERS = {
        "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "tiny.cc", "lc.chat",
        "bl.ink", "shorturl.at", "rebrand.ly", "cutt.ly", "rb.gy",
    }

    def extract(self, url: str) -> LexicalFeatures:
        """Extract all lexical features from a URL."""
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        # Basic URL properties
        url_length = len(url)
        path_depth = self._get_path_depth(parsed.path)
        has_https = parsed.scheme == "https"
        subdomain_count = self._count_subdomains(extracted.subdomain)
        has_ip_address = self._has_ip_address(parsed.netloc)
        suspicious_tld = self._is_suspicious_tld(extracted.suffix)
        has_suspicious_keywords = self._has_suspicious_keywords(url.lower())

        # Typosquat detection
        typosquat_distance = self._check_typosquat(extracted.domain)

        # Character analysis
        digit_ratio = self._get_digit_ratio(url)
        special_char_ratio = self._get_special_char_ratio(url)

        # Path and query analysis
        path_length = len(parsed.path)
        query_length = len(parsed.query) if parsed.query else 0

        # Structural features
        num_dots = url.count(".")
        num_hyphens = url.count("-")
        has_at_symbol = "@" in url
        has_double_slash = "//" in url[8:] if "://" in url else False  # After scheme

        # URL shortener check
        domain = extracted.registered_domain or parsed.netloc
        uses_shortener = domain.lower() in self.URL_SHORTENERS

        return LexicalFeatures(
            url_length=min(url_length, 500),
            path_depth=path_depth,
            has_https=has_https,
            subdomain_count=subdomain_count,
            has_ip_address=has_ip_address,
            suspicious_tld=suspicious_tld,
            has_suspicious_keywords=has_suspicious_keywords,
            typosquat_distance=typosquat_distance,
            digit_ratio=digit_ratio,
            special_char_ratio=special_char_ratio,
            path_length=min(path_length, 200),
            query_length=min(query_length, 200),
            num_dots=min(num_dots, 20),
            num_hyphens=min(num_hyphens, 20),
            has_at_symbol=has_at_symbol,
            has_double_slash=has_double_slash,
            uses_shortener=uses_shortener,
        )

    def _get_path_depth(self, path: str) -> int:
        """Calculate the depth of the URL path."""
        if not path or path == "/":
            return 0
        return len([p for p in path.strip("/").split("/") if p])

    def _count_subdomains(self, subdomain: str) -> int:
        """Count the number of subdomains."""
        if not subdomain:
            return 0
        return len(subdomain.split("."))

    def _has_ip_address(self, netloc: str) -> bool:
        """Check if the netloc contains an IP address."""
        import ipaddress
        host = netloc.split(":")[0]
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _is_suspicious_tld(self, tld: str) -> bool:
        """Check if the TLD is commonly used for phishing."""
        if not tld:
            return False
        return f".{tld.lower()}" in SUSPICIOUS_TLDS

    def _has_suspicious_keywords(self, url: str) -> bool:
        """Check if URL contains suspicious keywords."""
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS)

    def _check_typosquat(self, domain: str) -> int:
        """Check if domain is a typosquat of popular domains."""
        domain_lower = domain.lower() if domain else ""
        if not domain_lower:
            return 0

        # Exact match = not typosquat
        if domain_lower in POPULAR_DOMAINS:
            return 0

        min_distance = float("inf")
        for popular in POPULAR_DOMAINS:
            distance = self._levenshtein_distance(domain_lower, popular)
            if distance < min_distance:
                min_distance = distance

        return int(min_distance) if min_distance <= 3 else 0

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _get_digit_ratio(self, url: str) -> float:
        """Get ratio of digits in URL."""
        if not url:
            return 0.0
        digits = sum(c.isdigit() for c in url)
        return digits / len(url)

    def _get_special_char_ratio(self, url: str) -> float:
        """Get ratio of special characters in URL."""
        if not url:
            return 0.0
        special = sum(not c.isalnum() for c in url)
        return special / len(url)

    def to_vector(self, features: LexicalFeatures) -> list[float]:
        """Convert features to ML model input vector."""
        return [
            float(features.url_length),
            float(features.path_depth),
            float(features.has_https),
            float(features.subdomain_count),
            float(features.has_ip_address),
            float(features.suspicious_tld),
            float(features.has_suspicious_keywords),
            float(features.typosquat_distance),
            float(features.digit_ratio),
            float(features.special_char_ratio),
            float(features.path_length),
            float(features.query_length),
            float(features.num_dots),
            float(features.num_hyphens),
            float(features.has_at_symbol),
            float(features.has_double_slash),
            float(features.uses_shortener),
        ]


class URLClassifier:
    """ML classifier for phishing detection."""

    FEATURE_NAMES = [
        "url_length",
        "path_depth",
        "has_https",
        "subdomain_count",
        "has_ip_address",
        "suspicious_tld",
        "has_suspicious_keywords",
        "typosquat_distance",
        "digit_ratio",
        "special_char_ratio",
        "path_length",
        "query_length",
        "num_dots",
        "num_hyphens",
        "has_at_symbol",
        "has_double_slash",
        "uses_shortener",
    ]

    def __init__(self, model_path: str = "models/classifier_real.pkl"):
        """Initialize classifier."""
        self.model_path = Path(model_path)
        self.model = None

    def load(self) -> bool:
        """Load trained model from disk."""
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
        """Predict phishing verdict for URL features."""
        if self.model is None:
            raise ValueError("Model not loaded")

        X = np.array([features])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = float(max(probabilities))
        verdict = "phishing" if prediction == 1 else "safe"

        return verdict, confidence

    def get_feature_importance(self) -> dict[str, float]:
        """Get feature importance from the model."""
        if self.model is None or not hasattr(self.model, "feature_importances_"):
            return {}
        return dict(zip(self.FEATURE_NAMES, self.model.feature_importances_.tolist()))


def load_dataset(dataset_path: str) -> list[dict]:
    """Load dataset from JSON file."""
    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    with open(path) as f:
        return json.load(f)


def prepare_features(
    samples: list[dict],
    extractor: FastFeatureExtractor,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Extract features from samples.

    Returns:
        Tuple of (features array, labels array, raw URLs)
    """
    X = []
    y = []
    urls = []

    for sample in samples:
        url = sample["url"]
        label = sample["label"]

        try:
            features = extractor.extract(url)
            X.append(extractor.to_vector(features))
            y.append(1 if label == "phishing" else 0)
            urls.append(url)
        except Exception as e:
            logger.debug("Skipping URL", url=url, error=str(e))
            continue

    return np.array(X), np.array(y), urls


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> tuple[object, dict]:
    """Train and evaluate models."""
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        ),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            min_samples_split=5,
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
        )

        if f1 > best_f1:
            best_f1 = f1
            best_model = model

    return best_model, metrics


def main():
    """Main training routine."""
    print("=" * 60)
    print("PhishRadar ML Model Training (Real Data)")
    print("=" * 60)

    # Load dataset
    dataset_path = Path("data/training/real_dataset.json")
    if not dataset_path.exists():
        print("\nERROR: Dataset not found!")
        print("Run first: python -m src.ml.collect_real_data")
        return

    print("\n[1/5] Loading dataset...")
    samples = load_dataset(dataset_path)
    print(f"   Loaded {len(samples)} samples")

    phishing = sum(1 for s in samples if s["label"] == "phishing")
    legitimate = sum(1 for s in samples if s["label"] == "legitimate")
    print(f"   Phishing: {phishing}")
    print(f"   Legitimate: {legitimate}")

    # Extract features
    print("\n[2/5] Extracting features...")
    extractor = FastFeatureExtractor()
    X, y, urls = prepare_features(samples, extractor)
    print(f"   Feature matrix shape: {X.shape}")
    print(f"   Labels shape: {y.shape}")

    # Balance dataset if needed
    phishing_count = np.sum(y == 1)
    legitimate_count = np.sum(y == 0)
    print(f"   After extraction - Phishing: {phishing_count}, Legitimate: {legitimate_count}")

    # Split data
    print("\n[3/5] Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training samples: {len(X_train)}")
    print(f"   Test samples: {len(X_test)}")

    # Train models
    print("\n[4/5] Training models...")
    best_model, metrics = train_model(X_train, y_train, X_test, y_test)

    # Save model
    print("\n[5/5] Saving model...")
    model_dir = Path("models")
    model_dir.mkdir(parents=True, exist_ok=True)

    classifier = URLClassifier(model_path=model_dir / "classifier_real.pkl")
    classifier.model = best_model
    classifier.save()

    # Save metrics
    with open(model_dir / "metrics_real.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Print results
    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)

    best_name = "random_forest" if "RandomForest" in str(type(best_model)) else "gradient_boosting"
    best_name = max(metrics, key=lambda k: metrics[k]["f1"])

    print(f"\nBest Model: {best_name}")
    print(f"Accuracy:  {metrics[best_name]['accuracy']:.4f}")
    print(f"Precision: {metrics[best_name]['precision']:.4f}")
    print(f"Recall:    {metrics[best_name]['recall']:.4f}")
    print(f"F1 Score:  {metrics[best_name]['f1']:.4f}")

    # Check requirements
    meets_precision = metrics[best_name]['precision'] >= 0.90
    meets_recall = metrics[best_name]['recall'] >= 0.85
    meets_f1 = metrics[best_name]['f1'] >= 0.87

    print(f"\nRequirements Check:")
    print(f"  Precision >= 90%: {'PASS ✓' if meets_precision else 'FAIL ✗'} ({metrics[best_name]['precision']*100:.1f}%)")
    print(f"  Recall >= 85%:    {'PASS ✓' if meets_recall else 'FAIL ✗'} ({metrics[best_name]['recall']*100:.1f}%)")
    print(f"  F1 >= 0.87:       {'PASS ✓' if meets_f1 else 'FAIL ✗'} ({metrics[best_name]['f1']:.2f})")

    # Confusion matrix
    y_pred = best_model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(f"  TN: {cm[0][0]:4d}  FP: {cm[0][1]:4d}")
    print(f"  FN: {cm[1][0]:4d}  TP: {cm[1][1]:4d}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Feature importance
    print("\nFeature Importance:")
    importance = dict(zip(URLClassifier.FEATURE_NAMES, best_model.feature_importances_))
    for name, imp in sorted(importance.items(), key=lambda x: -x[1])[:10]:
        print(f"  {name:25s}: {imp:.4f}")

    print(f"\nModel saved to: {model_dir / 'classifier_real.pkl'}")


if __name__ == "__main__":
    main()
