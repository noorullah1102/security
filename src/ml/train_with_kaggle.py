#!/usr/bin/env python3
"""Train ML classifier with Kaggle datasets.

This script combines:
- Kaggle phishing datasets
- URLhaus phishing URLs
- OpenPhish feed
- Tranco top domains (legitimate)

Usage:
    python -m src.ml.train_with_kaggle
"""

import json
import random
import re
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from structlog import get_logger
import joblib

logger = get_logger()

# Directories
DATA_DIR = Path(__file__).parent.parent.parent / "data"
EXTERNAL_DIR = DATA_DIR / "external"
TRAINING_DIR = DATA_DIR / "training"
MODELS_DIR = Path(__file__).parent.parent.parent / "models"

# Legitimate top domains (fallback if Tranco unavailable)
TOP_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "reddit.com", "amazon.com", "apple.com", "microsoft.com",
    "netflix.com", "spotify.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "yahoo.com", "ebay.com", "paypal.com", "office.com", "live.com",
    "bing.com", "msn.com", "cnn.com", "bbc.com", "nytimes.com",
    "washingtonpost.com", "theguardian.com", "medium.com", "quora.com", "pinterest.com",
    "tumblr.com", "flickr.com", "vimeo.com", "soundcloud.com", "twitch.tv",
    "discord.com", "slack.com", "zoom.us", "dropbox.com", "drive.google.com",
    "mail.google.com", "docs.google.com", "sheets.google.com", "maps.google.com",
    "translate.google.com", "news.google.com", "photos.google.com", "calendar.google.com",
    "gmail.com", "outlook.com", "hotmail.com", "icloud.com", "protonmail.com",
    "adobe.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
    "amd.com", "samsung.com", "sony.com", "lg.com", "dell.com",
    "hp.com", "lenovo.com", "asus.com", "acer.com", "msi.com",
]


class KaggleFeatureExtractor:
    """Extract features from URLs for ML classification.

    Uses 17 lexical features (no network calls for speed).
    """

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
        ".xyz", ".top", ".club", ".online", ".site",
        ".work", ".click", ".link", ".info", ".biz",
        ".cc", ".ru", ".cn",
    }

    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = {
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "password", "credential", "banking", "alert",
        "warning", "suspended", "locked", "unlock", "webscr", "cmd",
    }

    def extract(self, url: str) -> dict[str, Any]:
        """Extract all features from a URL."""
        url_lower = url.lower()

        # Parse URL
        protocol = "https" if url.startswith("https") else "http"
        domain = self._extract_domain(url)
        path = url.replace(f"{protocol}://", "").replace(domain, "", 1)

        features = {
            # Basic features
            "url_length": len(url),
            "domain_length": len(domain.split("/")[0]),
            "path_length": len(path),
            "query_length": len(url.split("?")[1]) if "?" in url else 0,

            # Structural features
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_underscores": url.count("_"),
            "num_slashes": url.count("/"),
            "num_equals": url.count("="),
            "num_at_symbols": url.count("@"),
            "num_question_marks": url.count("?"),
            "num_ampersands": url.count("&"),
            "num_digits": sum(c.isdigit() for c in url),

            # Ratio features
            "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
            "special_char_ratio": sum(not c.isalnum() for c in url) / max(len(url), 1),

            # URL characteristics
            "has_https": 1 if url.startswith("https") else 0,
            "has_ip_address": self._has_ip_address(domain),
            "has_double_slash": 1 if "//" in url[8:] else 0,  # After protocol
            "has_at_symbol": 1 if "@" in url else 0,
            "has_suspicious_tld": self._has_suspicious_tld(domain),
            "has_suspicious_keywords": self._has_suspicious_keywords(url_lower),
            "uses_shortener": self._uses_url_shortener(domain),

            # Typosquat detection
            "typosquat_distance": self._check_typosquat(domain),
        }

        return features

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        url = url.replace("http://", "").replace("https://", "")
        domain = url.split("/")[0].split("?")[0].split("#")[0]
        return domain

    def _has_ip_address(self, domain: str) -> int:
        """Check if domain contains IP address."""
        import ipaddress
        host = domain.split(":")[0]
        try:
            ipaddress.ip_address(host)
            return 1
        except ValueError:
            return 0

    def _has_suspicious_tld(self, domain: str) -> int:
        """Check for suspicious TLD."""
        domain_lower = domain.lower()
        return 1 if any(domain_lower.endswith(tld) for tld in self.SUSPICIOUS_TLDS) else 0

    def _has_suspicious_keywords(self, url: str) -> int:
        """Check for suspicious keywords."""
        return 1 if any(kw in url for kw in self.SUSPICIOUS_KEYWORDS) else 0

    def _uses_url_shortener(self, domain: str) -> int:
        """Check if URL uses shortener service."""
        shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
                      "is.gd", "buff.ly", "short.link", "bl.ink"}
        return 1 if domain.lower() in shorteners else 0

    def _check_typosquat(self, domain: str) -> int:
        """Check for typosquatting (simplified)."""
        popular = ["google", "facebook", "amazon", "apple", "microsoft",
                   "paypal", "netflix", "twitter", "instagram", "linkedin"]
        domain_name = domain.split(".")[0].lower()

        for brand in popular:
            if brand in domain_name and domain_name != brand:
                return 1
            # Check for similar domains
            if self._levenshtein_distance(domain_name, brand) <= 2:
                return 1
        return 0

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j+1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    def to_vector(self, features: dict[str, Any]) -> list[float]:
        """Convert features dict to model input vector."""
        return [
            float(features["url_length"]),
            float(features["domain_length"]),
            float(features["path_length"]),
            float(features["query_length"]),
            float(features["num_dots"]),
            float(features["num_hyphens"]),
            float(features["num_digits"]),
            float(features["digit_ratio"]),
            float(features["special_char_ratio"]),
            float(features["has_https"]),
            float(features["has_ip_address"]),
            float(features["has_suspicious_tld"]),
            float(features["has_suspicious_keywords"]),
            float(features["uses_shortener"]),
            float(features["typosquat_distance"]),
            float(features["has_at_symbol"]),
            float(features["has_double_slash"]),
        ]


def load_kaggle_datasets() -> tuple[list[str], list[str]]:
    """Load URLs from downloaded Kaggle datasets.

    Returns:
        Tuple of (phishing_urls, legitimate_urls)
    """
    phishing_urls = []
    legitimate_urls = []

    # Dataset 1: phishing-site-urls
    dataset1 = EXTERNAL_DIR / "phishing_site_urls.csv"
    if dataset1.exists():
        print(f"Loading: {dataset1}")
        try:
            df = pd.read_csv(dataset1)
            # Standardize column names
            df.columns = [c.lower().strip() for c in df.columns]

            # Find URL and label columns
            url_col = next((c for c in df.columns if "url" in c), None)
            label_col = next((c for c in df.columns if "label" in c or "class" in c or "status" in c), None)

            if url_col and label_col:
                for _, row in df.iterrows():
                    url = str(row[url_col]).strip()
                    if not url.startswith("http"):
                        url = "https://" + url

                    label = str(row[label_col]).lower()
                    if label in ["bad", "phishing", "1", "malicious"]:
                        phishing_urls.append(url)
                    elif label in ["good", "safe", "legitimate", "0", "benign"]:
                        legitimate_urls.append(url)

                print(f"  Loaded {len(phishing_urls)} phishing, {len(legitimate_urls)} legitimate")
        except Exception as e:
            print(f"  Error loading {dataset1}: {e}")

    # Dataset 2: malicious-urls-dataset (malicious_phish.csv from Kaggle)
    dataset2 = EXTERNAL_DIR / "malicious_urls.csv"
    dataset2_alt = EXTERNAL_DIR / "malicious_phish.csv"
    dataset2_path = dataset2 if dataset2.exists() else dataset2_alt

    if dataset2_path.exists():
        print(f"Loading: {dataset2_path}")
        try:
            df = pd.read_csv(dataset2_path)
            df.columns = [c.lower().strip() for c in df.columns]

            url_col = next((c for c in df.columns if "url" in c), None)
            label_col = next((c for c in df.columns if "label" in c or "type" in c or "class" in c), None)

            if url_col and label_col:
                for _, row in df.iterrows():
                    url = str(row[url_col]).strip()
                    if not url.startswith("http"):
                        url = "https://" + url

                    label = str(row[label_col]).lower()
                    if label in ["phishing", "malware", "defacement", "bad", "1"]:
                        phishing_urls.append(url)
                    elif label in ["benign", "safe", "good", "0"]:
                        legitimate_urls.append(url)

                print(f"  Total: {len(phishing_urls)} phishing, {len(legitimate_urls)} legitimate")
        except Exception as e:
            print(f"  Error loading {dataset2_path}: {e}")

    # Dataset 3: Any other CSV files in external dir
    for csv_file in EXTERNAL_DIR.glob("*.csv"):
        if csv_file.name in ["phishing_site_urls.csv", "malicious_urls.csv"]:
            continue
        print(f"Found additional dataset: {csv_file}")
        try:
            df = pd.read_csv(csv_file, nrows=100)  # Sample to check structure
            print(f"  Columns: {list(df.columns)}")
        except Exception as e:
            print(f"  Could not read: {e}")

    return phishing_urls, legitimate_urls


def load_existing_data() -> tuple[list[str], list[str]]:
    """Load existing training data."""
    phishing = []
    legitimate = []

    existing_data = TRAINING_DIR / "real_dataset.json"
    if existing_data.exists():
        print(f"Loading existing data: {existing_data}")
        with open(existing_data) as f:
            data = json.load(f)

        for item in data:
            if item.get("label") == "phishing":
                phishing.append(item["url"])
            else:
                legitimate.append(item["url"])

        print(f"  Loaded {len(phishing)} phishing, {len(legitimate)} legitimate")

    return phishing, legitimate


def generate_legitimate_urls() -> list[str]:
    """Generate legitimate URLs from top domains."""
    urls = []
    paths = ["", "/", "/about", "/contact", "/products", "/services",
             "/blog", "/news", "/login", "/signup", "/help", "/faq"]

    for domain in TOP_DOMAINS:
        # Add base URLs
        urls.append(f"https://{domain}")
        urls.append(f"https://www.{domain}")

        # Add with paths (randomly)
        for path in random.sample(paths, min(3, len(paths))):
            urls.append(f"https://{domain}{path}")

    return urls


def prepare_dataset(
    kaggle_phishing: list[str],
    kaggle_legitimate: list[str],
    existing_phishing: list[str],
    existing_legitimate: list[str],
) -> tuple[list[dict], list[int]]:
    """Prepare combined dataset for training."""
    extractor = KaggleFeatureExtractor()

    features = []
    labels = []

    # Combine all phishing URLs
    all_phishing = list(set(kaggle_phishing + existing_phishing))
    print(f"\nTotal phishing URLs: {len(all_phishing)}")

    # Combine all legitimate URLs
    all_legitimate = list(set(kaggle_legitimate + existing_legitimate))
    # Add generated legitimate URLs
    generated = generate_legitimate_urls()
    all_legitimate.extend(generated)
    all_legitimate = list(set(all_legitimate))
    print(f"Total legitimate URLs: {len(all_legitimate)}")

    # Balance dataset
    min_count = min(len(all_phishing), len(all_legitimate))
    if len(all_phishing) > min_count:
        all_phishing = random.sample(all_phishing, min_count)
    if len(all_legitimate) > min_count:
        all_legitimate = random.sample(all_legitimate, min_count)

    print(f"Balanced dataset: {len(all_phishing)} phishing, {len(all_legitimate)} legitimate")

    # Extract features
    print("\nExtracting features...")

    for url in all_phishing:
        try:
            feat = extractor.extract(url)
            features.append(feat)
            labels.append(1)  # Phishing
        except Exception as e:
            pass

    for url in all_legitimate:
        try:
            feat = extractor.extract(url)
            features.append(feat)
            labels.append(0)  # Legitimate
        except Exception as e:
            pass

    print(f"Extracted features for {len(features)} URLs")

    return features, labels


def train_model(features: list[dict], labels: list[int]) -> tuple[Any, dict]:
    """Train ML model."""
    extractor = KaggleFeatureExtractor()

    # Convert to vectors
    X = [extractor.to_vector(f) for f in features]
    y = labels

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")

    # Train models
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=100, max_depth=20, random_state=42, n_jobs=-1
        ),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=100, max_depth=10, random_state=42
        ),
    }

    best_model = None
    best_score = 0
    best_name = ""
    results = {}

    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred),
            "f1": f1_score(y_test, y_pred),
        }
        results[name] = metrics

        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1']:.4f}")

        if metrics["f1"] > best_score:
            best_score = metrics["f1"]
            best_model = model
            best_name = name

    print(f"\nBest model: {best_name} (F1: {best_score:.4f})")

    return best_model, results


def main():
    """Main training pipeline."""
    print("=" * 60)
    print("PHISHING CLASSIFIER TRAINING WITH KAGGLE DATA")
    print("=" * 60)

    # Load Kaggle datasets
    print("\n1. Loading Kaggle datasets...")
    kaggle_phishing, kaggle_legitimate = load_kaggle_datasets()

    # Load existing data
    print("\n2. Loading existing training data...")
    existing_phishing, existing_legitimate = load_existing_data()

    # Check if we have enough data
    total_phishing = len(kaggle_phishing) + len(existing_phishing)
    total_legitimate = len(kaggle_legitimate) + len(existing_legitimate)

    if total_phishing < 100 or total_legitimate < 100:
        print("\nWARNING: Not enough data for training!")
        print(f"  Phishing: {total_phishing}")
        print(f"  Legitimate: {total_legitimate}")
        print("\nPlease download Kaggle datasets first:")
        print("  python scripts/download_kaggle_data.py")
        return

    # Prepare dataset
    print("\n3. Preparing dataset...")
    features, labels = prepare_dataset(
        kaggle_phishing, kaggle_legitimate,
        existing_phishing, existing_legitimate,
    )

    if len(features) < 100:
        print("ERROR: Not enough features extracted!")
        return

    # Train model
    print("\n4. Training model...")
    model, results = train_model(features, labels)

    # Save model
    print("\n5. Saving model...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / "classifier_kaggle.pkl"
    joblib.dump(model, model_path)
    print(f"  Model saved to: {model_path}")

    # Save metrics
    metrics_path = MODELS_DIR / "metrics_kaggle.json"
    with open(metrics_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Metrics saved to: {metrics_path}")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    main()
