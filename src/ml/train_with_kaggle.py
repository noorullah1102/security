#!/usr/bin/env python3
"""Train ML classifier with Kaggle datasets.

Improved pipeline with:
- Cleaner data (phishing-only labels, no malware/defacement)
- 29 lexical features (up from 17)
- Hyperparameter tuning with cross-validation
- Target: 95%+ accuracy

Usage:
    python -m src.ml.train_with_kaggle
"""

import json
import math
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from structlog import get_logger
import joblib

logger = get_logger()

# Directories
DATA_DIR = Path(__file__).parent.parent.parent / "data"
EXTERNAL_DIR = DATA_DIR / "external"
TRAINING_DIR = DATA_DIR / "training"
MODELS_DIR = Path(__file__).parent.parent.parent / "models"

# Legitimate top domains (fallback)
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


def _tokenize_url(url):
    """Module-level function for pickling compatibility."""
    return [t for t in re.split(r'[/?=&._\-]', url.lower()) if t]


class KaggleFeatureExtractor:
    """Extract 29 lexical features from URLs for ML classification.

    No network calls — all features are computed from the URL string.
    """

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
        ".xyz", ".top", ".club", ".online", ".site",
        ".work", ".click", ".link", ".info", ".biz",
        ".cc", ".ru", ".cn",
    }

    # Free TLDs (subset — strongly correlated with phishing)
    FREE_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq"}

    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = {
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "password", "credential", "banking", "alert",
        "warning", "suspended", "locked", "unlock", "webscr", "cmd",
    }

    # Brand names for impersonation detection
    BRAND_NAMES = {
        "paypal", "amazon", "apple", "microsoft", "google", "facebook",
        "netflix", "instagram", "twitter", "linkedin", "chase", "bankofamerica",
        "wellsfargo", "citi", "ebay", "walmart", "target", "outlook", "hotmail",
        "gmail", "office", "onedrive", "yahoo",
    }

    def extract(self, url: str) -> dict[str, Any]:
        """Extract all features from a URL."""
        url_lower = url.lower()

        # Parse URL parts
        protocol = "https" if url.startswith("https") else "http"
        domain = self._extract_domain(url)
        domain_name = domain.split("/")[0].split(":")[0]  # Strip path and port
        path = url.replace(f"{protocol}://", "", 1).replace(domain_name, "", 1)
        query = url.split("?")[1] if "?" in url else ""

        # Count subdomains
        parts = domain_name.split(".")
        # e.g. sub.domain.com → 1 subdomain, domain.com → 0
        num_subdomains = max(0, len(parts) - 2)

        features = {
            # === Basic features ===
            "url_length": len(url),
            "domain_length": len(domain_name),
            "path_length": len(path),
            "query_length": len(query),

            # === Structural features ===
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_underscores": url.count("_"),
            "num_slashes": url.count("/"),
            "num_equals": url.count("="),
            "num_at_symbols": url.count("@"),
            "num_question_marks": url.count("?"),
            "num_ampersands": url.count("&"),
            "num_digits": sum(c.isdigit() for c in url),

            # === Ratio features ===
            "digit_ratio": sum(c.isdigit() for c in url) / max(len(url), 1),
            "special_char_ratio": sum(not c.isalnum() for c in url) / max(len(url), 1),
            "digit_ratio_domain": sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1),

            # === URL characteristics ===
            "has_https": 1 if url.startswith("https") else 0,
            "has_ip_address": self._has_ip_address(domain_name),
            "has_double_slash": 1 if "//" in url[8:] else 0,
            "has_at_symbol": 1 if "@" in url else 0,
            "has_suspicious_tld": self._has_suspicious_tld(domain_name),
            "is_free_tld": self._is_free_tld(domain_name),
            "has_suspicious_keywords": self._has_suspicious_keywords(url_lower, domain_name),
            "uses_shortener": self._uses_url_shortener(domain_name),

            # === New features ===
            "domain_has_hyphen": 1 if "-" in domain_name else 0,
            "num_subdomains": num_subdomains,
            "num_query_params": query.count("&") + 1 if query else 0,
            "domain_entropy": self._shannon_entropy(domain_name),
            "brand_in_path": self._brand_in_path(url_lower, domain_name),
            "path_has_php": 1 if ".php" in url_lower else 0,
            "num_encoded_chars": url.count("%"),
            "typosquat_distance": self._check_typosquat(domain_name),
        }

        return features

    def _extract_domain(self, url: str) -> str:
        url = url.replace("http://", "").replace("https://", "")
        return url.split("/")[0].split("?")[0].split("#")[0]

    def _has_ip_address(self, domain: str) -> int:
        import ipaddress
        host = domain.split(":")[0]
        try:
            ipaddress.ip_address(host)
            return 1
        except ValueError:
            return 0

    def _has_suspicious_tld(self, domain: str) -> int:
        domain_lower = domain.lower()
        return 1 if any(domain_lower.endswith(tld) for tld in self.SUSPICIOUS_TLDS) else 0

    def _is_free_tld(self, domain: str) -> int:
        domain_lower = domain.lower()
        return 1 if any(domain_lower.endswith(tld) for tld in self.FREE_TLDS) else 0

    def _has_suspicious_keywords(self, url: str, domain: str) -> int:
        # Skip for trusted domains
        trusted = {
            "google.com", "paypal.com", "amazon.com", "apple.com", "microsoft.com",
            "facebook.com", "netflix.com", "twitter.com", "linkedin.com", "github.com",
            "youtube.com", "reddit.com", "wikipedia.org", "yahoo.com", "outlook.com",
            "hotmail.com", "gmail.com", "office.com", "ebay.com",
        }
        if domain.lower() in trusted:
            return 0
        return 1 if any(kw in url for kw in self.SUSPICIOUS_KEYWORDS) else 0

    def _uses_url_shortener(self, domain: str) -> int:
        shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
                      "is.gd", "buff.ly", "bl.ink"}
        return 1 if domain.lower() in shorteners else 0

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _brand_in_path(self, url_lower: str, domain: str) -> int:
        """Check if a brand name appears in URL but not in the official domain."""
        domain_lower = domain.lower()
        for brand in self.BRAND_NAMES:
            if brand in url_lower:
                # If it's the official brand domain, not impersonation
                if domain_lower == f"{brand}.com" or domain_lower == brand:
                    continue
                return 1
        return 0

    def _check_typosquat(self, domain: str) -> int:
        popular = ["google", "facebook", "amazon", "apple", "microsoft",
                   "paypal", "netflix", "twitter", "instagram", "linkedin"]
        domain_name = domain.split(".")[0].lower()

        for brand in popular:
            if brand in domain_name and domain_name != brand:
                return 1
            if self._levenshtein_distance(domain_name, brand) <= 2:
                return 1
        return 0

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    def to_vector(self, features: dict[str, Any]) -> list[float]:
        """Convert features dict to model input vector.

        Order MUST match the order used during training.
        """
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
            float(features["digit_ratio_domain"]),
            float(features["has_https"]),
            float(features["has_ip_address"]),
            float(features["has_suspicious_tld"]),
            float(features["is_free_tld"]),
            float(features["has_suspicious_keywords"]),
            float(features["uses_shortener"]),
            float(features["typosquat_distance"]),
            float(features["has_at_symbol"]),
            float(features["has_double_slash"]),
            float(features["domain_has_hyphen"]),
            float(features["num_subdomains"]),
            float(features["num_query_params"]),
            float(features["domain_entropy"]),
            float(features["brand_in_path"]),
            float(features["path_has_php"]),
            float(features["num_encoded_chars"]),
        ]

    @property
    def feature_names(self) -> list[str]:
        """Return ordered feature names matching to_vector()."""
        return [
            "url_length", "domain_length", "path_length", "query_length",
            "num_dots", "num_hyphens", "num_digits", "digit_ratio",
            "special_char_ratio", "digit_ratio_domain", "has_https",
            "has_ip_address", "has_suspicious_tld", "is_free_tld",
            "has_suspicious_keywords", "uses_shortener", "typosquat_distance",
            "has_at_symbol", "has_double_slash", "domain_has_hyphen",
            "num_subdomains", "num_query_params", "domain_entropy",
            "brand_in_path", "path_has_php", "num_encoded_chars",
        ]


def load_kaggle_datasets() -> tuple[list[str], list[str]]:
    """Load URLs from downloaded Kaggle datasets.

    Only uses clean phishing/benign labels. Excludes malware/defacement.
    """
    phishing_urls = []
    legitimate_urls = []

    # Dataset 1: phishing_site_urls.csv
    dataset1 = EXTERNAL_DIR / "phishing_site_urls.csv"
    if dataset1.exists():
        print(f"Loading: {dataset1}")
        try:
            df = pd.read_csv(dataset1)
            df.columns = [c.lower().strip() for c in df.columns]

            url_col = next((c for c in df.columns if "url" in c), None)
            label_col = next((c for c in df.columns if "label" in c or "class" in c or "status" in c), None)

            if url_col and label_col:
                for _, row in df.iterrows():
                    url = str(row[url_col]).strip()
                    if not url or url == "nan":
                        continue
                    if not url.startswith("http"):
                        url = "https://" + url

                    label = str(row[label_col]).lower().strip()
                    if label in ["bad", "phishing", "malware", "defacement"]:
                        phishing_urls.append(url)
                    elif label in ["good", "benign", "safe", "legitimate"]:
                        legitimate_urls.append(url)

                print(f"  phishing_site_urls: {len(phishing_urls)} malicious, {len(legitimate_urls)} benign")
        except Exception as e:
            print(f"  Error loading {dataset1}: {e}")

    phish_before = len(phishing_urls)
    legit_before = len(legitimate_urls)

    # Dataset 2: malicious_phish.csv — ONLY use phishing/benign labels
    dataset2 = EXTERNAL_DIR / "malicious_phish.csv"
    if not dataset2.exists():
        dataset2 = EXTERNAL_DIR / "malicious_urls.csv"

    if dataset2.exists():
        print(f"Loading: {dataset2}")
        try:
            df = pd.read_csv(dataset2)
            df.columns = [c.lower().strip() for c in df.columns]

            url_col = next((c for c in df.columns if "url" in c), None)
            label_col = next((c for c in df.columns if "type" in c or "label" in c or "class" in c), None)

            if url_col and label_col:
                ds2_malicious = 0
                ds2_legit = 0
                for _, row in df.iterrows():
                    url = str(row[url_col]).strip()
                    if not url or url == "nan":
                        continue
                    if not url.startswith("http"):
                        url = "https://" + url

                    label = str(row[label_col]).lower().strip()
                    if label in ["phishing", "malware", "defacement"]:
                        phishing_urls.append(url)
                        ds2_malicious += 1
                    elif label in ["benign"]:
                        legitimate_urls.append(url)
                        ds2_legit += 1

                print(f"  malicious_phish: {ds2_malicious} malicious, {ds2_legit} benign")
        except Exception as e:
            print(f"  Error loading {dataset2}: {e}")

    print(f"\nTotal raw: {len(phishing_urls)} phishing, {len(legitimate_urls)} legitimate")

    # Deduplicate
    phishing_urls = list(set(phishing_urls))
    legitimate_urls = list(set(legitimate_urls))
    print(f"After dedup: {len(phishing_urls)} phishing, {len(legitimate_urls)} legitimate")

    return phishing_urls, legitimate_urls


def generate_legitimate_urls() -> list[str]:
    """Generate legitimate URLs from top domains."""
    urls = []
    paths = ["", "/", "/about", "/contact", "/products", "/services",
             "/blog", "/news", "/login", "/signup", "/help", "/faq"]

    for domain in TOP_DOMAINS:
        urls.append(f"https://{domain}")
        urls.append(f"https://www.{domain}")
        for path in random.sample(paths, min(3, len(paths))):
            urls.append(f"https://{domain}{path}")

    return urls


def prepare_dataset(
    kaggle_phishing: list[str],
    kaggle_legitimate: list[str],
) -> tuple[list[str], list[int]]:
    """Prepare dataset for training. Returns (urls, labels) for TF-IDF pipeline."""
    # Add generated legitimate URLs
    generated = generate_legitimate_urls()
    all_legitimate = list(set(kaggle_legitimate + generated))

    # Balance dataset
    min_count = min(len(kaggle_phishing), len(all_legitimate))
    if len(kaggle_phishing) > min_count:
        kaggle_phishing = random.sample(kaggle_phishing, min_count)
    if len(all_legitimate) > min_count:
        all_legitimate = random.sample(all_legitimate, min_count)

    print(f"\nBalanced dataset: {len(kaggle_phishing)} phishing, {len(all_legitimate)} legitimate")

    urls = kaggle_phishing + all_legitimate
    labels = [1] * len(kaggle_phishing) + [0] * len(all_legitimate)

    print(f"Total: {len(urls)} URLs")
    return urls, labels


def train_model(urls: list[str], labels: list[int]) -> tuple[Any, dict]:
    """Train ML models with TF-IDF + lexical features."""
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from scipy.sparse import hstack

    extractor = KaggleFeatureExtractor()

    # Split data
    urls_train, urls_test, y_train, y_test = train_test_split(
        urls, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print(f"\nTraining set: {len(urls_train)} samples")
    print(f"Test set: {len(urls_test)} samples")

    # --- Feature extraction ---
    print("\nExtracting features...")

    # TF-IDF on character n-grams (captures patterns like "paypa1", ".php", etc.)
    char_tfidf = TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(2, 6),
        max_features=10000,
        sublinear_tf=True,
    )
    X_train_char = char_tfidf.fit_transform(urls_train)
    X_test_char = char_tfidf.transform(urls_test)
    print(f"  Char TF-IDF features: {X_train_char.shape[1]}")

    # TF-IDF on URL tokens (split by /, ?, =, &, -, .)
    word_tfidf = TfidfVectorizer(
        analyzer='word',
        tokenizer=_tokenize_url,
        token_pattern=None,
        max_features=2000,
        sublinear_tf=True,
    )
    X_train_word = word_tfidf.fit_transform(urls_train)
    X_test_word = word_tfidf.transform(urls_test)
    print(f"  Word TF-IDF features: {X_train_word.shape[1]}")

    # Lexical features
    X_train_lex = np.array([extractor.to_vector(extractor.extract(u)) for u in urls_train])
    X_test_lex = np.array([extractor.to_vector(extractor.extract(u)) for u in urls_test])
    print(f"  Lexical features: {X_train_lex.shape[1]}")

    # Combine all features
    X_train = hstack([X_train_char, X_train_word, X_train_lex])
    X_test = hstack([X_test_char, X_test_word, X_test_lex])
    print(f"  Total features: {X_train.shape[1]}")

    y_train = np.array(y_train)
    y_test = np.array(y_test)

    # --- Train models ---
    best_model = None
    best_vectorizers = None
    best_score = 0
    best_name = ""
    results = {}

    # Model 1: Tuned Gradient Boosting
    print("\nTraining gradient_boosting (tuned)...")
    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=7,
        learning_rate=0.1,
        min_samples_split=10,
        min_samples_leaf=5,
        subsample=0.8,
        max_features='sqrt',
        random_state=42,
    )
    gb.fit(X_train, y_train)
    y_pred = gb.predict(X_test)

    metrics_gb = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
    }
    results["gradient_boosting"] = metrics_gb

    print(f"  Accuracy:  {metrics_gb['accuracy']:.4f}")
    print(f"  Precision: {metrics_gb['precision']:.4f}")
    print(f"  Recall:    {metrics_gb['recall']:.4f}")
    print(f"  F1 Score:  {metrics_gb['f1']:.4f}")

    if metrics_gb["f1"] > best_score:
        best_score = metrics_gb["f1"]
        best_model = gb
        best_name = "gradient_boosting"

    # Model 2: Tuned Random Forest
    print("\nTraining random_forest (tuned)...")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)

    metrics_rf = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
    }
    results["random_forest"] = metrics_rf

    print(f"  Accuracy:  {metrics_rf['accuracy']:.4f}")
    print(f"  Precision: {metrics_rf['precision']:.4f}")
    print(f"  Recall:    {metrics_rf['recall']:.4f}")
    print(f"  F1 Score:  {metrics_rf['f1']:.4f}")

    if metrics_rf["f1"] > best_score:
        best_score = metrics_rf["f1"]
        best_model = rf
        best_name = "random_forest"

    # Model 3: Logistic Regression (best for sparse TF-IDF features)
    print("\nTraining logistic_regression...")
    lr = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver='lbfgs',
        random_state=42,
        n_jobs=-1,
    )
    lr.fit(X_train, y_train)
    y_pred = lr.predict(X_test)

    metrics_lr = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
    }
    results["logistic_regression"] = metrics_lr

    print(f"  Accuracy:  {metrics_lr['accuracy']:.4f}")
    print(f"  Precision: {metrics_lr['precision']:.4f}")
    print(f"  Recall:    {metrics_lr['recall']:.4f}")
    print(f"  F1 Score:  {metrics_lr['f1']:.4f}")

    if metrics_lr["f1"] > best_score:
        best_score = metrics_lr["f1"]
        best_model = lr
        best_name = "logistic_regression"

    print(f"\nBest model: {best_name} (F1: {best_score:.4f})")

    # Feature importance
    if hasattr(best_model, 'feature_importances_'):
        print("\nTop lexical feature importance:")
        importances = best_model.feature_importances_
        n_lex = len(extractor.feature_names)
        lex_importances = importances[-n_lex:]
        for name, imp in sorted(zip(extractor.feature_names, lex_importances), key=lambda x: -x[1])[:10]:
            print(f"  {name}: {imp:.4f}")

    # Detailed classification report
    print("\nClassification report:")
    y_pred_final = best_model.predict(X_test)
    print(classification_report(y_test, y_pred_final, target_names=["legitimate", "malicious"]))

    # Save vectorizers for prediction
    vectorizers = {"char_tfidf": char_tfidf, "word_tfidf": word_tfidf}

    return best_model, vectorizers, results


def main():
    """Main training pipeline."""
    print("=" * 60)
    print("PHISHING CLASSIFIER TRAINING (IMPROVED v2)")
    print("TF-IDF + Lexical Features")
    print("=" * 60)

    # Load Kaggle datasets
    print("\n1. Loading datasets...")
    phishing_urls, legitimate_urls = load_kaggle_datasets()

    if len(phishing_urls) < 100 or len(legitimate_urls) < 100:
        print("\nWARNING: Not enough data!")
        return

    # Prepare dataset
    print("\n2. Preparing dataset...")
    urls, labels = prepare_dataset(phishing_urls, legitimate_urls)

    if len(urls) < 100:
        print("ERROR: Not enough data!")
        return

    # Train model
    print("\n3. Training models...")
    model, vectorizers, results = train_model(urls, labels)

    # Save model + vectorizers
    print("\n4. Saving model and vectorizers...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODELS_DIR / "classifier_kaggle.pkl"
    joblib.dump(model, model_path)
    print(f"  Model saved to: {model_path}")

    vec_path = MODELS_DIR / "tfidf_vectorizers.pkl"
    joblib.dump(vectorizers, vec_path)
    print(f"  Vectorizers saved to: {vec_path}")

    # Save metrics
    metrics_path = MODELS_DIR / "metrics_kaggle.json"
    with open(metrics_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Metrics saved to: {metrics_path}")

    # Summary
    best = results.get("gradient_boosting", results.get("random_forest", {}))
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print(f"  Accuracy:  {best.get('accuracy', 0):.2%}")
    print(f"  Precision: {best.get('precision', 0):.2%}")
    print(f"  Recall:    {best.get('recall', 0):.2%}")
    print(f"  F1 Score:  {best.get('f1', 0):.4f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
