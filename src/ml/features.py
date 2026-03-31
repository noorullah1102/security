"""Feature engineering pipeline for ML model."""

import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

from src.analyzer.features import FeatureExtractor
from src.analyzer.models import URLFeatures


class FeaturePipeline:
    """Feature engineering pipeline for URL classification."""

    def __init__(self, model_dir: str = "models"):
        """Initialize feature pipeline.

        Args:
            model_dir: Directory to save/load pipeline artifacts
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.extractor = FeatureExtractor()
        self.scaler = StandardScaler()
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

    def extract_features(self, url: str) -> URLFeatures:
        """Extract features from a single URL.

        Args:
            url: URL to extract features from

        Returns:
            URLFeatures object
        """
        return self.extractor.extract(url)

    def features_to_vector(self, features: URLFeatures) -> np.ndarray:
        """Convert URLFeatures to numpy feature vector.

        Args:
            features: Extracted URL features

        Returns:
            Feature vector as numpy array
        """
        return np.array(features.to_feature_vector()).reshape(1, -1)

    def transform(self, features: URLFeatures) -> np.ndarray:
        """Transform features using fitted scaler.

        Args:
            features: Extracted URL features

        Returns:
            Scaled feature vector
        """
        vector = self.features_to_vector(features)
        return self.scaler.transform(vector)

    def fit_transform_batch(self, urls: list[str]) -> tuple[np.ndarray, list[str]]:
        """Extract and transform features for a batch of URLs.

        Args:
            urls: List of URLs to process

        Returns:
            Tuple of (feature_matrix, failed_urls)
        """
        features_list = []
        failed_urls = []

        for url in urls:
            try:
                features = self.extract_features(url)
                features_list.append(features.to_feature_vector())
            except Exception as e:
                failed_urls.append(url)
                continue

        if not features_list:
            return np.array([]), failed_urls

        X = np.array(features_list)
        X_scaled = self.scaler.fit_transform(X)

        return X_scaled, failed_urls

    def transform_batch(self, urls: list[str]) -> tuple[np.ndarray, list[URLFeatures], list[str]]:
        """Transform a batch of URLs (without fitting scaler).

        Args:
            urls: List of URLs to process

        Returns:
            Tuple of (feature_matrix, features_list, failed_urls)
        """
        features_list = []
        failed_urls = []

        for url in urls:
            try:
                features = self.extract_features(url)
                features_list.append(features)
            except Exception as e:
                failed_urls.append(url)
                continue

        if not features_list:
            return np.array([]), [], failed_urls

        X = np.array([f.to_feature_vector() for f in features_list])
        X_scaled = self.scaler.transform(X)

        return X_scaled, features_list, failed_urls

    def save(self) -> None:
        """Save pipeline artifacts."""
        joblib.dump(self.scaler, self.model_dir / "scaler.pkl")

        metadata = {
            "feature_names": self.feature_names,
        }
        with open(self.model_dir / "pipeline_metadata.json", "w") as f:
            json.dump(metadata, f)

    def load(self) -> None:
        """Load pipeline artifacts."""
        scaler_path = self.model_dir / "scaler.pkl"
        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)

        metadata_path = self.model_dir / "pipeline_metadata.json"
        if metadata_path.exists():
            with open(metadata_path) as f:
                metadata = json.load(f)
            self.feature_names = metadata.get("feature_names", self.feature_names)
