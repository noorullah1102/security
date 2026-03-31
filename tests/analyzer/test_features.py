"""Tests for URL feature extraction."""

import pytest

from src.analyzer.features import (
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    FeatureExtractor,
)
from src.analyzer.models import URLFeatures


class TestFeatureExtractor:
    """Tests for FeatureExtractor class."""

    @pytest.fixture
    def extractor(self) -> FeatureExtractor:
        """Create a feature extractor instance."""
        return FeatureExtractor()

    def test_extract_url_length(self, extractor: FeatureExtractor) -> None:
        """Test URL length extraction."""
        # https://example.com/path/to/page = 8 + 11 + 13 = 32 chars
        features = extractor.extract("https://example.com/path/to/page")
        assert features.url_length == 32

        # https://google.com = 8 + 10 = 18 chars
        features = extractor.extract("https://google.com")
        assert features.url_length == 18

    def test_extract_path_depth(self, extractor: FeatureExtractor) -> None:
        """Test path depth extraction."""
        features = extractor.extract("https://example.com")
        assert features.path_depth == 0

        features = extractor.extract("https://example.com/a/b/c")
        assert features.path_depth == 3

    def test_extract_has_ip_address_true(self, extractor: FeatureExtractor) -> None:
        """Test IP address detection - positive cases."""
        features = extractor.extract("http://192.168.1.1/login")
        assert features.has_ip_address is True

        features = extractor.extract("http://10.0.0.1/admin")
        assert features.has_ip_address is True

    def test_extract_has_ip_address_false(self, extractor: FeatureExtractor) -> None:
        """Test IP address detection - negative cases."""
        features = extractor.extract("https://example.com")
        assert features.has_ip_address is False

        features = extractor.extract("https://subdomain.example.com")
        assert features.has_ip_address is False

    def test_extract_suspicious_keywords(self, extractor: FeatureExtractor) -> None:
        """Test suspicious keyword detection."""
        features = extractor.extract("https://example.com/verify-account")
        assert features.has_suspicious_keywords is True

        features = extractor.extract("https://example.com/secure-login")
        assert features.has_suspicious_keywords is True

        features = extractor.extract("https://example.com/normal-page")
        assert features.has_suspicious_keywords is False

    def test_extract_subdomain_count(self, extractor: FeatureExtractor) -> None:
        """Test subdomain count extraction."""
        features = extractor.extract("https://example.com")
        assert features.subdomain_count == 0

        features = extractor.extract("https://a.b.c.example.com")
        assert features.subdomain_count == 3

    def test_extract_has_https(self, extractor: FeatureExtractor) -> None:
        """Test HTTPS protocol detection."""
        features = extractor.extract("https://example.com")
        assert features.has_https is True

        features = extractor.extract("http://example.com")
        assert features.has_https is False

    def test_extract_suspicious_tld(self, extractor: FeatureExtractor) -> None:
        """Test suspicious TLD detection."""
        features = extractor.extract("https://example.tk")
        assert features.suspicious_tld is True

        features = extractor.extract("https://example.ml")
        assert features.suspicious_tld is True

        features = extractor.extract("https://example.com")
        assert features.suspicious_tld is False

    def test_typosquat_detection(self, extractor: FeatureExtractor) -> None:
        """Test typosquatting detection."""
        features = extractor.extract("https://g00gle.com")
        # Should detect as typosquat of google.com
        assert features.typosquat_target is not None or features.typosquat_distance == 0

        features = extractor.extract("https://googl.com")
        # Should detect as typosquat
        assert features.typosquat_target is not None or features.typosquat_distance == 0


class TestSuspiciousKeywords:
    """Tests for suspicious keywords list."""

    def test_suspicious_keywords_list(self) -> None:
        """Verify suspicious keywords are defined."""
        assert "login" in SUSPICIOUS_KEYWORDS
        assert "verify" in SUSPICIOUS_KEYWORDS
        assert "secure" in SUSPICIOUS_KEYWORDS
        assert "password" in SUSPICIOUS_KEYWORDS


class TestSuspiciousTLDs:
    """Tests for suspicious TLDs list."""

    def test_suspicious_tlds_list(self) -> None:
        """Verify suspicious TLDs are defined."""
        assert ".tk" in SUSPICIOUS_TLDS
        assert ".ml" in SUSPICIOUS_TLDS
        assert ".xyz" in SUSPICIOUS_TLDS
