"""Basic tests for feature extraction constants."""

import pytest
from src.analyzer.features import FeatureExtractor, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS


class TestFeatureExtractor:
    """Tests for FeatureExtractor class."""

    @pytest.fixture
    def extractor(self):
        """Create a feature extractor instance."""
        return FeatureExtractor()

    def test_extract_url_length(self, extractor):
        """Test URL length extraction."""
        features = extractor.extract("https://example.com/path/to/page")
        assert features.url_length == 32

        features = extractor.extract("https://google.com")
        assert features.url_length == 18

    def test_extract_path_depth(self, extractor):
        """Test path depth extraction."""
        features = extractor.extract("https://example.com")
        assert features.path_depth == 0

        features = extractor.extract("https://example.com/a/b/c")
        assert features.path_depth == 3

    def test_extract_has_ip_address_true(self, extractor):
        """Test IP address detection - positive cases."""
        features = extractor.extract("http://192.168.1.1/login")
        assert features.has_ip_address is True

        features = extractor.extract("http://10.0.0.1/admin")
        assert features.has_ip_address is True

    def test_extract_has_ip_address_false(self, extractor):
        """Test IP address detection - negative cases."""
        features = extractor.extract("https://example.com")
        assert features.has_ip_address is False

        features = extractor.extract("https://subdomain.example.com")
        assert features.has_ip_address is False

    def test_extract_has_https(self, extractor):
        """Test HTTPS protocol detection."""
        features = extractor.extract("https://example.com")
        assert features.has_https is True

        features = extractor.extract("http://example.com")
        assert features.has_https is False

    def test_extract_suspicious_tld(self, extractor):
        """Test suspicious TLD detection."""
        features = extractor.extract("https://example.tk")
        assert features.suspicious_tld is True

        features = extractor.extract("https://example.ml")
        assert features.suspicious_tld is True

        features = extractor.extract("https://example.com")
        assert features.suspicious_tld is False


class TestSuspiciousKeywords:
    """Tests for suspicious keywords list."""

    def test_suspicious_keywords_list(self):
        """Verify suspicious keywords are defined."""
        assert "login" in SUSPICIOUS_KEYWORDS
        assert "verify" in SUSPICIOUS_KEYWORDS
        assert "secure" in SUSPICIOUS_KEYWORDS
        assert "password" in SUSPICIOUS_KEYWORDS


class TestSuspiciousTLDs:
    """Tests for suspicious TLDs list."""

    def test_suspicious_tlds_list(self):
        """Verify suspicious TLDs are defined."""
        assert ".tk" in SUSPICIOUS_TLDS
        assert ".ml" in SUSPICIOUS_TLDS
        assert ".xyz" in SUSPICIOUS_TLDS
