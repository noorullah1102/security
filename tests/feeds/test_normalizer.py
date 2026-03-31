"""Tests for feed normalizer."""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.feeds.normalizer import FeedNormalizer, ThreatIndicatorData


@pytest.fixture
def normalizer():
    """Create normalizer instance."""
    return FeedNormalizer()


class TestThreatIndicatorData:
    """Tests for ThreatIndicatorData class."""

    def test_create_threat_indicator_data(self):
        """Test creating a threat indicator data instance."""
        indicator = ThreatIndicatorData(
            url="http://example.com/phish",
            threat_type="phishing",
            source="phishtank",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        assert indicator.url == "http://example.com/phish"
        assert indicator.threat_type == "phishing"
        assert indicator.source == "phishtank"
    def test_to_dict(self):
        """Test converting to dictionary."""
        indicator = ThreatIndicatorData(
            url="http://example.com/phish",
            threat_type="phishing",
            source="phishtank",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        data = indicator.to_dict()
        assert data["url"] == "http://example.com/phish"
        assert data["threat_type"] == "phishing"
        assert data["source"] == "phishtank"


class TestFeedNormalizer:
    """Tests for FeedNormalizer class."""

    def test_normalize_phishtank(self, normalizer):
        """Test normalizing PhishTank data."""
        raw_data = {
            "phish_id": "12345",
            "url": "http://example.com/phish",
            "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=12345",
            "submission_time": "2024-01-15T10:30:00+00:00",
            "verified": "yes",
            "verification_time": "2024-01-15T11:00:00+00:00",
            "online": "yes",
            "target": "PayPal",
        }
        result = normalizer.normalize_phishtank(raw_data)
        assert result is not None
        assert result.url == "http://example.com/phish"
        assert result.threat_type == "phishing"
        assert result.source == "phishtank"
        assert result.source_id == "12345"
        assert result.confidence == 1.0
        assert "phishing" in result.tags
        assert "verified" in result.tags

    def test_normalize_phishtank_unverified(self, normalizer):
        """Test normalizing unverified PhishTank entry."""
        raw_data = {
            "phish_id": "12345",
            "url": "http://example.com/phish",
            "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=12345",
            "submission_time": "2024-01-15T10:30:00+00:00",
            "verified": "no",
            "verification_time": "2024-01-15T11:00:00+00:00",
            "online": "yes",
            "target": "PayPal",
        }
        result = normalizer.normalize_phishtank(raw_data)
        assert result is not None
        assert result.confidence == 0.7
        assert "unverified" in result.tags
    def test_normalize_phishtank_missing_url(self, normalizer):
        """Test normalizing PhishTank entry with missing URL."""
        raw_data = {
            "phish_id": "12345",
            "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=12345",
            "submission_time": "2024-01-15T10:30:00+00:00",
            "verified": "yes",
            "verification_time": "2024-01-15T11:00:00+00:00",
            "online": "yes",
        }
        result = normalizer.normalize_phishtank(raw_data)
        assert result is None
    def test_normalize_phishtank_malformed_timestamp(self, normalizer):
        """Test normalizing PhishTank entry with malformed timestamp."""
        raw_data = {
            "phish_id": "12345",
            "url": "http://example.com/phish",
            "submission_time": "invalid-timestamp",
            "verified": "yes",
            "target": "PayPal",
        }
        result = normalizer.normalize_phishtank(raw_data)
        assert result is not None
        assert result.first_seen.year == datetime.utcnow().year
    def test_normalize_urlhaus(self, normalizer):
        """Test normalizing URLhaus entry."""
        raw_data = {
            "id": "12345",
            "url": "http://example.com/malware.exe",
            "url_status": "online",
            "date_added": "2024-01-15 10:30:00 UTC",
            "threat": "malware_download",
            "tags": ["exe", "trickbot"],
            "urlhaus_link": "https://urlhaus.abuse.ch/url/12345/",
            "host": "example.com",
            "reporter": "user123",
        }
        result = normalizer.normalize_urlhaus(raw_data)
        assert result is not None
        assert result.url == "http://example.com/malware.exe"
        assert result.threat_type == "malware"
        assert result.source == "urlhaus"
        assert result.source_id == "12345"
        assert result.confidence == 0.9
        assert "malware" in result.tags
        assert "exe" in result.tags
        assert "trickbot" in result.tags
    def test_normalize_urlhaus_missing_url(self, normalizer):
        """Test normalizing URLhaus entry with missing URL."""
        raw_data = {
            "id": "12345",
            "url": "",
            "url_status": "online",
            "date_added": "2024-01-15 10:30:00 UTC",
            "threat": "malware_download",
            "tags": ["exe", "trickbot"],
            "urlhaus_link": "https://urlhaus.abuse.ch/url/12345/",
            "host": "example.com",
            "reporter": "user123",
        }
        result = normalizer.normalize_urlhaus(raw_data)
        assert result is None
    def test_normalize_urlhaus_malformed_timestamp(self, normalizer):
        """Test normalizing URLhaus entry with malformed timestamp."""
        raw_data = {
            "id": "12345",
            "url": "http://example.com/malware.exe",
            "date_added": "not a valid timestamp",
            "threat": "malware_download",
        }
        result = normalizer.normalize_urlhaus(raw_data)
        assert result is not None
        assert result.first_seen.year == datetime.utcnow().year
    def test_normalize_reddit(self, normalizer):
        """Test normalizing Reddit entry."""
        raw_data = {
            "post_id": "abc123",
            "url": "http://suspicious-site.com",
            "title": "Found this phishing site",
            "subreddit": "cybersecurity",
            "author": "user123",
            "created_utc": 1705315800,
            "score": 42,
            "num_comments": 5,
            "permalink": "/r/cybersecurity/comments/abc123/",
        }
        result = normalizer.normalize_reddit(raw_data)
        assert result is not None
        assert result.url == "http://suspicious-site.com"
        assert result.threat_type == "phishing"
        assert result.source == "reddit"
        assert result.source_id == "abc123"
        assert result.target_brand is None
        assert result.confidence >= 0.5
        assert "phishing" in result.tags
        assert "community-reported" in result.tags
    def test_normalize_reddit_with_brand_in_title(self, normalizer):
        """Test normalizing Reddit entry with brand in title."""
        raw_data = {
            "post_id": "abc123",
            "url": "http://apple-phishing.com",
            "title": "Apple phishing scam detected",
            "subreddit": "cybersecurity",
            "author": "user123",
            "created_utc": 1705315800,
            "score": 42,
            "num_comments": 5,
            "permalink": "/r/cybersecurity/comments/abc123/",
        }
        result = normalizer.normalize_reddit(raw_data)
        assert result is not None
        assert result.target_brand == "Apple"
    def test_normalize_reddit_malware(self, normalizer):
        """Test normalizing Reddit entry with malware in title."""
        raw_data = {
            "post_id": "abc123",
            "url": "http://malware-site.com",
            "title": "New malware distribution campaign",
            "subreddit": "cybersecurity",
            "author": "user123",
            "created_utc": 1705315800,
            "score": 42,
            "num_comments": 5,
            "permalink": "/r/cybersecurity/comments/abc123/",
        }
        result = normalizer.normalize_reddit(raw_data)
        assert result is not None
        assert result.threat_type == "malware"
    def test_normalize_reddit_skip_reddit_urls(self, normalizer):
        """Test normalizing Reddit entry with Reddit internal URL."""
        raw_data = {
            "post_id": "abc123",
            "url": "https://reddit.com/r/cybersecurity/post",
            "title": "Found this phishing site",
            "subreddit": "cybersecurity",
            "author": "user123",
            "created_utc": 1705315800,
            "score": 42,
            "num_comments": 5,
            "permalink": "/r/cybersecurity/comments/abc123/",
        }
        result = normalizer.normalize_reddit(raw_data)
        assert result is None
    def test_normalize_reddit_empty_url(self, normalizer):
        """Test normalizing Reddit entry with empty URL."""
        raw_data = {
            "post_id": "abc123",
            "url": "",
            "title": "Found this phishing site",
            "subreddit": "cybersecurity",
            "author": "user123",
            "created_utc": 1705315800,
            "score": 42,
            "num_comments": 5,
            "permalink": "/r/cybersecurity/comments/abc123/",
        }
        result = normalizer.normalize_reddit(raw_data)
        assert result is None
    def test_normalize_unknown_source(self, normalizer):
        """Test normalizing with unknown source raises error."""
        with pytest.raises(ValueError, match="Unknown feed source"):
            normalizer.normalize("unknown", {})
    def test_normalize_batch(self, normalizer):
        """Test normalizing a batch of entries."""
        raw_data_list = [
            {"phish_id": "1", "url": "http://phish1.com", "submission_time": "2024-01-15T10:00:00Z", "verified": "yes", "target": "PayPal"},
            {"phish_id": "2", "url": "http://phish2.com", "submission_time": "2024-01-15T10:00:00Z", "verified": "yes", "target": "Apple"},
            {"phish_id": "3", "url": "", "submission_time": "2024-01-15T10:00:00Z"},  # Missing URL
        ]
        results = normalizer.normalize_batch("phishtank", raw_data_list)
        assert len(results) == 2
        assert results[0].url == "http://phish1.com"
        assert results[1].url == "http://phish2.com"
    def test_extract_brand_from_url(self, normalizer):
        """Test extracting brand from URL."""
        brand = normalizer._extract_brand("https://paypal-secure.com/login")
        assert brand == "PayPal"
        brand = normalizer._extract_brand("https://apple-id-verify.com")
        assert brand == "Apple"
    def test_extract_brand_from_text(self, normalizer):
        """Test extracting brand from text."""
        brand = normalizer._extract_brand("Login to your Microsoft account")
        assert brand == "Microsoft"
        brand = normalizer._extract_brand("Amazon gift card scam")
        assert brand == "Amazon"
