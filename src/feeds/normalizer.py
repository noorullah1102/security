"""Data normalizer for threat feed aggregation.

Converts raw data from various threat feeds into a unified ThreatIndicator schema.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4
from urllib.parse import urlparse


@dataclass
class ThreatIndicatorData:
    """Normalized threat indicator from any feed source.

    This is the in-memory representation used before database persistence.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    url: str = ""
    threat_type: str = "phishing"  # phishing, malware, spam, other
    source: str = ""  # phishtank, urlhaus, reddit
    source_id: str | None = None  # Original ID from the source
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    target_brand: str | None = None  # Impersonated brand if detected
    confidence: float = 1.0  # 0.0 - 1.0
    metadata: dict[str, Any] = field(default_factory=dict)  # Source-specific data
    tags: list[str] = field(default_factory=list)  # Categorization tags

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization or database storage."""
        return {
            "id": self.id,
            "url": self.url,
            "threat_type": self.threat_type,
            "source": self.source,
            "source_id": self.source_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "target_brand": self.target_brand,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "tags": self.tags,
        }


class FeedNormalizer:
    """Normalizes raw feed data to unified ThreatIndicatorData schema."""

    # Common threat type mappings across feeds
    THREAT_TYPE_MAP = {
        # PhishTank
        "phishing": "phishing",
        # URLhaus
        "malware_download": "malware",
        "malware_download_2": "malware",
        "c2": "malware",
        "payload_delivery": "malware",
        "spam": "spam",
        # Generic
        "suspicious": "suspicious",
        "unknown": "other",
    }

    # Known brand domains for target detection
    BRAND_DOMAINS = {
        "paypal": "PayPal",
        "apple": "Apple",
        "microsoft": "Microsoft",
        "amazon": "Amazon",
        "google": "Google",
        "facebook": "Facebook",
        "meta": "Meta",
        "instagram": "Instagram",
        "twitter": "Twitter",
        "x.com": "X (Twitter)",
        "netflix": "Netflix",
        "spotify": "Spotify",
        "linkedin": "LinkedIn",
        "dropbox": "Dropbox",
        "adobe": "Adobe",
        "office": "Microsoft",
        "outlook": "Microsoft",
        "hotmail": "Microsoft",
        "live": "Microsoft",
        "yahoo": "Yahoo",
        "bank": "Banking",
        "chase": "Chase",
        "wells": "Wells Fargo",
        "citi": "Citibank",
        "dhl": "DHL",
        "fedex": "FedEx",
        "ups": "UPS",
        "usps": "USPS",
        "irs": "IRS",
        "gov": "Government",
    }

    def normalize_phishtank(self, raw_data: dict[str, Any]) -> ThreatIndicatorData | None:
        """Normalize PhishTank API response.

        PhishTank format:
        {
            "phish_id": "12345",
            "url": "http://example.com/phish",
            "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=12345",
            "submission_time": "2024-01-15T10:30:00+00:00",
            "verified": "yes",
            "verification_time": "2024-01-15T11:00:00+00:00",
            "online": "yes",
            "target": "PayPal"
        }
        """
        url = raw_data.get("url", "")
        if not url:
            return None

        # Parse timestamps
        first_seen = self._parse_timestamp(raw_data.get("submission_time"))
        last_seen = self._parse_timestamp(raw_data.get("verification_time")) or first_seen

        # Get target brand
        target = raw_data.get("target", "")
        target_brand = self._extract_brand(target) or self._extract_brand(url)

        # Build metadata
        metadata = {
            "phishtank_id": raw_data.get("phish_id"),
            "detail_url": raw_data.get("phish_detail_url"),
            "verified": raw_data.get("verified") == "yes",
            "online": raw_data.get("online") == "yes",
        }

        return ThreatIndicatorData(
            id=str(uuid4()),
            url=url,
            threat_type="phishing",
            source="phishtank",
            source_id=str(raw_data.get("phish_id", "")),
            first_seen=first_seen,
            last_seen=last_seen,
            target_brand=target_brand,
            confidence=1.0 if raw_data.get("verified") == "yes" else 0.7,
            metadata=metadata,
            tags=["phishing", "verified"] if raw_data.get("verified") == "yes" else ["phishing", "unverified"],
        )

    def normalize_urlhaus(self, raw_data: dict[str, Any]) -> ThreatIndicatorData | None:
        """Normalize URLhaus API response.

        URLhaus format:
        {
            "id": "12345",
            "url": "http://example.com/malware.exe",
            "url_status": "online",
            "date_added": "2024-01-15 10:30:00 UTC",
            "threat": "malware_download",
            "tags": ["exe", "trickbot"],
            "urlhaus_link": "https://urlhaus.abuse.ch/url/12345/",
            "host": "example.com",
            "reporter": "user123"
        }
        """
        url = raw_data.get("url", "")
        if not url:
            return None

        # Parse timestamp
        first_seen = self._parse_urlhaus_timestamp(raw_data.get("date_added", ""))

        # Map threat type
        threat = raw_data.get("threat", "other")
        threat_type = self.THREAT_TYPE_MAP.get(threat.lower(), "other")

        # Get target brand from URL
        target_brand = self._extract_brand(url)

        # Build tags
        tags = [threat_type]
        if raw_data.get("tags"):
            tags.extend(raw_data.get("tags", []))

        metadata = {
            "urlhaus_id": raw_data.get("id"),
            "url_status": raw_data.get("url_status"),
            "urlhaus_link": raw_data.get("urlhaus_link"),
            "host": raw_data.get("host"),
            "reporter": raw_data.get("reporter"),
        }

        return ThreatIndicatorData(
            id=str(uuid4()),
            url=url,
            threat_type=threat_type,
            source="urlhaus",
            source_id=str(raw_data.get("id", "")),
            first_seen=first_seen,
            last_seen=first_seen,
            target_brand=target_brand,
            confidence=0.9,
            metadata=metadata,
            tags=tags,
        )

    def normalize_reddit(self, raw_data: dict[str, Any]) -> ThreatIndicatorData | None:
        """Normalize Reddit post/comment data.

        Expected format:
        {
            "post_id": "abc123",
            "url": "http://suspicious-site.com",
            "title": "Found this phishing site",
            "subreddit": "cybersecurity",
            "author": "user123",
            "created_utc": 1705315800,
            "score": 42,
            "num_comments": 5,
            "permalink": "/r/cybersecurity/comments/abc123/"
        }
        """
        url = raw_data.get("url", "")
        if not url:
            return None

        # Skip URLs that are likely just Reddit internal links
        if "reddit.com" in url or "redd.it" in url:
            return None

        # Parse timestamp (Reddit uses Unix timestamp)
        created_utc = raw_data.get("created_utc", 0)
        first_seen = datetime.utcfromtimestamp(created_utc) if created_utc else datetime.utcnow()

        # Extract threat type from title
        title = raw_data.get("title", "").lower()
        threat_type = "other"
        if "phish" in title:
            threat_type = "phishing"
        elif "malware" in title or "ransomware" in title:
            threat_type = "malware"
        elif "scam" in title or "fraud" in title:
            threat_type = "spam"

        # Calculate confidence based on engagement
        score = raw_data.get("score", 0)
        confidence = min(0.5 + (score / 100), 0.95)  # Cap at 0.95

        target_brand = self._extract_brand(url) or self._extract_brand(title)

        metadata = {
            "post_id": raw_data.get("post_id"),
            "title": raw_data.get("title"),
            "subreddit": raw_data.get("subreddit"),
            "author": raw_data.get("author"),
            "score": score,
            "num_comments": raw_data.get("num_comments"),
            "permalink": f"https://reddit.com{raw_data.get('permalink', '')}",
        }

        return ThreatIndicatorData(
            id=str(uuid4()),
            url=url,
            threat_type=threat_type,
            source="reddit",
            source_id=raw_data.get("post_id"),
            first_seen=first_seen,
            last_seen=datetime.utcnow(),
            target_brand=target_brand,
            confidence=confidence,
            metadata=metadata,
            tags=["community-reported", threat_type],
        )

    def normalize(self, source: str, raw_data: dict[str, Any]) -> ThreatIndicatorData | None:
        """Normalize data from any source.

        Args:
            source: Feed source name (phishtank, urlhaus, reddit)
            raw_data: Raw data from the feed

        Returns:
            Normalized ThreatIndicatorData or None if invalid
        """
        normalizers = {
            "phishtank": self.normalize_phishtank,
            "urlhaus": self.normalize_urlhaus,
            "reddit": self.normalize_reddit,
        }

        normalizer = normalizers.get(source)
        if not normalizer:
            raise ValueError(f"Unknown feed source: {source}")

        return normalizer(raw_data)

    def normalize_batch(
        self, source: str, raw_data_list: list[dict[str, Any]]
    ) -> list[ThreatIndicatorData]:
        """Normalize multiple items from a feed.

        Args:
            source: Feed source name
            raw_data_list: List of raw data items

        Returns:
            List of normalized indicators (invalid items are skipped)
        """
        results = []
        for raw_data in raw_data_list:
            try:
                indicator = self.normalize(source, raw_data)
                if indicator:
                    results.append(indicator)
            except Exception:
                # Skip invalid items silently
                continue
        return results

    def _parse_timestamp(self, timestamp: str | None) -> datetime:
        """Parse ISO format timestamp."""
        if not timestamp:
            return datetime.utcnow()

        # Try various formats
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp, fmt)
                # Convert to UTC if timezone-aware
                if dt.tzinfo:
                    dt = dt.replace(tzinfo=None)
                return dt
            except ValueError:
                continue

        return datetime.utcnow()

    def _parse_urlhaus_timestamp(self, timestamp: str) -> datetime:
        """Parse URLhaus timestamp format: '2024-01-15 10:30:00 UTC'."""
        if not timestamp:
            return datetime.utcnow()

        try:
            # Remove ' UTC' suffix if present
            ts = timestamp.replace(" UTC", "").strip()
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.utcnow()

    def _extract_brand(self, text: str) -> str | None:
        """Extract target brand from URL or text.

        Args:
            text: URL or text to analyze

        Returns:
            Detected brand name or None
        """
        if not text:
            return None

        text_lower = text.lower()

        # Check for known brand patterns
        for brand_key, brand_name in self.BRAND_DOMAINS.items():
            if brand_key in text_lower:
                return brand_name

        return None
