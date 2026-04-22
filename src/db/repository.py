"""Database repository for scan history and threat indicators."""

from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from structlog import get_logger

from src.db.models import (
    APIKey,
    ExplanationCache,
    FeedStatus,
    ScanRecord,
    ThreatIndicator,
)

logger = get_logger()


class Database:
    """Database connection wrapper."""

    def __init__(self, engine):
        """Initialize database wrapper.

        Args:
            engine: SQLAlchemy engine
        """
        self.engine = engine
        self.SessionLocal = sessionmaker(bind=engine)

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Get a new database session as context manager."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def close(self) -> None:
        """Dispose of the engine."""
        self.engine.dispose()


class ScanRepository:
    """Repository for scan history operations."""
    def __init__(self, db: Database):
        """Initialize repository.
        Args:
            db: Database instance
        """
        self.db = db
    def save(
        self,
        url: str,
        verdict: str,
        confidence: float,
        features: dict,
        severity: str | None = None,
        ai_explanation: dict | None = None,
        target_brand: str | None = None,
    ) -> str:
        """Save a scan record.

        Args:
            url: Scanned URL
            verdict: Scan verdict (safe/phishing/suspicious)
            confidence: Confidence score
            features: Extracted features dict
            severity: Severity level (optional)
            ai_explanation: AI explanation dict (optional)
            target_brand: Target brand for phishing (optional)

        Returns:
            The scan ID
        """
        scan_id = str(uuid4())
        with self.db.get_session() as session:
            scan = ScanRecord(
                id=scan_id,
                url=url,
                verdict=verdict,
                confidence=confidence,
                severity=severity,
                features=features,
                ai_explanation=ai_explanation,
                target_brand=target_brand,
                created_at=datetime.utcnow(),
            )
            session.add(scan)
            session.commit()
            logger.debug("Scan saved", scan_id=scan_id, url=url)
            return scan_id

    def get_by_id(self, scan_id: str) -> dict | None:
        """Get scan by ID.
        Args:
            scan_id: Scan identifier
        Returns:
            Scan dict or None
        """
        with self.db.get_session() as session:
            record = session.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
            if record:
                return {
                    "id": record.id,
                    "url": record.url,
                    "verdict": record.verdict,
                    "confidence": record.confidence,
                    "severity": record.severity,
                    "features": record.features,
                    "ai_explanation": record.ai_explanation,
                    "target_brand": record.target_brand,
                    "created_at": record.created_at.isoformat() if record.created_at else None,
                }
            return None

    def get_by_url(self, url: str) -> dict | None:
        """Get most recent scan by URL.
        Args:
            url: URL to search for
        Returns:
            Scan dict or None
        """
        with self.db.get_session() as session:
            record = (
                session.query(ScanRecord)
                .filter(ScanRecord.url == url)
                .order_by(ScanRecord.created_at.desc())
                .first()
            )
            if record:
                return {
                    "id": record.id,
                    "url": record.url,
                    "verdict": record.verdict,
                    "confidence": record.confidence,
                    "severity": record.severity,
                    "features": record.features,
                    "ai_explanation": record.ai_explanation,
                    "target_brand": record.target_brand,
                    "created_at": record.created_at.isoformat() if record.created_at else None,
                }
            return None
    def get_recent(
        self,
        limit: int = 20,
        offset: int = 0,
        verdict: str | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        """Get recent scans with optional filters.
        Args:
            limit: Maximum number of results
            offset: Pagination offset
            verdict: Filter by verdict (optional)
            severity: Filter by severity (optional)
        Returns:
            List of scan dictionaries
        """
        with self.db.get_session() as session:
            query = session.query(ScanRecord)
            if verdict:
                query = query.filter(ScanRecord.verdict == verdict)
            if severity:
                query = query.filter(ScanRecord.severity == severity)
            records = (
                query.order_by(ScanRecord.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            # Convert to dicts within session to avoid detachment issues
            return [
                {
                    "id": r.id,
                    "url": r.url,
                    "verdict": r.verdict,
                    "confidence": r.confidence,
                    "severity": r.severity,
                    "features": r.features,
                    "ai_explanation": r.ai_explanation,
                    "target_brand": r.target_brand,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in records
            ]
    def search(self, query: str, limit: int = 20) -> list[dict]:
        """Search scans by URL substring.
        Args:
            query: Search query string
            limit: Maximum number of results
        Returns:
            List of scan dictionaries
        """
        with self.db.get_session() as session:
            records = (
                session.query(ScanRecord)
                .filter(ScanRecord.url.contains(query))
                .order_by(ScanRecord.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "url": r.url,
                    "verdict": r.verdict,
                    "confidence": r.confidence,
                    "severity": r.severity,
                    "features": r.features,
                    "ai_explanation": r.ai_explanation,
                    "target_brand": r.target_brand,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in records
            ]
    def get_stats(self, days: int = 7) -> dict[str, Any]:
        """Get scan statistics for the past N days.
        Args:
            days: Number of days to include
        Returns:
            Dictionary with statistics
        """
        with self.db.get_session() as session:
            from datetime import timedelta
            start_date = datetime.utcnow() - timedelta(days=days)
            # Total scans
            total = session.query(ScanRecord).filter(
                ScanRecord.created_at >= start_date
            ).count()
            # Phishing detected
            phishing = (
                session.query(ScanRecord)
                .filter(ScanRecord.created_at >= start_date)
                .filter(ScanRecord.verdict == "phishing")
                .count()
            )
            # Safe URLs
            safe = (
                session.query(ScanRecord)
                .filter(ScanRecord.created_at >= start_date)
                .filter(ScanRecord.verdict == "safe")
                .count()
            )
            # Suspicious URLs
            suspicious = (
                session.query(ScanRecord)
                .filter(ScanRecord.created_at >= start_date)
                .filter(ScanRecord.verdict == "suspicious")
                .count()
            )
            # Average confidence
            avg_confidence_result = (
                session.query(ScanRecord.confidence)
                .filter(ScanRecord.created_at >= start_date)
                .first()
            )
            avg_confidence = float(avg_confidence_result[0]) if avg_confidence_result else 0.0
            return {
                "total_scans": total,
                "phishing_detected": phishing,
                "safe_urls": safe,
                "suspicious": suspicious,
                "avg_confidence": avg_confidence,
                "period_days": days,
            }
    def create_from_analysis(
        self,
        url: str,
        verdict: str,
        confidence: float,
        features: dict,
        severity: str | None = None,
        ai_explanation: dict | None = None,
        target_brand: str | None = None,
        user_id: str | None = None,
        ip_address: str | None = None,
    ) -> ScanRecord:
        """Create a ScanRecord from analysis result.
        Args:
            url: Analyzed URL
            verdict: Verdict (safe/phishing/suspicious)
            confidence: Confidence score
            features: Extracted features dict
            severity: Severity level
            ai_explanation: AI explanation dict
            target_brand: Target brand if detected
            user_id: User ID if authenticated
            ip_address: Client IP address
        Returns:
            ScanRecord instance
        """
        return ScanRecord(
            id=str(uuid4()),
            url=url,
            verdict=verdict,
            confidence=confidence,
            severity=severity,
            features=features,
            ai_explanation=ai_explanation,
            target_brand=target_brand,
            user_id=user_id,
            ip_address=ip_address,
        )
class ThreatIndicatorRepository:
    """Repository for threat indicators."""
    def __init__(self, db: Database):
        """Initialize repository.
        Args:
            db: Database instance
        """
        self.db = db
    def save(self, indicator: ThreatIndicator) -> str:
        """Save a threat indicator.
        Args:
            indicator: ThreatIndicator to save
        Returns:
            The indicator ID
        """
        with self.db.get_session() as session:
            session.add(indicator)
            session.commit()
            return indicator.id
    def save_batch(self, indicators: list[ThreatIndicator]) -> int:
        """Save multiple threat indicators.
        Args:
            indicators: List of ThreatIndicator objects
        Returns:
            Number of indicators saved
        """
        with self.db.get_session() as session:
            session.add_all(indicators)
            session.commit()
            return len(indicators)
    def get_by_url(self, url: str) -> ThreatIndicator | None:
        """Get indicator by URL.
        Args:
            url: URL to search for
        Returns:
            ThreatIndicator or None
        """
        with self.db.get_session() as session:
            return (
                session.query(ThreatIndicator)
                .filter(ThreatIndicator.url == url)
                .first()
            )
    def get_recent(
        self,
        source: str | None = None,
        threat_type: str | None = None,
        limit: int = 100,
        since: datetime | None = None,
    ) -> list[ThreatIndicator]:
        """Get recent threat indicators.
        Args:
            source: Filter by source (optional)
            threat_type: Filter by threat type (optional)
            limit: Maximum number of results
            since: Only indicators after this datetime
        Returns:
            List of ThreatIndicator objects
        """
        with self.db.get_session() as session:
            query = session.query(ThreatIndicator)
            if source:
                query = query.filter(ThreatIndicator.source == source)
            if threat_type:
                query = query.filter(ThreatIndicator.threat_type == threat_type)
            if since:
                query = query.filter(ThreatIndicator.last_seen >= since)
            return (
                query.order_by(ThreatIndicator.last_seen.desc())
                .limit(limit)
                .all()
            )
    def dedupe_count(self) -> int:
        """Count duplicate URLs across sources.
        Returns:
            Number of duplicate URLs
        """
        with self.db.get_session() as session:
            return (
                session.query(ThreatIndicator.url)
                .group_by(ThreatIndicator.url)
                .having(ThreatIndicator.url.count() > 1)
                .count()
            )
class FeedStatusRepository:
    """Repository for feed status tracking."""
    def __init__(self, db: Database):
        """Initialize repository.
        Args:
            db: Database instance
        """
        self.db = db
    def get_status(self, source: str) -> FeedStatus | None:
        """Get status for a feed source.
        Args:
            source: Feed source name
        Returns:
            FeedStatus or None
        """
        with self.db.get_session() as session:
            return session.query(FeedStatus).filter(FeedStatus.source == source).first()
    def get_all_status(self) -> list[dict]:
        """Get status for all feed sources.
        Returns:
            List of feed status dictionaries
        """
        with self.db.get_session() as session:
            records = session.query(FeedStatus).all()
            return [
                {
                    "source": r.source,
                    "status": r.status,
                    "last_update": r.last_update,
                    "last_attempt": r.last_attempt,
                    "indicator_count": r.indicator_count,
                    "error_count": r.error_count,
                    "last_error": r.last_error,
                }
                for r in records
            ]
    def update_status(
        self,
        source: str,
        status: str,
        indicator_count: int | None = None,
        error: str | None = None,
    ) -> None:
        """Update feed status.
        Args:
            source: Feed source name
            status: Status (healthy/degraded/error)
            indicator_count: Number of indicators (optional)
            error: Error message if any
        """
        with self.db.get_session() as session:
            feed_status = session.query(FeedStatus).filter(FeedStatus.source == source).first()
            now = datetime.utcnow()
            if feed_status:
                feed_status.status = status
                feed_status.last_attempt = now
                if status == "healthy":
                    feed_status.last_update = now
                    feed_status.error_count = 0
                    feed_status.last_error = None
                if indicator_count is not None:
                    feed_status.indicator_count = indicator_count
                if error:
                    feed_status.error_count = (feed_status.error_count or 00) + 1
                    feed_status.last_error = error
            else:
                # Create new status record
                feed_status = FeedStatus(
                    source=source,
                    status=status,
                    last_update=now if status == "healthy" else None,
                    last_attempt=now,
                    indicator_count=indicator_count or 0,
                    error_count=1 if error else 0,
                    last_error=error,
                )
                session.add(feed_status)
            session.commit()
class ExplanationCacheRepository:
    """Repository for AI explanation caching."""
    def __init__(self, db: Database):
        """Initialize repository.
        Args:
            db: Database instance
        """
        self.db = db
    def get(self, feature_hash: str) -> dict | None:
        """Get cached explanation by feature hash.
        Args:
            feature_hash: Hash of URL features
        Returns:
            Cached explanation dict or None
        """
        with self.db.get_session() as session:
            cached = (
                session.query(ExplanationCache)
                .filter(ExplanationCache.feature_hash == feature_hash)
                .filter(ExplanationCache.expires_at > datetime.utcnow())
                .first()
            )
            if cached:
                return cached.explanation
            return None
    def set(self, feature_hash: str, explanation: dict, ttl_hours: int = 24) -> None:
        """Cache an explanation.
        Args:
            feature_hash: Hash of URL features
            explanation: Explanation to cache
            ttl_hours: Cache TTL in hours
        """
        from datetime import timedelta
        with self.db.get_session() as session:
            cached = ExplanationCache(
                feature_hash=feature_hash,
                explanation=explanation,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=ttl_hours),
            )
            session.merge(cached)
            session.commit()
    def cleanup_expired(self) -> int:
        """Remove expired cache entries.
        Returns:
            Number of entries removed
        """
        with self.db.get_session() as session:
            result = (
                session.query(ExplanationCache)
                .filter(ExplanationCache.expires_at < datetime.utcnow())
                .delete()
            )
            session.commit()
            return result.rowcount
class APIKeyRepository:
    """Repository for API key management."""
    def __init__(self, db: Database):
        """Initialize repository.
        Args:
            db: Database instance
        """
        self.db = db
    def get_by_key(self, key: str) -> APIKey | None:
        """Get API key by key value.
        Args:
            key: API key value
        Returns:
            APIKey or None
        """
        with self.db.get_session() as session:
            return session.query(APIKey).filter(APIKey.key == key).first()
    def validate_key(self, key: str) -> bool:
        """Validate an API key.
        Args:
            key: API key to validate
        Returns:
            True if valid, False otherwise
        """
        api_key = self.get_by_key(key)
        if api_key is None:
            return False
        if not api_key.is_active:
            return False
        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
            return False
        # Update last used timestamp
        with self.db.get_session() as session:
            api_key.last_used_at = datetime.utcnow()
            session.commit()
        return True
    def create_key(
        self,
        key: str,
        name: str,
        user_id: str | None = None,
        rate_limit: int = 100,
        expires_at: datetime | None = None,
    ) -> APIKey:
        """Create a new API key.
        Args:
            key: API key value
            name: Friendly name for the key
            user_id: Associated user ID
            rate_limit: Requests per minute limit
            expires_at: Expiration datetime
        Returns:
            APIKey instance
        """
        api_key = APIKey(
            key=key,
            name=name,
            user_id=user_id,
            rate_limit=rate_limit,
            expires_at=expires_at,
        )
        with self.db.get_session() as session:
            session.add(api_key)
            session.commit()
        return api_key
