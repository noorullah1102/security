"""Database models using SQLAlchemy."""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, mapped_column
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    """Base model with common fields."""

    __abstract__ = True
    __allow_unmapped__ = True

    id = Column(Text, primary_key=True, default=lambda: str(uuid4()))
    created_at = Column(DateTime, default=lambda: datetime.utcnow())


class ScanRecord(Base):
    """Database record for scan history."""

    __tablename__ = "scan_history"

    id = mapped_column(Text, primary_key=True)
    url = mapped_column(Text, nullable=False)
    verdict = mapped_column(Text, nullable=False)  # safe, phishing, suspicious
    confidence = mapped_column(Float, nullable=False)
    severity = mapped_column(String, nullable=True)  # low, medium, high, critical
    features = mapped_column(JSON, nullable=False)
    ai_explanation = mapped_column(JSON, nullable=True)
    target_brand = mapped_column(Text, nullable=True)
    user_id = mapped_column(Text, nullable=True)
    ip_address = mapped_column(Text, nullable=True)


class ThreatIndicator(Base):
    """Cached threat indicator from external feeds."""

    __tablename__ = "threat_indicators"

    id = mapped_column(Text, primary_key=True)
    url = mapped_column(Text, nullable=False)
    threat_type = mapped_column(Text, nullable=False)  # phishing, malware, spam, other
    source = mapped_column(Text, nullable=False)  # phishtank, urlhaus, reddit
    source_id = mapped_column(Text, nullable=True)
    first_seen = mapped_column(DateTime, nullable=False)
    last_seen = mapped_column(DateTime, nullable=False)
    target_brand = mapped_column(Text, nullable=True)
    confidence = mapped_column(Float, default=1.0)
    extra_data = mapped_column(JSON, nullable=True)
    tags = mapped_column(JSON, nullable=True)


class FeedStatus(Base):
    """Tracks health of threat feed sources."""

    __tablename__ = "feed_status"

    source = mapped_column(Text, primary_key=True)  # phishtank, urlhaus, reddit
    status = mapped_column(Text, nullable=False)  # healthy, degraded, error
    last_update = mapped_column(DateTime, nullable=True)
    last_attempt = mapped_column(DateTime, nullable=True)
    indicator_count = mapped_column(Integer, default=0)
    error_count = mapped_column(Integer, default=0)
    last_error = mapped_column(Text, nullable=True)


class APIKey(Base):
    """API key for authentication."""

    __tablename__ = "api_keys"

    key = mapped_column(Text, primary_key=True)
    name = mapped_column(Text, nullable=False)
    user_id = mapped_column(Text, nullable=True)
    is_active = mapped_column(Integer, default=1)
    rate_limit = mapped_column(Integer, default=100)
    expires_at = mapped_column(DateTime, nullable=True)
    last_used_at = mapped_column(DateTime, nullable=True)


class ExplanationCache(Base):
    """Caches AI explanations to reduce API costs."""

    __tablename__ = "explanation_cache"

    feature_hash = mapped_column(Text, primary_key=True)
    explanation = mapped_column(JSON, nullable=False)
    created_at = mapped_column(DateTime, nullable=False)
    expires_at = mapped_column(DateTime, nullable=False)
