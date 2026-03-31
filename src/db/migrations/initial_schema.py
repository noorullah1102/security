"""Initial database migration."""

from structlog import get_logger
from sqlalchemy import text

logger = get_logger()


def run_migration(engine):
    """Run database migration."""
    with engine.connect() as conn:
        # Create scan_history table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                severity TEXT,
                features TEXT NOT NULL,
                ai_explanation TEXT,
                target_brand TEXT,
                user_id TEXT,
                ip_address TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_url ON scan_history(url)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_verdict ON scan_history(verdict)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON scan_history(created_at)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_severity ON scan_history(severity)
        """))

        # Create threat_indicators table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source TEXT NOT NULL,
                source_id TEXT,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                target_brand TEXT,
                confidence REAL NOT NULL DEFAULT 1.0,
                metadata TEXT,
                tags TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_indicators_url_source
            ON threat_indicators(url, source)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_threat_indicators_source ON threat_indicators(source)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_threat_indicators_threat_type ON threat_indicators(threat_type)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_threat_indicators_first_seen ON threat_indicators(first_seen)
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_threat_indicators_last_seen ON threat_indicators(last_seen)
        """))

        # Create feed_status table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS feed_status (
                source TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                last_update TIMESTAMP,
                last_attempt TIMESTAMP,
                indicator_count INTEGER DEFAULT 0,
                error_count INTEGER DEFAULT 0,
                last_error TEXT,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """))

        # Create api_keys table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                user_id TEXT,
                is_active INTEGER DEFAULT 1,
                rate_limit INTEGER DEFAULT 100,
                expires_at TIMESTAMP,
                last_used_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """))

        # Create explanation_cache table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS explanation_cache (
                feature_hash TEXT PRIMARY KEY,
                explanation TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_explanation_cache_expires ON explanation_cache(expires_at)
        """))

        conn.commit()
    logger.info("Database migration completed")
