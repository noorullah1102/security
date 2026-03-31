"""Explanation caching using SQLite."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from structlog import get_logger

logger = get_logger()


class ExplanationCache:
    """Cache for AI-generated explanations using SQLite."""

    def __init__(self, db_path: str = "data/cache.db", ttl_hours: int = 24):
        """Initialize the cache.

        Args:
            db_path: Path to SQLite database file
            ttl_hours: Cache time-to-live in hours
        """
        self.db_path = Path(db_path)
        self.ttl = timedelta(hours=ttl_hours)
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Ensure database and table exist."""
        import sqlite3

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS explanation_cache (
                cache_key TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                explanation_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_expires_at
            ON explanation_cache(expires_at)
        """)
        conn.commit()
        conn.close()

    def _compute_cache_key(self, url: str, features: dict[str, Any]) -> str:
        """Compute cache key from URL and features.

        Args:
            url: The analyzed URL
            features: Feature dictionary

        Returns:
            SHA256 hash as cache key
        """
        # Create a canonical representation for hashing
        key_data = {
            "url": url,
            "features": {
                k: v for k, v in sorted(features.items())
                if k not in ["redirect_chain", "ssl_issuer"]  # Exclude variable fields
            }
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get(self, url: str, features: dict[str, Any]) -> dict[str, Any] | None:
        """Get cached explanation if available and not expired.

        Args:
            url: The analyzed URL
            features: Feature dictionary

        Returns:
            Cached explanation dict or None
        """
        import sqlite3

        cache_key = self._compute_cache_key(url, features)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                """
                SELECT explanation_json, expires_at
                FROM explanation_cache
                WHERE cache_key = ?
                """,
                (cache_key,),
            )
            row = cursor.fetchone()
            conn.close()

            if row is None:
                logger.debug("Cache miss", cache_key=cache_key[:16])
                return None

            explanation_json, expires_at = row
            expires_at = datetime.fromisoformat(expires_at)

            if datetime.now(timezone.utc) > expires_at:
                logger.debug("Cache expired", cache_key=cache_key[:16])
                return None

            logger.debug("Cache hit", cache_key=cache_key[:16])
            return json.loads(explanation_json)

        except Exception as e:
            logger.warning("Cache read error", error=str(e))
            return None

    def set(
        self,
        url: str,
        features: dict[str, Any],
        explanation: dict[str, Any],
    ) -> None:
        """Cache an explanation.

        Args:
            url: The analyzed URL
            features: Feature dictionary
            explanation: Explanation dictionary to cache
        """
        import sqlite3

        cache_key = self._compute_cache_key(url, features)
        expires_at = datetime.now(timezone.utc) + self.ttl

        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                INSERT OR REPLACE INTO explanation_cache
                (cache_key, url, explanation_json, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (cache_key, url, json.dumps(explanation), expires_at.isoformat()),
            )
            conn.commit()
            conn.close()

            logger.debug("Cached explanation", cache_key=cache_key[:16], url=url)

        except Exception as e:
            logger.warning("Cache write error", error=str(e))

    def cleanup_expired(self) -> int:
        """Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        import sqlite3

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                """
                DELETE FROM explanation_cache
                WHERE expires_at < ?
                """,
                (datetime.now(timezone.utc).isoformat(),),
            )
            deleted = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted > 0:
                logger.info("Cleaned up expired cache entries", count=deleted)

            return deleted

        except Exception as e:
            logger.warning("Cache cleanup error", error=str(e))
            return 0

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        import sqlite3

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM explanation_cache")
            total_entries = cursor.fetchone()[0]

            cursor = conn.execute(
                """
                SELECT COUNT(*) FROM explanation_cache
                WHERE expires_at > ?
                """,
                (datetime.now(timezone.utc).isoformat(),),
            )
            active_entries = cursor.fetchone()[0]

            conn.close()

            return {
                "total_entries": total_entries,
                "active_entries": active_entries,
                "expired_entries": total_entries - active_entries,
                "ttl_hours": self.ttl.total_seconds() / 3600,
            }

        except Exception as e:
            logger.warning("Cache stats error", error=str(e))
            return {
                "total_entries": 0,
                "active_entries": 0,
                "expired_entries": 0,
                "ttl_hours": self.ttl.total_seconds() / 3600,
                "error": str(e),
            }
