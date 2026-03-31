"""Database manager with connection pooling and initialization."""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, scoped_session
from structlog import get_logger

from src.config import get_settings
from src.db.migrations import run_migration
from src.db.repository import Database, ScanRepository

logger = get_logger()


class DatabaseManager:
    """Manages database connections and sessions."""

    _instance: "DatabaseManager | None" = None
    _database: Database | None = None
    _session_factory: sessionmaker | None = None
    _engine: Engine | None = None

    def __init__(self, database_url: str | None = None):
        """Initialize database manager.

        Args:
            database_url: Database connection URL (defaults to config)
        """
        settings = get_settings()
        self.database_url = database_url or settings.database_url
        self._engine = create_engine(
            self.database_url,
            echo=settings.is_development,
            pool_pre_ping=True,
            pool_recycle=-1,
        )
        self._session_factory = sessionmaker(bind=self._engine)
        self._database = Database(self._engine)
        run_migration(self._engine)
        logger.info("Database initialized", url=self.database_url)

    def get_session(self) -> scoped_session:
        """Get a new database session.

        Returns:
            SQLAlchemy scoped session
        """
        return scoped_session(self._session_factory)

    def close(self) -> None:
        """Close database connection."""
        self._engine.dispose()

    @classmethod
    def get_instance(cls) -> "DatabaseManager":
        """Get singleton instance of database manager.

        Returns:
            DatabaseManager instance
        """
        if cls._instance is None:
            cls._instance = DatabaseManager()
        return cls._instance

    @classmethod
    def get_database(cls) -> Database:
        """Get database instance.

        Returns:
            Database instance
        """
        return cls.get_instance()._database
    @classmethod
    def get_session_generator(cls) -> Generator[scoped_session, None, None]:
        """Get a session generator.

        Returns:
            SQLAlchemy scoped session generator
        """
        instance = cls.get_instance()
        yield from scoped_session(instance._session_factory)

    @classmethod
    def get_scan_repository(cls) -> ScanRepository:
        """Get scan repository instance.

        Returns:
            ScanRepository for scan history
        """
        return ScanRepository(cls.get_database())
