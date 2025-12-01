"""Database connection management."""

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import settings

# Create engine
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_recycle=3600,
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialize database connection.

    This is called at startup to verify the database connection.
    """
    # Test connection
    with engine.connect() as conn:
        conn.execute("SELECT 1")


def get_session() -> Session:
    """Get a database session.

    Returns:
        A SQLAlchemy session. Caller is responsible for closing.

    Example:
        session = get_session()
        try:
            scan = session.query(Scan).get(scan_id)
            session.commit()
        finally:
            session.close()
    """
    return SessionLocal()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope around operations.

    Yields:
        A SQLAlchemy session

    Example:
        with session_scope() as session:
            scan = session.query(Scan).get(scan_id)
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
