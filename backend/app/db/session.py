"""Database engine, connection pooling, and session management.

Implements Blueprint Section 4:
- SQLAlchemy 2.0 sync engine with connection pool
- Session factory with expire_on_commit=False
- Dependency provider for FastAPI routes
"""

from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_engine(database_url: str | None = None) -> Engine:
    """Create or return cached SQLAlchemy engine."""
    settings = get_settings()
    url = database_url or settings.DATABASE_URL

    # Pool arguments only apply to network databases (like PostgreSQL)
    is_sqlite = url.startswith("sqlite")
    kwargs: dict[str, Any] = {
        "echo": settings.DB_ECHO,
    }
    if not is_sqlite:
        kwargs["pool_size"] = settings.DB_POOL_SIZE
        kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
        kwargs["pool_pre_ping"] = True

    return create_engine(url, **kwargs)


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Create a sessionmaker bound to the given or default engine."""
    eng = engine or get_engine()
    return sessionmaker(
        bind=eng,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a managed database session."""
    factory = get_session_factory()
    with factory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
