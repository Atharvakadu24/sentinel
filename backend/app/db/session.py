"""Database engine, connection pooling, and session management.

Implements Blueprint Section 4:
- SQLAlchemy 2.0 sync engine with connection pool (PostgreSQL / psycopg 3)
- Session factory with expire_on_commit=False
- Context-managed session_scope and FastAPI dependency provider
- Dialect-aware pooling (connection pooling for PostgreSQL, StaticPool for in-memory SQLite)
"""

from __future__ import annotations

import threading
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_global_engine: Engine | None = None
_engine_lock = threading.Lock()


def _create_engine_instance(
    url: str | None = None,
    echo: bool | None = None,
    pool_size: int | None = None,
    max_overflow: int | None = None,
) -> Engine:
    """Instantiate a new configured SQLAlchemy Engine based on database dialect."""
    settings = get_settings()
    target_url = url or settings.DATABASE_URL
    is_echo = settings.DB_ECHO if echo is None else echo

    kwargs: dict[str, Any] = {
        "echo": is_echo,
    }

    parsed_url = make_url(target_url)
    is_sqlite = parsed_url.get_backend_name() == "sqlite"

    if is_sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
        is_in_memory = (
            parsed_url.database is None
            or parsed_url.database == ""
            or parsed_url.database == ":memory:"
        )
        if is_in_memory:
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_size"] = settings.DB_POOL_SIZE if pool_size is None else pool_size
        kwargs["max_overflow"] = (
            settings.DB_MAX_OVERFLOW if max_overflow is None else max_overflow
        )
        kwargs["pool_pre_ping"] = True

    return create_engine(target_url, **kwargs)


def get_engine(
    database_url: str | None = None,
    echo: bool | None = None,
    pool_size: int | None = None,
    max_overflow: int | None = None,
) -> Engine:
    """Create or return cached SQLAlchemy engine.

    When invoked without custom parameters, returns the cached global Engine instance,
    creating it safely under a thread lock if it does not yet exist.
    When invoked with explicit configuration arguments, creates and returns a newly
    configured Engine instance without modifying the global singleton.
    """
    global _global_engine

    if (
        database_url is None
        and echo is None
        and pool_size is None
        and max_overflow is None
    ):
        if _global_engine is None:
            with _engine_lock:
                if _global_engine is None:
                    _global_engine = _create_engine_instance()
        return _global_engine

    return _create_engine_instance(
        url=database_url,
        echo=echo,
        pool_size=pool_size,
        max_overflow=max_overflow,
    )


def set_engine(engine: Engine | None) -> None:
    """Set or override the global engine singleton (used in test suites)."""
    global _global_engine
    with _engine_lock:
        if _global_engine is not None and _global_engine is not engine:
            _global_engine.dispose()
        _global_engine = engine


def dispose_engine(engine: Engine | None = None) -> None:
    """Dispose the connection pool for the given engine or the global singleton."""
    global _global_engine
    if engine is not None:
        engine.dispose()
        with _engine_lock:
            if engine is _global_engine:
                _global_engine = None
        return

    with _engine_lock:
        if _global_engine is not None:
            _global_engine.dispose()
            _global_engine = None


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Create a sessionmaker bound to the given or default engine.

    Configured with autocommit=False, autoflush=False, and expire_on_commit=False
    per Blueprint Section 4 architecture.
    """
    eng = engine or get_engine()
    return sessionmaker(
        bind=eng,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


@contextmanager
def session_scope(
    factory: sessionmaker[Session] | None = None,
) -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of database operations.

    Yields a Session, automatically committing active transactions upon normal exit,
    rolling back transactions if an unhandled exception is raised, and ensuring
    the session is always closed.
    """
    session_factory = factory or get_session_factory()
    session = session_factory()
    try:
        yield session
        if session.in_transaction():
            session.commit()
    except BaseException:
        if session.in_transaction():
            session.rollback()
        raise
    finally:
        session.close()


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a managed database session.

    Yields a Session within a transactional scope. Automatically commits
    upon successful completion of the request, rolls back on unhandled
    exceptions, and closes the session upon request termination.
    """
    with session_scope() as session:
        yield session
