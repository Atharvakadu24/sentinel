"""Shared pytest fixtures and path configuration."""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

# Ensure backend root is on sys.path for direct imports
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import _create_engine_instance, get_session_factory

POSTGRES_TEST_ENV_VAR = "SENTINEL_TEST_DATABASE_URL"
EXPECTED_TEST_ALEMBIC_REVISION = "0003"
ALLOWED_POSTGRES_TEST_HOSTS = frozenset({"127.0.0.1", "localhost"})
EXACT_POSTGRES_TEST_DB = "sentinel_migration_test"


def validate_postgres_test_url(raw_url: str) -> tuple[URL, str]:
    """Parse and strictly validate SENTINEL_TEST_DATABASE_URL before connecting.

    Fail-closed rules:
    - Non-empty string without leading/trailing or embedded whitespace.
    - SQLAlchemy driver must be ``postgresql+psycopg``.
    - Host must be a loopback address (``127.0.0.1`` or ``localhost``).
    - No SQLAlchemy URL query parameters are permitted (blocks libpq overrides
      such as ``host``, ``hostaddr``, ``service``, ``options``, etc.).
    - Database name must be ``sentinel_migration_test`` or end with ``_test``.
    """
    if not raw_url or any(ch.isspace() for ch in raw_url):
        raise ValueError(
            f"{POSTGRES_TEST_ENV_VAR} must be a non-empty database URL without whitespace."
        )

    try:
        parsed = make_url(raw_url)
    except ArgumentError as exc:
        raise ValueError(f"{POSTGRES_TEST_ENV_VAR} is not a valid SQLAlchemy URL.") from exc

    if parsed.drivername != "postgresql+psycopg":
        raise ValueError(
            f"{POSTGRES_TEST_ENV_VAR} must use the 'postgresql+psycopg' driver "
            f"(got '{parsed.drivername}')."
        )

    host = (parsed.host or "").lower()
    if host not in ALLOWED_POSTGRES_TEST_HOSTS:
        raise ValueError(
            f"{POSTGRES_TEST_ENV_VAR} host must be '127.0.0.1' or 'localhost' "
            f"(got '{parsed.host or ''}')."
        )

    if parsed.query:
        raise ValueError(f"{POSTGRES_TEST_ENV_VAR} must not include URL query parameters.")

    database = parsed.database or ""
    if database != EXACT_POSTGRES_TEST_DB and not database.endswith("_test"):
        raise ValueError(
            f"{POSTGRES_TEST_ENV_VAR} database must be '{EXACT_POSTGRES_TEST_DB}' "
            f"or end with '_test' (got '{database}')."
        )

    return parsed, database


class PostgresRecordCleanup:
    """Tracks individual test-created primary keys for dependency-safe teardown cleanup."""

    def __init__(self) -> None:
        self._records: list[tuple[type[Any], uuid.UUID]] = []
        self._seen: set[tuple[type[Any], uuid.UUID]] = set()

    def track(self, model_cls: type[Any], record_id: uuid.UUID) -> uuid.UUID:
        """Record a created ORM entity ID for targeted, dependency-safe deletion."""
        if not hasattr(model_cls, "__table__") or not hasattr(model_cls, "id"):
            raise TypeError(f"Expected mapped ORM model with 'id' column, got {model_cls!r}.")
        if record_id is None:
            raise ValueError(
                f"Cannot track {model_cls.__name__} before primary key 'id' is populated."
            )

        key = (model_cls, record_id)
        if key not in self._seen:
            self._seen.add(key)
            self._records.append(key)
        return record_id

    @property
    def records(self) -> list[tuple[type[Any], uuid.UUID]]:
        """Return tracked (model_class, record_id) pairs in creation order."""
        return list(self._records)

    def ordered_records_for_delete(self) -> list[tuple[type[Any], uuid.UUID]]:
        """Order tracked records child-table-first, then reverse creation order.

        Uses SQLAlchemy table dependency metadata so child rows are always deleted
        before parent rows even if tracked out of order, while preserving reverse
        creation order within the same table (e.g. self-referential FKs).
        """
        if not self._records:
            return []

        metadata = self._records[0][0].__table__.metadata
        table_delete_rank = {
            table.name: rank for rank, table in enumerate(reversed(metadata.sorted_tables))
        }
        indexed = list(enumerate(self._records))
        indexed.sort(
            key=lambda item: (
                table_delete_rank.get(item[1][0].__table__.name, -1),
                -item[0],
            )
        )
        return [pair for _, pair in indexed]


@pytest.fixture(scope="session")
def pg_database_url() -> str:
    """Opt-in disposable PostgreSQL URL read exclusively from SENTINEL_TEST_DATABASE_URL.

    Never falls back to DATABASE_URL or Settings.DATABASE_URL.
    Skips when unset; fails closed on invalid or non-test URLs.
    """
    if POSTGRES_TEST_ENV_VAR not in os.environ:
        pytest.skip(f"{POSTGRES_TEST_ENV_VAR} is not set; skipping PostgreSQL integration tests.")

    raw_url = os.environ[POSTGRES_TEST_ENV_VAR]
    try:
        validate_postgres_test_url(raw_url)
    except ValueError as exc:
        pytest.fail(str(exc), pytrace=False)

    return raw_url


@pytest.fixture(scope="session")
def pg_engine(pg_database_url: str) -> Generator[Engine, None, None]:
    """Session-scoped PostgreSQL engine verified against DB identity and Alembic head."""
    _, expected_database = validate_postgres_test_url(pg_database_url)
    engine = _create_engine_instance(url=pg_database_url, echo=False)
    try:
        try:
            with engine.connect() as conn:
                actual_database = conn.execute(sa.text("SELECT current_database()")).scalar_one()
                if actual_database != expected_database:
                    pytest.fail(
                        f"Connected database '{actual_database}' does not match "
                        f"expected test database '{expected_database}'.",
                        pytrace=False,
                    )

                revisions = (
                    conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalars().all()
                )
        except SQLAlchemyError as exc:
            pytest.fail(
                f"PostgreSQL test database verification failed: {type(exc).__name__}",
                pytrace=False,
            )

        if list(revisions) != [EXPECTED_TEST_ALEMBIC_REVISION]:
            pytest.fail(
                f"Expected alembic_version == ['{EXPECTED_TEST_ALEMBIC_REVISION}'], "
                f"got {list(revisions)}.",
                pytrace=False,
            )

        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def pg_session_factory(pg_engine: Engine) -> sessionmaker[Session]:
    """Session factory bound strictly to the validated disposable PostgreSQL engine."""
    return get_session_factory(engine=pg_engine)


@pytest.fixture
def pg_cleanup(
    pg_session_factory: sessionmaker[Session],
) -> Generator[PostgresRecordCleanup, None, None]:
    """Clean up only records explicitly tracked by each PostgreSQL integration test."""
    tracker = PostgresRecordCleanup()
    try:
        yield tracker
    finally:
        ordered_records = tracker.ordered_records_for_delete()
        if ordered_records:
            with pg_session_factory() as session, session.begin():
                for model_cls, record_id in ordered_records:
                    session.execute(sa.delete(model_cls).where(model_cls.id == record_id))


@pytest.fixture
def sample_fingerprint_key() -> str:
    """Deterministic, synthetic mock key for fingerprint tests. Never a real secret."""
    return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def sample_sql_injection_code() -> str:
    """Sample vulnerable python code snippet for testing."""
    return """def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = '{user_id}'"\n    return db.execute(query)\n"""


@pytest.fixture
def sample_secret_value() -> str:
    """Synthetic dummy credential string for testing secret anchor hashing."""
    return "mock_api_token_prefix_synthetic_test_token_12345"
