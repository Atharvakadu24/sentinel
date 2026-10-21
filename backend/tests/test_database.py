"""Focused unit tests for SQLAlchemy 2.0 database infrastructure and session lifecycle.

Validates Blueprint Section 4:
- Engine creation, pooling configuration, and dialect-specific behavior (PostgreSQL vs SQLite)
- Engine singleton caching, concurrent access, and disposal lifecycle
- Session factory configuration (autocommit=False, autoflush=False, expire_on_commit=False)
- Transactional session_scope context manager (commit on success, rollback on error, close)
- FastAPI get_db_session dependency lifecycle and integration with TestClient
- Declarative Base, UUIDPrimaryKeyMixin, TimestampMixin, and portable JSONType
- Configuration security and isolation for testing
"""

from __future__ import annotations

import concurrent.futures
import uuid
from collections.abc import Generator
from datetime import UTC
from pathlib import Path
from typing import Annotated, Any

import pytest
import sqlalchemy as sa
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import QueuePool, StaticPool

from app.core.config import Settings, get_settings
from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, utc_now
from app.db.session import (
    dispose_engine,
    get_db_session,
    get_engine,
    get_session_factory,
    session_scope,
    set_engine,
)


@pytest.fixture(autouse=True)
def clean_engine_lifecycle() -> Generator[None, None, None]:
    """Ensure each test starts and finishes with a clean engine state."""
    dispose_engine()
    yield
    dispose_engine()


DbSession = Annotated[Session, Depends(get_db_session)]


class IsolatedModelBase(DeclarativeBase):
    """Isolated metadata base to prevent test models from polluting production Base.metadata."""

    type_annotation_map = Base.type_annotation_map


class DummyItem(IsolatedModelBase, UUIDPrimaryKeyMixin, TimestampMixin):
    """Test model for validating declarative base and lifecycle operations."""

    __tablename__ = "dummy_items"

    name: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column(nullable=True)
    tags: Mapped[list[Any] | None] = mapped_column(nullable=True)


class TestDatabaseEngine:
    """Tests for SQLAlchemy Engine creation, pooling, and dialect adaptation."""

    def test_default_engine_configuration(self) -> None:
        """Default engine must use psycopg driver with configured pool settings."""
        settings = get_settings()
        engine = get_engine()

        assert engine.dialect.name == "postgresql"
        assert engine.dialect.driver == "psycopg"
        assert engine.echo is settings.DB_ECHO
        # Verify connection pool parameters on network database
        assert isinstance(engine.pool, QueuePool)
        assert engine.pool.size() == settings.DB_POOL_SIZE
        assert engine.pool.checkedout() == 0  # No checked-out connections initially
        assert engine.pool._max_overflow == settings.DB_MAX_OVERFLOW

    def test_engine_singleton_and_dispose_lifecycle(self) -> None:
        """get_engine() must return cached singleton until dispose_engine() is invoked."""
        engine_1 = get_engine()
        engine_2 = get_engine()
        assert engine_1 is engine_2

        dispose_engine()

        engine_3 = get_engine()
        assert engine_3 is not engine_1

    def test_concurrent_engine_access(self) -> None:
        """Concurrent calls to get_engine() must safely return the identical engine singleton."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(get_engine) for _ in range(20)]
            engines = [f.result() for f in futures]

        first_engine = engines[0]
        assert all(eng is first_engine for eng in engines)

    def test_sqlite_in_memory_uses_static_pool_for_connection_sharing(self) -> None:
        """SQLite in-memory engine uses StaticPool and check_same_thread=False for connection sharing."""
        sqlite_engine = get_engine("sqlite:///:memory:")
        assert isinstance(sqlite_engine.pool, StaticPool)

        # Verify tables created on one connection persist to another
        with sqlite_engine.connect() as conn1:
            conn1.execute(text("CREATE TABLE test_table (id INTEGER PRIMARY KEY, val TEXT)"))
            conn1.execute(text("INSERT INTO test_table (id, val) VALUES (1, 'persisted')"))
            conn1.commit()

        with sqlite_engine.connect() as conn2:
            result = conn2.execute(text("SELECT val FROM test_table WHERE id = 1")).scalar()
            assert result == "persisted"

        dispose_engine(sqlite_engine)

    def test_sqlite_file_engine_does_not_use_static_pool(self, tmp_path: Path) -> None:
        """File-based SQLite engines do not use StaticPool."""
        db_file = tmp_path / "sentinel_test.db"
        file_engine = get_engine(f"sqlite:///{db_file}")
        assert not isinstance(file_engine.pool, StaticPool)
        dispose_engine(file_engine)

    def test_custom_engine_options(self) -> None:
        """Explicit options to get_engine must configure the returned engine independently."""
        custom_engine = get_engine(
            database_url="sqlite:///:memory:",
            echo=True,
        )
        assert custom_engine.echo is True
        dispose_engine(custom_engine)

    def test_set_engine_override(self) -> None:
        """set_engine() allows test suites to inject an explicit engine singleton."""
        mock_engine = get_engine("sqlite:///:memory:")
        set_engine(mock_engine)

        assert get_engine() is mock_engine
        dispose_engine()


class TestSessionFactory:
    """Tests for sessionmaker configuration (Blueprint Section 4)."""

    def test_session_factory_conventions(self) -> None:
        """Session factory must configure autocommit=False, autoflush=False, expire_on_commit=False."""
        engine = get_engine("sqlite:///:memory:")
        factory = get_session_factory(engine)

        session = factory()
        try:
            assert isinstance(session, Session)
            assert session.autoflush is False
            assert session.expire_on_commit is False
            assert session.bind is engine
        finally:
            session.close()
            dispose_engine(engine)


class TestSessionScope:
    """Tests for transactional session_scope context manager."""

    def test_session_scope_commits_on_success(self) -> None:
        """Normal block exit must automatically commit session changes."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        factory = get_session_factory(engine)

        item_id: uuid.UUID | None = None
        with session_scope(factory) as session:
            item = DummyItem(name="committed_item")
            session.add(item)
            session.flush()
            item_id = item.id

        assert item_id is not None
        # Verify in fresh independent session that row was committed
        with session_scope(factory) as session2:
            persisted = session2.get(DummyItem, item_id)
            assert persisted is not None
            assert persisted.name == "committed_item"

        dispose_engine(engine)

    def test_session_scope_rolls_back_on_exception(self) -> None:
        """Unhandled exceptions must trigger rollback and propagate the error."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        factory = get_session_factory(engine)

        item_id = uuid.uuid4()
        with (
            pytest.raises(RuntimeError, match="simulated failure"),
            session_scope(factory) as session,
        ):
            item = DummyItem(id=item_id, name="doomed_item")
            session.add(item)
            raise RuntimeError("simulated failure")

        # Verify row was NOT persisted
        with session_scope(factory) as session2:
            persisted = session2.get(DummyItem, item_id)
            assert persisted is None

        dispose_engine(engine)

    def test_session_scope_manual_rollback_not_committed(self) -> None:
        """If caller manually rolls back inside session_scope, it is not committed on normal exit."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        factory = get_session_factory(engine)

        item_id = uuid.uuid4()
        with session_scope(factory) as session:
            item = DummyItem(id=item_id, name="manually_rolled_back")
            session.add(item)
            session.flush()
            session.rollback()

        # Verify row was not committed
        with session_scope(factory) as session2:
            assert session2.get(DummyItem, item_id) is None

        dispose_engine(engine)

    def test_session_scope_commit_failure_rolls_back(self) -> None:
        """Commit failure (e.g. database constraint) triggers rollback and raises error."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        factory = get_session_factory(engine)

        fixed_id = uuid.uuid4()
        with session_scope(factory) as session:
            session.add(DummyItem(id=fixed_id, name="original"))

        # Attempt inserting conflicting primary key in separate scope
        with pytest.raises(IntegrityError), session_scope(factory) as session:
            session.add(DummyItem(id=fixed_id, name="conflicting_duplicate"))

        with session_scope(factory) as session2:
            item = session2.get(DummyItem, fixed_id)
            assert item is not None
            assert item.name == "original"

        dispose_engine(engine)

    def test_session_scope_closes_session_on_exit(self) -> None:
        """Session must always be closed upon leaving the scope."""
        engine = get_engine("sqlite:///:memory:")
        factory = get_session_factory(engine)

        captured_session: Session | None = None
        with session_scope(factory) as session:
            captured_session = session
            assert session.is_active is True

        assert captured_session is not None
        dispose_engine(engine)


class TestFastAPIDbSessionDependency:
    """Tests for FastAPI get_db_session dependency and HTTP request lifecycle."""

    def test_get_db_session_generator_lifecycle(self) -> None:
        """Manually verify generator enter, yield, commit, and cleanup."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        set_engine(engine)

        gen = get_db_session()
        session = next(gen)
        assert isinstance(session, Session)

        item = DummyItem(name="generator_item")
        session.add(item)
        session.flush()
        saved_id = item.id

        # Simulating normal FastAPI request completion
        with pytest.raises(StopIteration):
            next(gen)

        # Verify row is persisted in new session
        verify_factory = get_session_factory(engine)
        with verify_factory() as verify_session:
            persisted = verify_session.get(DummyItem, saved_id)
            assert persisted is not None

        dispose_engine(engine)

    def test_fastapi_http_request_integration_success(self) -> None:
        """FastAPI route with Depends(get_db_session) correctly persists data across HTTP calls."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        set_engine(engine)

        app = FastAPI()

        @app.post("/items")
        def create_item(name: str, db: DbSession) -> dict[str, str]:
            item = DummyItem(name=name)
            db.add(item)
            db.flush()
            return {"id": str(item.id), "name": item.name}

        @app.get("/items/{item_id}")
        def read_item(item_id: str, db: DbSession) -> dict[str, str]:
            item = db.get(DummyItem, uuid.UUID(item_id))
            if not item:
                raise HTTPException(status_code=404, detail="Item not found")
            return {"id": str(item.id), "name": item.name}

        client = TestClient(app)

        # 1. Create item via POST
        post_resp = client.post("/items?name=test_artifact")
        assert post_resp.status_code == 200
        data = post_resp.json()
        created_id = data["id"]
        assert data["name"] == "test_artifact"

        # 2. Retrieve item via GET in a separate HTTP request
        get_resp = client.get(f"/items/{created_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["name"] == "test_artifact"

        dispose_engine(engine)

    def test_fastapi_http_request_rollback_on_route_error(self) -> None:
        """FastAPI route raising an unhandled error rolls back pending database changes."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        set_engine(engine)

        app = FastAPI()
        item_id = uuid.uuid4()

        @app.post("/items-fail")
        def failing_route(db: DbSession) -> dict[str, str]:
            item = DummyItem(id=item_id, name="doomed_http_item")
            db.add(item)
            db.flush()
            raise ValueError("Intentional route explosion")

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/items-fail")
        assert response.status_code == 500

        # Verify doomed item was rolled back and never persisted
        verify_factory = get_session_factory(engine)
        with verify_factory() as verify_session:
            persisted = verify_session.get(DummyItem, item_id)
            assert persisted is None

        dispose_engine(engine)

    def test_fastapi_http_exception_triggers_rollback(self) -> None:
        """FastAPI route raising HTTPException rolls back pending database changes."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        set_engine(engine)

        app = FastAPI()
        item_id = uuid.uuid4()

        @app.post("/items-http-error")
        def http_error_route(db: DbSession) -> dict[str, str]:
            item = DummyItem(id=item_id, name="doomed_by_http_error")
            db.add(item)
            db.flush()
            raise HTTPException(status_code=400, detail="Explicit client error")

        client = TestClient(app)
        resp = client.post("/items-http-error")
        assert resp.status_code == 400

        verify_factory = get_session_factory(engine)
        with verify_factory() as verify_session:
            assert verify_session.get(DummyItem, item_id) is None

        dispose_engine(engine)


class TestDeclarativeBaseAndMixins:
    """Tests for DeclarativeBase, UUIDPrimaryKeyMixin, TimestampMixin, and JSONType."""

    def test_metadata_isolation_from_production(self) -> None:
        """Production Base.metadata must not be contaminated by test models."""
        assert "dummy_items" not in Base.metadata.tables
        from app.db import models  # noqa: F401

        assert "users" in Base.metadata.tables
        assert "dummy_items" not in Base.metadata.tables

    def test_uuid_primary_key_mixin(self) -> None:
        """UUIDPrimaryKeyMixin generates valid uuid4 upon database insertion."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        factory = get_session_factory(engine)

        # 1. Automatic generation via column default
        with session_scope(factory) as session:
            item = DummyItem(name="uuid_test_auto")
            session.add(item)
            session.flush()
            assert item.id is not None
            assert isinstance(item.id, uuid.UUID)
            assert item.id.version == 4

        # 2. Explicit UUID assignment is preserved
        explicit_id = uuid.uuid4()
        with session_scope(factory) as session:
            item2 = DummyItem(id=explicit_id, name="uuid_test_explicit")
            session.add(item2)
            session.flush()
            assert item2.id == explicit_id

        dispose_engine(engine)

    def test_timestamp_mixin_defaults(self) -> None:
        """TimestampMixin initializes created_at and updated_at with UTC datetimes."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        factory = get_session_factory(engine)

        with session_scope(factory) as session:
            item = DummyItem(name="timestamp_test")
            session.add(item)
            session.flush()
            assert item.created_at is not None
            assert item.updated_at is not None
            assert item.created_at.tzinfo == UTC
            assert item.updated_at.tzinfo == UTC

        dispose_engine(engine)

    def test_utc_now_helper(self) -> None:
        """utc_now() must return timezone-aware current UTC datetime."""
        now = utc_now()
        assert now.tzinfo is not None
        assert now.tzinfo == UTC

    def test_json_type_and_type_annotation_map(self) -> None:
        """Base type_annotation_map seamlessly serializes dictionaries and lists."""
        engine = get_engine("sqlite:///:memory:")
        IsolatedModelBase.metadata.create_all(engine)
        factory = get_session_factory(engine)

        item_id: uuid.UUID | None = None
        payload_data = {"key": "value", "nested": {"count": 42}}
        tags_data = ["security", "audit", "triage"]

        with session_scope(factory) as session:
            item = DummyItem(name="json_test", payload=payload_data, tags=tags_data)
            session.add(item)
            session.flush()
            item_id = item.id

        assert item_id is not None
        with session_scope(factory) as session2:
            retrieved = session2.get(DummyItem, item_id)
            assert retrieved is not None
            assert retrieved.payload == payload_data
            assert retrieved.tags == tags_data

        dispose_engine(engine)

    def test_expanded_type_annotation_map(self) -> None:
        """Base type_annotation_map maps dictionary and list types to JSONType."""
        assert Base.type_annotation_map[dict] is JSONType
        assert Base.type_annotation_map[list] is JSONType
        assert Base.type_annotation_map[dict[str, Any]] is JSONType
        assert Base.type_annotation_map[list[Any]] is JSONType
        assert Base.type_annotation_map[dict[str, int]] is JSONType
        assert Base.type_annotation_map[list[dict[str, Any]]] is JSONType


class TestDatabaseSecurityAndConfiguration:
    """Tests for database configuration safety and test environment isolation."""

    def test_database_url_from_settings(self) -> None:
        """Database URL is derived from Settings.DATABASE_URL by default."""
        settings = Settings()
        assert "postgresql://" in settings.DATABASE_URL
        assert settings.DB_POOL_SIZE == 10
        assert settings.DB_MAX_OVERFLOW == 20

    def test_credentials_hidden_in_engine_url_render(self) -> None:
        """Engine URL rendering must support password masking."""
        engine = get_engine()
        rendered_safe = engine.url.render_as_string(hide_password=True)
        assert "***" in rendered_safe or ":***@" in rendered_safe
        assert "sentinel_dev_password" not in rendered_safe

    def test_configurable_via_custom_settings(self) -> None:
        """Settings can configure custom database URL for tests or environments."""
        test_settings = Settings(
            DATABASE_URL="sqlite:///custom_test.db",
            DB_ECHO=False,
        )
        assert test_settings.DATABASE_URL == "sqlite:///custom_test.db"
