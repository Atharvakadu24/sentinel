"""Opt-in PostgreSQL 16 integration tests and fail-closed URL validation tests."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

import app.db.models  # noqa: F401  Ensure every ORM model is registered on Base.metadata
from app.db.base import Base
from app.db.models import GitHubInstallation, Project, Scan, User, UserSession
from app.db.session import session_scope
from tests.conftest import PostgresRecordCleanup, validate_postgres_test_url


def _random_positive_int(base: int = 900_000_000) -> int:
    """Return a high random synthetic integer ID to avoid collisions."""
    return base + secrets.randbelow(90_000_000)


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


class TestPostgresTestUrlValidation:
    """Fail-closed unit tests for SENTINEL_TEST_DATABASE_URL parsing (no DB needed)."""

    @pytest.mark.parametrize(
        "valid_url",
        [
            "postgresql+psycopg://postgres:pass@127.0.0.1:55432/sentinel_migration_test",
            "postgresql+psycopg://sentinel:secret@localhost:5432/sentinel_test",
            "postgresql+psycopg://user:pass@LOCALHOST:55432/ci_integration_test",
        ],
    )
    def test_accepts_valid_disposable_loopback_urls(self, valid_url: str) -> None:
        parsed, database = validate_postgres_test_url(valid_url)
        assert parsed.drivername == "postgresql+psycopg"
        assert database == "sentinel_migration_test" or database.endswith("_test")

    @pytest.mark.parametrize(
        "invalid_url",
        [
            "",
            "   ",
            "not-a-url",
            "postgresql+psycopg://postgres:pass@127.0.0.1:55432/sentinel_migration_test ",
            # Must use postgresql+psycopg driver explicitly
            "postgresql://postgres:pass@127.0.0.1:55432/sentinel_migration_test",
            "postgresql+asyncpg://postgres:pass@127.0.0.1:55432/sentinel_migration_test",
            "sqlite:///./sentinel_test.db",
            # Must target loopback host only
            "postgresql+psycopg://postgres:pass@db.example.com:5432/sentinel_migration_test",
            "postgresql+psycopg://postgres:pass@10.0.0.5:5432/sentinel_migration_test",
            "postgresql+psycopg://postgres:pass@/sentinel_migration_test",
            # Must not pass any libpq/URL query parameters
            "postgresql+psycopg://postgres:pass@127.0.0.1:5432/sentinel_migration_test?host=10.0.0.5",
            "postgresql+psycopg://postgres:pass@localhost:5432/sentinel_test?hostaddr=192.168.1.5",
            "postgresql+psycopg://postgres:pass@127.0.0.1:5432/sentinel_migration_test?service=prod",
            "postgresql+psycopg://postgres:pass@127.0.0.1:5432/sentinel_migration_test?options=-csearch_path=other",
            "postgresql+psycopg://postgres:pass@localhost:5432/sentinel_test?sslmode=disable",
            "postgresql+psycopg://localhost:5432/sentinel_test?target_session_attrs=read-write",
            # Must target explicit test database name
            "postgresql+psycopg://postgres:pass@127.0.0.1:55432/sentinel",
            "postgresql+psycopg://postgres:pass@127.0.0.1:55432/sentinel_dev",
            "postgresql+psycopg://postgres:pass@127.0.0.1:55432/",
        ],
    )
    def test_rejects_unsafe_or_malformed_urls_fail_closed(self, invalid_url: str) -> None:
        with pytest.raises(ValueError):
            validate_postgres_test_url(invalid_url)


class TestPostgresRecordCleanup:
    """Unit tests for dependency-safe primary-key teardown ordering."""

    def test_orders_children_before_parents_and_deduplicates(self) -> None:
        cleanup = PostgresRecordCleanup()
        user_id = uuid.uuid4()
        inst_id = uuid.uuid4()
        project_id = uuid.uuid4()
        parent_scan_id = uuid.uuid4()
        child_scan_id = uuid.uuid4()

        # Deliberately track parent and duplicate entries out of dependency order
        cleanup.track(Scan, parent_scan_id)
        cleanup.track(User, user_id)
        cleanup.track(Project, project_id)
        cleanup.track(GitHubInstallation, inst_id)
        cleanup.track(Scan, child_scan_id)
        cleanup.track(User, user_id)  # duplicate ignored

        ordered = cleanup.ordered_records_for_delete()
        assert ordered == [
            (Scan, child_scan_id),
            (Scan, parent_scan_id),
            (Project, project_id),
            (GitHubInstallation, inst_id),
            (User, user_id),
        ]

    def test_rejects_unpopulated_id_and_non_model(self) -> None:
        cleanup = PostgresRecordCleanup()
        with pytest.raises(ValueError, match="before primary key 'id' is populated"):
            cleanup.track(User, None)  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected mapped ORM model"):
            cleanup.track(object, uuid.uuid4())


@pytest.mark.postgres
class TestPostgresSchemaAndTransactions:
    """Phase 2 A & B: live schema parity and real PostgreSQL transaction rollback."""

    def test_live_alembic_schema_matches_models(self, pg_engine: Engine) -> None:
        """Alembic compare_metadata against live PostgreSQL must report zero drift."""
        with pg_engine.connect() as conn:
            context = MigrationContext.configure(
                conn,
                opts={"compare_type": True},
            )
            diff = compare_metadata(context, Base.metadata)

        assert diff == [], f"Unexpected schema drift against live PostgreSQL: {diff}"

    def test_session_scope_rolls_back_on_exception(
        self,
        pg_session_factory: sessionmaker[Session],
        pg_cleanup: PostgresRecordCleanup,
    ) -> None:
        """Uncommitted work inside session_scope rolls back cleanly when an exception fires."""
        tag = _suffix()
        committed_github_id = _random_positive_int()
        rolled_back_github_id = _random_positive_int()

        with session_scope(pg_session_factory) as session:
            committed_user = User(
                github_user_id=committed_github_id,
                github_login=f"pg-committed-{tag}",
            )
            session.add(committed_user)
            session.flush()
            pg_cleanup.track(User, committed_user.id)

        rolled_back_user_id: uuid.UUID | None = None
        rolled_back_project_id: uuid.UUID | None = None
        with (
            pytest.raises(RuntimeError, match="simulated rollback failure"),
            session_scope(pg_session_factory) as session,
        ):
            ephemeral_user = User(
                github_user_id=rolled_back_github_id,
                github_login=f"pg-rollback-{tag}",
            )
            session.add(ephemeral_user)
            session.flush()
            rolled_back_user_id = ephemeral_user.id

            ephemeral_project = Project(
                owner_user_id=committed_user.id,
                kind="manual",
                name=f"rolled-back-project-{tag}",
            )
            session.add(ephemeral_project)
            session.flush()
            rolled_back_project_id = ephemeral_project.id

            raise RuntimeError("simulated rollback failure")

        assert rolled_back_user_id is not None
        assert rolled_back_project_id is not None

        with session_scope(pg_session_factory) as verify_session:
            assert (
                verify_session.scalar(sa.select(User).where(User.id == rolled_back_user_id)) is None
            )
            assert (
                verify_session.scalar(
                    sa.select(Project).where(Project.id == rolled_back_project_id)
                )
                is None
            )
            persisted_user = verify_session.scalar(
                sa.select(User).where(User.github_user_id == committed_github_id)
            )
            assert persisted_user is not None
            assert persisted_user.github_login == f"pg-committed-{tag}"


@pytest.mark.postgres
class TestPostgresNativeTypes:
    """Phase 2 C: verify native PostgreSQL JSONB, TIMESTAMPTZ, and BYTEA behavior."""

    def test_native_column_types_and_roundtrips(
        self,
        pg_engine: Engine,
        pg_session_factory: sessionmaker[Session],
        pg_cleanup: PostgresRecordCleanup,
    ) -> None:
        with pg_engine.connect() as conn:
            column_udts: dict[str, str] = {
                row[0]: row[1]
                for row in conn.execute(
                    sa.text(
                        """
                        SELECT table_name || '.' || column_name AS col, udt_name
                        FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND (
                            (table_name = 'projects' AND column_name = 'settings')
                            OR (table_name = 'scans' AND column_name IN ('counts', 'queued_at'))
                            OR (
                              table_name = 'user_sessions'
                              AND column_name IN ('token_hash', 'expires_at')
                            )
                          )
                        """
                    )
                ).all()
            }

        assert column_udts == {
            "projects.settings": "jsonb",
            "scans.counts": "jsonb",
            "scans.queued_at": "timestamptz",
            "user_sessions.token_hash": "bytea",
            "user_sessions.expires_at": "timestamptz",
        }

        tag = _suffix()
        binary_digest = b"\x00\x01\xff\x10" + secrets.token_bytes(28)
        assert len(binary_digest) == 32

        ist_offset = timezone(timedelta(hours=5, minutes=30))
        aware_expires_at = datetime(2026, 12, 1, 14, 30, 15, 123456, tzinfo=ist_offset)
        aware_queued_at = datetime(2026, 12, 1, 9, 0, 0, 654321, tzinfo=UTC)

        settings_payload = {
            "branch_rules": ["main", "release/*"],
            "thresholds": {"critical": 0, "fail_on_secrets": True},
            "label": "unicode-\u2713",
        }
        counts_payload = {"critical": 1, "high": 2, "details": [{"rule": "sqli", "count": 1}]}

        with session_scope(pg_session_factory) as session:
            user = User(
                github_user_id=_random_positive_int(),
                github_login=f"pg-types-{tag}",
            )
            session.add(user)
            session.flush()
            pg_cleanup.track(User, user.id)

            user_session = UserSession(
                user_id=user.id,
                token_hash=binary_digest,
                expires_at=aware_expires_at,
            )
            session.add(user_session)
            session.flush()
            pg_cleanup.track(UserSession, user_session.id)

            project = Project(
                owner_user_id=user.id,
                kind="manual",
                name=f"types-project-{tag}",
                settings=settings_payload,
            )
            session.add(project)
            session.flush()
            pg_cleanup.track(Project, project.id)

            scan = Scan(
                project_id=project.id,
                created_by_user_id=user.id,
                trigger="manual",
                trigger_key=f"manual-{tag}",
                status="queued",
                queued_at=aware_queued_at,
                counts=counts_payload,
            )
            session.add(scan)
            session.flush()
            pg_cleanup.track(Scan, scan.id)

            user_session_id = user_session.id
            project_id = project.id
            scan_id = scan.id

        with session_scope(pg_session_factory) as read_session:
            loaded_session = read_session.get(UserSession, user_session_id)
            loaded_project = read_session.get(Project, project_id)
            loaded_scan = read_session.get(Scan, scan_id)

            assert loaded_session is not None
            assert loaded_session.token_hash == binary_digest
            assert isinstance(loaded_session.token_hash, bytes)
            assert loaded_session.expires_at.tzinfo is not None
            assert loaded_session.expires_at.astimezone(UTC) == aware_expires_at.astimezone(UTC)

            assert loaded_project is not None
            assert loaded_project.settings == settings_payload

            assert loaded_scan is not None
            assert loaded_scan.counts == counts_payload
            assert loaded_scan.queued_at.tzinfo is not None
            assert loaded_scan.queued_at.astimezone(UTC) == aware_queued_at


@pytest.mark.postgres
class TestPostgresConstraintsAndPartialIndexes:
    """Phase 2 D: uniqueness, foreign keys, and PostgreSQL partial indexes."""

    def test_uniqueness_and_foreign_key_constraints(
        self,
        pg_session_factory: sessionmaker[Session],
        pg_cleanup: PostgresRecordCleanup,
    ) -> None:
        tag = _suffix()
        github_user_id = _random_positive_int()

        with session_scope(pg_session_factory) as session:
            user = User(
                github_user_id=github_user_id,
                github_login=f"pg-uniq-{tag}",
            )
            session.add(user)
            session.flush()
            pg_cleanup.track(User, user.id)

            project = Project(
                owner_user_id=user.id,
                kind="manual",
                name=f"uniq-project-{tag}",
            )
            session.add(project)
            session.flush()
            pg_cleanup.track(Project, project.id)

            scan = Scan(
                project_id=project.id,
                created_by_user_id=user.id,
                trigger="manual",
                trigger_key=f"dup-trigger-{tag}",
                status="queued",
            )
            session.add(scan)
            session.flush()
            pg_cleanup.track(Scan, scan.id)

            user_id = user.id
            project_id = project.id

        # Duplicate User.github_user_id must raise IntegrityError
        with pytest.raises(IntegrityError), session_scope(pg_session_factory) as session:
            session.add(
                User(
                    github_user_id=github_user_id,
                    github_login=f"pg-uniq-dup-{tag}",
                )
            )

        # Duplicate Scan(project_id, trigger_key) must raise IntegrityError
        with pytest.raises(IntegrityError), session_scope(pg_session_factory) as session:
            session.add(
                Scan(
                    project_id=project_id,
                    created_by_user_id=user_id,
                    trigger="manual",
                    trigger_key=f"dup-trigger-{tag}",
                    status="queued",
                )
            )

        # Foreign-key violation: Scan referencing non-existent Project
        with pytest.raises(IntegrityError), session_scope(pg_session_factory) as session:
            session.add(
                Scan(
                    project_id=uuid.uuid4(),
                    created_by_user_id=user_id,
                    trigger="manual",
                    trigger_key=f"missing-project-{tag}",
                    status="queued",
                )
            )

        # Foreign-key violation: Project referencing non-existent User
        with pytest.raises(IntegrityError), session_scope(pg_session_factory) as session:
            session.add(
                Project(
                    owner_user_id=uuid.uuid4(),
                    kind="manual",
                    name=f"orphan-project-{tag}",
                )
            )

    def test_active_scan_partial_index_and_status_constraint(
        self,
        pg_engine: Engine,
        pg_session_factory: sessionmaker[Session],
        pg_cleanup: PostgresRecordCleanup,
    ) -> None:
        with pg_engine.connect() as conn:
            index_def = conn.execute(
                sa.text(
                    """
                    SELECT indexdef
                    FROM pg_indexes
                    WHERE schemaname = 'public'
                      AND tablename = 'scans'
                      AND indexname = 'ix_scans_active_status'
                    """
                )
            ).scalar_one_or_none()

        assert index_def is not None
        assert "WHERE" in index_def
        assert "queued" in index_def
        assert "running" in index_def

        tag = _suffix()
        with session_scope(pg_session_factory) as session:
            user = User(
                github_user_id=_random_positive_int(),
                github_login=f"pg-scan-idx-{tag}",
            )
            session.add(user)
            session.flush()
            pg_cleanup.track(User, user.id)

            project = Project(
                owner_user_id=user.id,
                kind="manual",
                name=f"scan-idx-project-{tag}",
            )
            session.add(project)
            session.flush()
            pg_cleanup.track(Project, project.id)

            active_queued = Scan(
                project_id=project.id,
                created_by_user_id=user.id,
                trigger="manual",
                trigger_key=f"active-queued-{tag}",
                status="queued",
            )
            active_running = Scan(
                project_id=project.id,
                created_by_user_id=user.id,
                trigger="manual",
                trigger_key=f"active-running-{tag}",
                status="running",
            )
            terminal_scan = Scan(
                project_id=project.id,
                created_by_user_id=user.id,
                trigger="manual",
                trigger_key=f"done-{tag}",
                status="succeeded",
            )
            session.add_all([active_queued, active_running, terminal_scan])
            session.flush()
            pg_cleanup.track(Scan, active_queued.id)
            pg_cleanup.track(Scan, active_running.id)
            pg_cleanup.track(Scan, terminal_scan.id)
            project_id = project.id

        # Invalid status violates ck_scans_status on PostgreSQL
        with pytest.raises(IntegrityError), session_scope(pg_session_factory) as session:
            session.add(
                Scan(
                    project_id=project_id,
                    trigger="manual",
                    trigger_key=f"bad-status-{tag}",
                    status="not_a_real_status",
                )
            )

    def test_github_project_partial_unique_index_enforced(
        self,
        pg_session_factory: sessionmaker[Session],
        pg_cleanup: PostgresRecordCleanup,
    ) -> None:
        tag = _suffix()
        ext_installation_id = _random_positive_int()
        repo_id_1 = _random_positive_int(500_000_000)
        repo_id_2 = repo_id_1 + 1

        with session_scope(pg_session_factory) as session:
            user = User(
                github_user_id=_random_positive_int(),
                github_login=f"pg-gh-proj-{tag}",
            )
            session.add(user)
            session.flush()
            pg_cleanup.track(User, user.id)

            installation = GitHubInstallation(
                installation_id=ext_installation_id,
                owner_user_id=user.id,
                account_login=f"pg-org-{tag}",
                account_type="Organization",
                status="active",
                permissions={"pull_requests": "write"},
            )
            session.add(installation)
            session.flush()
            pg_cleanup.track(GitHubInstallation, installation.id)

            gh_project_1 = Project(
                owner_user_id=user.id,
                kind="github",
                name=f"repo-1-{tag}",
                installation_id=installation.id,
                github_repo_id=repo_id_1,
                full_name=f"pg-org-{tag}/repo-1",
                default_branch="main",
            )
            gh_project_2 = Project(
                owner_user_id=user.id,
                kind="github",
                name=f"repo-2-{tag}",
                installation_id=installation.id,
                github_repo_id=repo_id_2,
                full_name=f"pg-org-{tag}/repo-2",
                default_branch="main",
            )
            # Manual projects do not require installation_id/github_repo_id and are outside the partial unique index
            manual_project_1 = Project(
                owner_user_id=user.id,
                kind="manual",
                name=f"manual-a-{tag}",
            )
            manual_project_2 = Project(
                owner_user_id=user.id,
                kind="manual",
                name=f"manual-b-{tag}",
            )
            session.add_all([gh_project_1, gh_project_2, manual_project_1, manual_project_2])
            session.flush()
            pg_cleanup.track(Project, gh_project_1.id)
            pg_cleanup.track(Project, gh_project_2.id)
            pg_cleanup.track(Project, manual_project_1.id)
            pg_cleanup.track(Project, manual_project_2.id)

            user_id = user.id
            installation_pk = installation.id

        # Duplicate (installation_id, github_repo_id) with kind='github' must raise IntegrityError
        with pytest.raises(IntegrityError), session_scope(pg_session_factory) as session:
            session.add(
                Project(
                    owner_user_id=user_id,
                    kind="github",
                    name=f"repo-1-dup-{tag}",
                    installation_id=installation_pk,
                    github_repo_id=repo_id_1,
                    full_name=f"pg-org-{tag}/repo-1-dup",
                    default_branch="main",
                )
            )

        # kind='github' without installation_id violates ck_projects_github_fields
        with pytest.raises(IntegrityError), session_scope(pg_session_factory) as session:
            session.add(
                Project(
                    owner_user_id=user_id,
                    kind="github",
                    name=f"repo-missing-inst-{tag}",
                    installation_id=None,
                    github_repo_id=repo_id_2 + 1,
                    full_name=f"pg-org-{tag}/repo-missing",
                )
            )
