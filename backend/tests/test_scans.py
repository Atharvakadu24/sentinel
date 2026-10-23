"""Regression and integration tests for scan-job persistence, validation, and API routes.

Validates Blueprint Section 7 (Workflow A: Manual code analysis), Section 8.1
(Database models, constraints, and relationships), and Section 9.3 (Scans API contracts):
- Successful transactional creation of Scan and Job
- File summary classification (supported Semgrep/Secret extensions vs unsupported vs minified)
- File quantity and size limits (1-20 files, 200 KB per file, 1 MB total)
- File path safety and case-folded uniqueness
- Invalid project and user references
- Uniqueness conflicts (uq_scans_project_trigger)
- Rollback invariants (neither Scan nor Job persists on failure)
- FastAPI endpoints: POST /projects/{id}/scans/manual and GET /scans/{id}
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.models import Job, Project, Scan, User
from app.db.session import get_db_session, session_scope
from app.main import app
from app.schemas.scan import ManualFileInput
from app.services.scan_service import (
    MAX_FILE_BYTES,
    MAX_FILES_COUNT,
    MAX_LINE_LENGTH,
    MAX_TOTAL_BYTES,
    ProjectNotFoundError,
    ScanConflictError,
    ScanPayloadTooLargeError,
    ScanValidationError,
    UserNotFoundError,
    create_manual_scan,
    create_scan_and_job,
    get_scan,
    is_extension_supported,
    is_minified_or_generated,
    validate_manual_scan_files,
)


@pytest.fixture
def test_engine() -> Engine:
    """Isolated in-memory SQLite engine with foreign key constraints enabled."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session_factory(test_engine: Engine) -> sessionmaker[Session]:
    """Session factory for the isolated test database."""
    return sessionmaker(bind=test_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def db_session(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Isolated database session fixture."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_user(db_session: Session) -> User:
    """Create a persistent user in the test database."""
    user = User(
        github_user_id=123456,
        github_login="maya-dev",
        display_name="Maya Developer",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def sample_project(db_session: Session, sample_user: User) -> Project:
    """Create a persistent manual project in the test database."""
    project = Project(
        owner_user_id=sample_user.id,
        kind="manual",
        name="Manual scans",
        status="active",
    )
    db_session.add(project)
    db_session.commit()
    return project


@pytest.fixture
def client(session_factory: sessionmaker[Session]) -> Generator[TestClient, None, None]:
    """TestClient configured with dependency override for get_db_session and dev scan opt-in."""

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    def override_get_settings() -> Settings:
        return Settings(
            APP_ENV="test",
            ENABLE_DEV_UNAUTHENTICATED_SCANS=True,
        )

    app.dependency_overrides[get_db_session] = override_get_db_session
    app.dependency_overrides[get_settings] = override_get_settings
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def unauthenticated_client(
    session_factory: sessionmaker[Session],
) -> Generator[TestClient, None, None]:
    """TestClient with default fail-closed unauthenticated scan creation."""

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    def override_get_settings() -> Settings:
        return Settings(
            APP_ENV="test",
            ENABLE_DEV_UNAUTHENTICATED_SCANS=False,
        )

    app.dependency_overrides[get_db_session] = override_get_db_session
    app.dependency_overrides[get_settings] = override_get_settings
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def production_client(
    session_factory: sessionmaker[Session],
) -> Generator[TestClient, None, None]:
    """TestClient in production environment ensuring unauthenticated access fails closed."""

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    valid_key = SecretStr("0123456789abcdef0123456789abcdef")

    def override_get_settings() -> Settings:
        return Settings(
            APP_ENV="production",
            AI_DEBUG_LOG=False,
            SECRET_KEY=valid_key,
            SESSION_SECRET=valid_key,
            FINGERPRINT_KEY=valid_key,
            ENABLE_DEV_UNAUTHENTICATED_SCANS=False,
        )

    app.dependency_overrides[get_db_session] = override_get_db_session
    app.dependency_overrides[get_settings] = override_get_settings
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


class TestFileValidationAndClassification:
    """Tests for file validation, extension allowlists, size limits, and minification."""

    def test_extension_allowlist_classification(self) -> None:
        """Verify extension allowlist matches Workflow A specification."""
        # Semgrep extensions
        assert is_extension_supported("src/main.py")
        assert is_extension_supported("frontend/app.js")
        assert is_extension_supported("components/button.jsx")
        assert is_extension_supported("lib/index.ts")
        assert is_extension_supported("views/home.tsx")
        assert is_extension_supported("modules/util.mjs")
        assert is_extension_supported("legacy/old.cjs")

        # Secret scanning extensions
        assert is_extension_supported(".env")
        assert is_extension_supported("config/.env")
        assert is_extension_supported(".env.local")
        assert is_extension_supported("config/.env.production")
        assert is_extension_supported("settings.json")
        assert is_extension_supported("deploy/config.yaml")
        assert is_extension_supported("ci.yml")
        assert is_extension_supported("pyproject.toml")
        assert is_extension_supported("setup.cfg")
        assert is_extension_supported("app.ini")
        assert is_extension_supported("app.properties")
        assert is_extension_supported("scripts/build.sh")
        assert is_extension_supported("notes.txt")

        # Unsupported extensions (must be classified as skipped, never silently dropped)
        assert not is_extension_supported("README.md")
        assert not is_extension_supported("image.png")
        assert not is_extension_supported("document.pdf")
        assert not is_extension_supported("archive.tar.gz")
        assert not is_extension_supported("Dockerfile")

    def test_minified_line_detection(self) -> None:
        """Verify lines > 5000 characters trigger minified_or_generated skip reason."""
        normal_content = "def foo():\n    return 42\n"
        assert not is_minified_or_generated(normal_content)

        minified_line = "a" * 5001
        minified_content = f"// header\n{minified_line}\n// footer"
        assert is_minified_or_generated(minified_content)

        exact_5000 = "b" * 5000
        assert not is_minified_or_generated(exact_5000)

    def test_validate_files_mixed_supported_unsupported_minified(self) -> None:
        """Verify validate_manual_scan_files produces correct summary and payload entries."""
        files = [
            ManualFileInput(path="src/main.py", content="print('hello')"),
            ManualFileInput(path="docs/guide.md", content="# Guide"),
            ManualFileInput(path="bundle.js", content="var x = '" + ("x" * 5005) + "';"),
        ]
        summary, payload = validate_manual_scan_files(files)

        assert len(summary) == 3
        assert len(payload) == 3

        # 1. Supported Python file
        assert summary[0]["path"] == "src/main.py"
        assert summary[0]["scanned"] is True
        assert summary[0]["skip_reason"] is None
        assert payload[0]["content"] == "print('hello')"

        # 2. Unsupported extension (.md)
        assert summary[1]["path"] == "docs/guide.md"
        assert summary[1]["scanned"] is False
        assert summary[1]["skip_reason"] == "unsupported_extension"

        # 3. Minified JS file
        assert summary[2]["path"] == "bundle.js"
        assert summary[2]["scanned"] is False
        assert summary[2]["skip_reason"] == "minified_or_generated"

    def test_empty_files_batch_rejected(self) -> None:
        """Submitting 0 files raises ScanValidationError (422)."""
        with pytest.raises(ScanValidationError, match="At least one file"):
            validate_manual_scan_files([])

    def test_too_many_files_rejected(self) -> None:
        """Submitting > 20 files raises ScanValidationError (422)."""
        files = [
            ManualFileInput(path=f"file{i}.py", content=f"x = {i}")
            for i in range(MAX_FILES_COUNT + 1)
        ]
        with pytest.raises(ScanValidationError, match="Cannot submit more than 20 files"):
            validate_manual_scan_files(files)

    def test_single_file_exceeds_200kb_rejected(self) -> None:
        """Individual file > 200 KB raises ScanPayloadTooLargeError (413)."""
        large_content = "a" * (MAX_FILE_BYTES + 1)
        files = [ManualFileInput(path="large.py", content=large_content)]
        with pytest.raises(
            ScanPayloadTooLargeError, match="exceeds maximum allowed size of 200 KB"
        ):
            validate_manual_scan_files(files)

    def test_total_payload_exceeds_1mb_rejected(self) -> None:
        """Total batch > 1 MB raises ScanPayloadTooLargeError (413)."""
        # 6 files of 180 KB each = 1,080 KB > 1,024 KB (MAX_TOTAL_BYTES)
        chunk_size = 180 * 1024
        files = [ManualFileInput(path=f"file_{i}.py", content="x" * chunk_size) for i in range(6)]
        assert sum(len(f.content.encode("utf-8")) for f in files) > MAX_TOTAL_BYTES
        with pytest.raises(
            ScanPayloadTooLargeError, match="Total payload size exceeds maximum limit of 1 MB"
        ):
            validate_manual_scan_files(files)

    def test_case_folded_duplicate_paths_rejected(self) -> None:
        """Duplicate file paths differing only in case are rejected (Threat T8)."""
        files = [
            ManualFileInput(path="src/App.py", content="x = 1"),
            ManualFileInput(path="src/app.py", content="x = 2"),
        ]
        with pytest.raises(ScanValidationError, match="Duplicate file path"):
            validate_manual_scan_files(files)

    def test_nul_byte_in_content_rejected(self) -> None:
        """Files containing NUL bytes in content are rejected."""
        files = [ManualFileInput(path="src/main.py", content="def test():\x00pass")]
        with pytest.raises(ScanValidationError, match="contains invalid NUL bytes"):
            validate_manual_scan_files(files)

    def test_unsafe_paths_rejected(self) -> None:
        """Directory traversal, absolute paths, and drive letters are rejected."""
        for unsafe in ["../secret.py", "/etc/passwd", "C:/Windows/app.py", "foo\\bar.py"]:
            files = [ManualFileInput(path=unsafe, content="x = 1")]
            with pytest.raises(ScanValidationError, match="Invalid file path"):
                validate_manual_scan_files(files)

    def test_exact_200kb_file_boundary(self) -> None:
        """Exact 200 KB boundary (204,800 bytes allowed, 204,801 bytes rejected)."""
        exact_content = "a" * MAX_FILE_BYTES
        assert len(exact_content.encode("utf-8")) == MAX_FILE_BYTES
        summary, payload = validate_manual_scan_files(
            [ManualFileInput(path="exact.py", content=exact_content)]
        )
        assert summary[0]["byte_size"] == MAX_FILE_BYTES
        assert len(payload) == 1

        overflow_content = "a" * (MAX_FILE_BYTES + 1)
        with pytest.raises(
            ScanPayloadTooLargeError, match="exceeds maximum allowed size of 200 KB"
        ):
            validate_manual_scan_files(
                [ManualFileInput(path="overflow.py", content=overflow_content)]
            )

    def test_exact_1mb_total_payload_boundary(self) -> None:
        """Exact 1 MB boundary (1,048,576 bytes allowed, 1,048,577 bytes rejected)."""
        # Distribute exactly 1,048,576 bytes across 6 files (each <= 200 KB)
        # 5 files of 174,762 bytes + 1 file of 174,766 bytes = 1,048,576 bytes
        chunk = 174_762
        remainder = MAX_TOTAL_BYTES - (chunk * 5)
        files = [ManualFileInput(path=f"file_{i}.py", content="x" * chunk) for i in range(5)]
        files.append(ManualFileInput(path="file_last.py", content="x" * remainder))
        assert sum(len(f.content.encode("utf-8")) for f in files) == MAX_TOTAL_BYTES

        summary, payload = validate_manual_scan_files(files)
        assert len(summary) == 6
        assert len(payload) == 6

        # Adding 1 byte to exceed 1 MB limit
        files[-1] = ManualFileInput(path="file_last.py", content="x" * (remainder + 1))
        assert sum(len(f.content.encode("utf-8")) for f in files) == MAX_TOTAL_BYTES + 1
        with pytest.raises(
            ScanPayloadTooLargeError, match="Total payload size exceeds maximum limit of 1 MB"
        ):
            validate_manual_scan_files(files)

    def test_utf8_multi_byte_character_byte_accounting(self) -> None:
        """UTF-8 byte accounting counts actual encoded bytes, not character count."""
        euro_char = "€"  # 3 bytes in UTF-8
        assert len(euro_char.encode("utf-8")) == 3

        # 68,266 Euro characters = 204,798 bytes (under 204,800 limit)
        content_within = euro_char * 68_266
        assert len(content_within) == 68_266
        assert len(content_within.encode("utf-8")) == 204_798
        summary, _ = validate_manual_scan_files(
            [ManualFileInput(path="euro.py", content=content_within)]
        )
        assert summary[0]["byte_size"] == 204_798

        # 68,267 Euro characters = 204,801 bytes (exceeds 204,800 limit)
        content_over = euro_char * 68_267
        assert len(content_over.encode("utf-8")) == 204_801
        with pytest.raises(
            ScanPayloadTooLargeError, match="exceeds maximum allowed size of 200 KB"
        ):
            validate_manual_scan_files([ManualFileInput(path="euro.py", content=content_over)])

    def test_exact_5000_char_line_length_boundary(self) -> None:
        """Line length boundary (5,000 chars not minified, 5,001 chars minified)."""
        exact_5000 = "x" * MAX_LINE_LENGTH
        summary_5000, _ = validate_manual_scan_files(
            [ManualFileInput(path="app.py", content=exact_5000)]
        )
        assert summary_5000[0]["scanned"] is True
        assert summary_5000[0]["skip_reason"] is None

        over_5001 = "x" * (MAX_LINE_LENGTH + 1)
        summary_5001, _ = validate_manual_scan_files(
            [ManualFileInput(path="app.py", content=over_5001)]
        )
        assert summary_5001[0]["scanned"] is False
        assert summary_5001[0]["skip_reason"] == "minified_or_generated"


class TestScanAndJobPersistenceTransactional:
    """Tests for single-transaction Scan + Job creation, relationship, and rollback."""

    def test_create_manual_scan_success(
        self,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Verify successful atomic creation of Scan and Job with correct fields."""
        files = [
            ManualFileInput(path="app/main.py", content="def run(): pass"),
            ManualFileInput(path="README.md", content="# Project Readme"),
        ]

        scan, job = create_manual_scan(
            session=db_session,
            project_id=sample_project.id,
            files=files,
            run_ai=True,
            created_by_user_id=sample_user.id,
            auto_commit=True,
        )

        assert scan.id is not None
        assert job.id is not None
        assert job.scan_id == scan.id
        assert scan.project_id == sample_project.id
        assert scan.created_by_user_id == sample_user.id
        assert scan.status == "queued"
        assert scan.trigger == "manual"
        assert scan.report_status == "not_applicable"
        assert job.status == "queued"
        assert job.type == "scan"
        assert job.attempts == 0
        assert job.max_attempts == 3

        # Verify payload contains files and run_ai flag
        assert isinstance(job.payload, dict)
        assert job.payload["run_ai"] is True
        assert len(job.payload["files"]) == 2
        assert job.payload["files"][0]["path"] == "app/main.py"
        assert job.payload["files"][0]["content"] == "def run(): pass"

        # Verify files_summary in Scan
        assert scan.files_summary is not None
        assert len(scan.files_summary) == 2
        assert scan.files_summary[0]["path"] == "app/main.py"
        assert scan.files_summary[0]["scanned"] is True
        assert scan.files_summary[1]["path"] == "README.md"
        assert scan.files_summary[1]["scanned"] is False
        assert scan.files_summary[1]["skip_reason"] == "unsupported_extension"

        # Verify ORM relationship navigation
        assert scan.job is not None
        assert scan.job.id == job.id
        assert job.scan.id == scan.id

        # Verify get_scan service helper
        retrieved_scan = get_scan(db_session, scan.id)
        assert retrieved_scan is not None
        assert retrieved_scan.id == scan.id

    def test_invalid_project_id_raises_not_found(
        self,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Creating a scan for a non-existent project raises ProjectNotFoundError."""
        non_existent_id = uuid.uuid4()
        files = [ManualFileInput(path="main.py", content="x = 1")]

        with pytest.raises(ProjectNotFoundError, match="does not exist"):
            create_manual_scan(
                session=db_session,
                project_id=non_existent_id,
                files=files,
                created_by_user_id=sample_user.id,
            )

        # Confirm no scan or job was inserted
        scans = db_session.scalars(select(Scan)).all()
        jobs = db_session.scalars(select(Job)).all()
        assert len(scans) == 0
        assert len(jobs) == 0

    def test_invalid_user_id_raises_not_found(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Supplying a non-existent user_id raises UserNotFoundError."""
        non_existent_user_id = uuid.uuid4()
        files = [ManualFileInput(path="main.py", content="x = 1")]

        with pytest.raises(UserNotFoundError, match="does not exist"):
            create_manual_scan(
                session=db_session,
                project_id=sample_project.id,
                files=files,
                created_by_user_id=non_existent_user_id,
            )

        # Confirm no scan or job was inserted
        scans = db_session.scalars(select(Scan)).all()
        jobs = db_session.scalars(select(Job)).all()
        assert len(scans) == 0
        assert len(jobs) == 0

    def test_unique_trigger_key_conflict_raises_409(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Creating two scans with the same trigger_key on the same project raises ScanConflictError."""
        files = [ManualFileInput(path="main.py", content="x = 1")]
        trigger_key = "idempotency-key-12345"

        # First scan succeeds
        scan1, _ = create_manual_scan(
            session=db_session,
            project_id=sample_project.id,
            files=files,
            trigger_key=trigger_key,
            auto_commit=True,
        )
        assert scan1.id is not None

        # Second scan with identical trigger_key must fail
        with pytest.raises(ScanConflictError, match="already exists for project"):
            create_manual_scan(
                session=db_session,
                project_id=sample_project.id,
                files=files,
                trigger_key=trigger_key,
                auto_commit=True,
            )

        # Verify only the first scan and job exist
        scans = db_session.scalars(select(Scan)).all()
        jobs = db_session.scalars(select(Job)).all()
        assert len(scans) == 1
        assert len(jobs) == 1

    def test_same_trigger_key_different_projects_allowed(
        self,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Same trigger_key on different projects is allowed (scoped by project_id)."""
        project1 = Project(owner_user_id=sample_user.id, kind="manual", name="P1", status="active")
        project2 = Project(owner_user_id=sample_user.id, kind="manual", name="P2", status="active")
        db_session.add_all([project1, project2])
        db_session.commit()

        files = [ManualFileInput(path="main.py", content="x = 1")]
        common_key = "shared-trigger-key"

        scan1, _ = create_manual_scan(
            session=db_session,
            project_id=project1.id,
            files=files,
            trigger_key=common_key,
            auto_commit=True,
        )
        scan2, _ = create_manual_scan(
            session=db_session,
            project_id=project2.id,
            files=files,
            trigger_key=common_key,
            auto_commit=True,
        )

        assert scan1.id != scan2.id
        assert scan1.trigger_key == common_key
        assert scan2.trigger_key == common_key

    def test_rollback_on_session_scope_exception(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """Verify that an unhandled exception rolls back both Scan and Job."""
        files = [ManualFileInput(path="main.py", content="x = 1")]

        with (
            pytest.raises(RuntimeError, match="Simulated application crash"),
            session_scope(session_factory) as session,
        ):
            create_manual_scan(
                session=session,
                project_id=sample_project.id,
                files=files,
            )
            raise RuntimeError("Simulated application crash")

        # Verify in a clean session that neither Scan nor Job was committed
        with session_scope(session_factory) as session:
            scans = session.scalars(select(Scan)).all()
            jobs = session.scalars(select(Job)).all()
            assert len(scans) == 0
            assert len(jobs) == 0

    def test_rollback_on_flush_failure(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify that if session.flush() fails, both Scan and Job are rolled back."""
        files_summary = [{"path": "main.py", "byte_size": 5, "scanned": True, "skip_reason": None}]
        payload_files = [
            {"path": "main.py", "content": "x = 1", "scanned": True, "skip_reason": None}
        ]

        with (
            patch.object(db_session, "flush", side_effect=RuntimeError("Simulated DB flush error")),
            pytest.raises(Exception, match="Unexpected database error creating scan and job"),
        ):
            create_scan_and_job(
                session=db_session,
                project_id=sample_project.id,
                files_summary=files_summary,
                payload_files=payload_files,
            )

        # Neither Scan nor Job remains
        scans = db_session.scalars(select(Scan)).all()
        jobs = db_session.scalars(select(Job)).all()
        assert len(scans) == 0
        assert len(jobs) == 0

    def test_conflict_leaves_session_usable_without_autocommit(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When a conflict occurs with auto_commit=False, the session is rolled back

        internally so it remains safe and usable for subsequent queries and operations.
        """
        files = [ManualFileInput(path="main.py", content="x = 1")]
        trigger_key = "idempotency-key-usable-check"

        # 1. Create initial scan and commit it
        scan1, _ = create_manual_scan(
            session=db_session,
            project_id=sample_project.id,
            files=files,
            trigger_key=trigger_key,
            auto_commit=True,
        )
        assert scan1.id is not None

        # 2. Attempt duplicate scan with auto_commit=False; raises ScanConflictError
        with pytest.raises(ScanConflictError, match="already exists for project"):
            create_manual_scan(
                session=db_session,
                project_id=sample_project.id,
                files=files,
                trigger_key=trigger_key,
                auto_commit=False,
            )

        # 3. Verify session is NOT in broken/PendingRollbackError state:
        # Caller can successfully query and execute a new scan in the exact same session
        alternate_key = "idempotency-key-usable-check-alternate"
        scan2, job2 = create_manual_scan(
            session=db_session,
            project_id=sample_project.id,
            files=files,
            trigger_key=alternate_key,
            auto_commit=False,
        )
        db_session.commit()

        assert scan2.id is not None
        assert job2.id is not None
        assert scan2.trigger_key == alternate_key

    def test_service_does_not_commit_when_autocommit_false_and_caller_rolls_back(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """When auto_commit=False, the service flushes but does not commit.

        The outer caller (e.g. session_scope) owns transaction boundaries.
        """
        files = [ManualFileInput(path="main.py", content="x = 1")]

        with session_scope(session_factory) as session:
            scan, job = create_manual_scan(
                session=session,
                project_id=sample_project.id,
                files=files,
                auto_commit=False,
            )
            assert scan.id is not None
            assert job.id is not None
            # Caller decides to abort outer transaction
            session.rollback()

        # In a new session, verify nothing was committed
        with session_scope(session_factory) as check_session:
            scans = check_session.scalars(select(Scan)).all()
            jobs = check_session.scalars(select(Job)).all()
            assert len(scans) == 0
            assert len(jobs) == 0


class TestFastAPIEndpoints:
    """Tests for FastAPI HTTP endpoints: POST /projects/{id}/scans/manual and GET /scans/{id}."""

    def test_post_manual_scan_unauthenticated_fails_closed_by_default(
        self,
        unauthenticated_client: TestClient,
        sample_project: Project,
    ) -> None:
        """Scan creation fails closed (401 Unauthorized) when unauthenticated scans are not enabled."""
        payload = {"files": [{"path": "main.py", "content": "x = 1"}]}
        response = unauthenticated_client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_post_manual_scan_production_fails_closed(
        self,
        production_client: TestClient,
        sample_project: Project,
    ) -> None:
        """Scan creation fails closed in production even if an attempt is made to bypass."""
        payload = {"files": [{"path": "main.py", "content": "x = 1"}]}
        response = production_client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_client_supplied_user_id_rejected_as_extra_field(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """Client-supplied created_by_user_id is never accepted as identity (rejected with 422)."""
        random_user_id = uuid.uuid4()
        payload = {
            "files": [{"path": "main.py", "content": "x = 1"}],
            "created_by_user_id": str(random_user_id),
        }

        response = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 422
        assert "extra" in response.text.lower() or "forbidden" in response.text.lower()

    def test_post_manual_scan_success(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """POST /api/v1/projects/{id}/scans/manual returns 202 Accepted with status_url."""
        payload = {
            "files": [
                {"path": "src/app.py", "content": "def run(): return 1"},
                {"path": ".env", "content": "DATABASE_URL=postgres://..."},
            ],
            "run_ai": True,
        }

        response = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )

        assert response.status_code == 202
        data = response.json()
        assert "id" in data
        assert data["status"] == "queued"
        assert data["status_url"] == f"/api/v1/scans/{data['id']}"

        # Test polling status via GET /api/v1/scans/{id}
        scan_id = data["id"]
        detail_response = client.get(f"/api/v1/scans/{scan_id}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        assert detail["id"] == scan_id
        assert detail["project_id"] == str(sample_project.id)
        assert detail["status"] == "queued"
        assert detail["trigger"] == "manual"
        assert detail["pr"] is None
        assert detail["report_status"] == "not_applicable"
        assert len(detail["files_summary"]) == 2
        assert detail["files_summary"][0]["path"] == "src/app.py"
        assert detail["files_summary"][0]["scanned"] is True
        assert detail["files_summary"][1]["path"] == ".env"
        assert detail["files_summary"][1]["scanned"] is True

    def test_root_path_aliases_work(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """Root-level routes (/projects/... and /scans/...) match versioned routes."""
        payload = {
            "files": [{"path": "main.py", "content": "x = 42"}],
        }

        # Create via root path
        create_resp = client.post(
            f"/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert create_resp.status_code == 202
        scan_id = create_resp.json()["id"]

        # Retrieve via root path
        get_resp = client.get(f"/scans/{scan_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == scan_id

    def test_post_manual_scan_project_not_found(self, client: TestClient) -> None:
        """POST to non-existent project returns 404 Not Found."""
        random_project_id = uuid.uuid4()
        payload = {"files": [{"path": "main.py", "content": "x = 1"}]}

        response = client.post(
            f"/api/v1/projects/{random_project_id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 404
        assert "does not exist" in response.json()["detail"]

    def test_post_manual_scan_payload_too_large_413(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """POST exceeding 200 KB per file returns 413 Request Entity Too Large."""
        oversized = "x" * (MAX_FILE_BYTES + 10)
        payload = {"files": [{"path": "large.py", "content": oversized}]}

        response = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 413
        assert "exceeds maximum allowed size of 200 KB" in response.json()["detail"]

    def test_post_manual_scan_validation_error_422(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """POST with duplicate paths returns 422 Unprocessable Entity."""
        payload = {
            "files": [
                {"path": "src/App.py", "content": "x = 1"},
                {"path": "src/app.py", "content": "x = 2"},
            ]
        }

        response = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 422
        assert "Duplicate file path" in response.json()["detail"]

    def test_post_manual_scan_conflict_409(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """POST with duplicate trigger_key returns 409 Conflict."""
        payload = {
            "files": [{"path": "main.py", "content": "x = 1"}],
            "trigger_key": "fixed-idempotency-key",
        }

        # First request succeeds
        resp1 = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert resp1.status_code == 202

        # Second request with same trigger_key conflicts
        resp2 = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert resp2.status_code == 409
        assert "already exists for project" in resp2.json()["detail"]

    def test_get_scan_not_found_404(self, client: TestClient) -> None:
        """GET /api/v1/scans/{non_existent_id} returns 404 Not Found."""
        random_scan_id = uuid.uuid4()
        response = client.get(f"/api/v1/scans/{random_scan_id}")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def test_submitted_source_and_secrets_confidentiality(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """Submitted code and secrets are never returned in responses or error messages."""
        secret_token = "ghp_TEST_MOCK_SECRET_TOKEN_DO_NOT_LEAK_9876543210"
        secret_content = f"DATABASE_PASSWORD = '{secret_token}'\nAPI_KEY = '{secret_token}'\n"

        payload = {
            "files": [{"path": "secrets.py", "content": secret_content}],
            "trigger_key": "confidentiality-test-key",
        }

        # 1. 202 Accepted response must not leak source code or secrets
        resp = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert resp.status_code == 202
        assert secret_token not in resp.text
        scan_id = resp.json()["id"]

        # 2. 200 OK scan-detail response must not leak source code or secrets
        detail_resp = client.get(f"/api/v1/scans/{scan_id}")
        assert detail_resp.status_code == 200
        assert secret_token not in detail_resp.text
        assert "DATABASE_PASSWORD" not in detail_resp.text

        # 3. 409 Conflict error must not leak source code or secrets
        conflict_resp = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert conflict_resp.status_code == 409
        assert secret_token not in conflict_resp.text
