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

import hashlib
import os
import uuid
from collections.abc import Generator
from datetime import timedelta
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
from app.db.base import Base, utc_now
from app.db.models import Finding, Job, Project, Scan, User, UserSession
from app.db.session import get_db_session, session_scope
from app.domain.findings import (
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
)
from app.main import app
from app.schemas.scan import ManualFileInput
from app.services.finding_service import persist_scan_findings
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
def other_user(db_session: Session) -> User:
    """Second user for cross-tenant isolation testing."""
    user = User(
        github_user_id=654321,
        github_login="other-attacker",
        display_name="Other User",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def other_project(db_session: Session, other_user: User) -> Project:
    """Project owned by second user for cross-tenant isolation testing."""
    project = Project(
        owner_user_id=other_user.id,
        kind="manual",
        name="Other Project",
        status="active",
    )
    db_session.add(project)
    db_session.commit()
    return project


def create_authenticated_user_session(db_session: Session, user: User) -> str:
    """Helper to create a server-side session and return raw token for Bearer auth."""
    raw_token = f"test-token-{uuid.uuid4().hex}-{user.id}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).digest()
    user_session = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash,
        expires_at=utc_now() + timedelta(days=1),
    )
    db_session.add(user_session)
    db_session.commit()
    return raw_token


@pytest.fixture
def client(
    session_factory: sessionmaker[Session],
    db_session: Session,
    sample_user: User,
) -> Generator[TestClient, None, None]:
    """TestClient authenticated as sample_user via real UserSession token."""
    token = create_authenticated_user_session(db_session, sample_user)

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def other_client(
    session_factory: sessionmaker[Session],
    db_session: Session,
    other_user: User,
) -> Generator[TestClient, None, None]:
    """TestClient authenticated as other_user via real UserSession token."""
    token = create_authenticated_user_session(db_session, other_user)

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as test_client:
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

    app.dependency_overrides[get_db_session] = override_get_db_session
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
            GITLEAKS_PATH=os.path.abspath("/usr/local/bin/gitleaks"),
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

    def test_post_manual_scan_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
        sample_project: Project,
    ) -> None:
        """POST /projects/{id}/scans/manual without authentication fails closed with 401 Unauthorized."""
        payload = {"files": [{"path": "main.py", "content": "x = 1"}]}
        # Versioned route
        response = unauthenticated_client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

        # Root-level route alias
        root_response = unauthenticated_client.post(
            f"/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert root_response.status_code == 401
        assert "Authentication required" in root_response.json()["detail"]

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
        assert "not found" in response.json()["detail"].lower()

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

    def test_get_scan_unauthenticated_fails_closed_401(
        self,
        unauthenticated_client: TestClient,
        sample_project: Project,
        db_session: Session,
    ) -> None:
        """GET /scans/{id} without authentication fails closed with 401 Unauthorized."""
        scan, _ = create_manual_scan(
            db_session,
            project_id=sample_project.id,
            files=[ManualFileInput(path="src/main.py", content="x = 1")],
            auto_commit=True,
        )
        response = unauthenticated_client.get(f"/api/v1/scans/{scan.id}")
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_get_scan_cross_tenant_isolation_returns_404(
        self,
        client: TestClient,
        other_client: TestClient,
        sample_project: Project,
        other_project: Project,
        db_session: Session,
    ) -> None:
        """User B cannot retrieve User A's scan and receives 404 Not Found."""
        alice_scan, _ = create_manual_scan(
            db_session,
            project_id=sample_project.id,
            files=[ManualFileInput(path="src/alice.py", content="a = 1")],
            auto_commit=True,
        )
        bob_scan, _ = create_manual_scan(
            db_session,
            project_id=other_project.id,
            files=[ManualFileInput(path="src/bob.py", content="b = 2")],
            auto_commit=True,
        )

        # User A can retrieve own scan
        r_alice = client.get(f"/api/v1/scans/{alice_scan.id}")
        assert r_alice.status_code == 200
        assert r_alice.json()["id"] == str(alice_scan.id)

        # User B cannot retrieve User A's scan -> 404
        r_bob_alice = other_client.get(f"/api/v1/scans/{alice_scan.id}")
        assert r_bob_alice.status_code == 404
        assert f"Scan with ID '{alice_scan.id}' not found" in r_bob_alice.json()["detail"]

        # User A cannot retrieve User B's scan -> 404
        r_alice_bob = client.get(f"/api/v1/scans/{bob_scan.id}")
        assert r_alice_bob.status_code == 404
        assert f"Scan with ID '{bob_scan.id}' not found" in r_alice_bob.json()["detail"]

    def test_post_manual_scan_cross_tenant_isolation_returns_404(
        self,
        other_client: TestClient,
        sample_project: Project,
    ) -> None:
        """User B cannot submit a manual scan to User A's project and receives 404 Not Found."""
        payload = {"files": [{"path": "src/exploit.py", "content": "attack = True"}]}
        response = other_client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 404
        assert f"Project with ID '{sample_project.id}' not found" in response.json()["detail"]

    def test_post_manual_scan_records_authenticated_user_id(
        self,
        client: TestClient,
        sample_project: Project,
        sample_user: User,
        db_session: Session,
    ) -> None:
        """Successful scan creation stores the authenticated user's ID in created_by_user_id."""
        payload = {"files": [{"path": "src/feature.py", "content": "data = 123"}]}
        response = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 202
        scan_id = uuid.UUID(response.json()["id"])

        db_session.expire_all()
        scan = db_session.get(Scan, scan_id)
        assert scan is not None
        assert scan.created_by_user_id == sample_user.id

    def test_post_manual_scan_soft_deleted_project_returns_404(
        self,
        client: TestClient,
        sample_project: Project,
        db_session: Session,
    ) -> None:
        """Soft-deleted project fails closed with 404 Not Found for scan submission and retrieval."""
        # 1. Create a scan while project is active
        scan, _ = create_manual_scan(
            db_session,
            project_id=sample_project.id,
            files=[ManualFileInput(path="src/feature.py", content="data = 123")],
            auto_commit=True,
        )

        # 2. Mark the project soft-deleted and commit
        sample_project.deleted_at = utc_now()
        db_session.commit()

        # 3. Verify POST scan submission returns 404 with project-not-found detail
        payload = {"files": [{"path": "src/feature.py", "content": "data = 123"}]}
        response = client.post(
            f"/api/v1/projects/{sample_project.id}/scans/manual",
            json=payload,
        )
        assert response.status_code == 404
        assert f"Project with ID '{sample_project.id}' not found" in response.json()["detail"]

        # 4. Verify GET scan retrieval returns 404 with generic scan-not-found detail
        get_response = client.get(f"/api/v1/scans/{scan.id}")
        assert get_response.status_code == 404
        assert f"Scan with ID '{scan.id}' not found" in get_response.json()["detail"]


class TestListScansEndpoints:
    """Test suite for GET /projects/{project_id}/scans and GET /scans listing endpoints."""

    def test_list_project_scans_pagination_and_deterministic_ordering(
        self,
        client: TestClient,
        sample_project: Project,
        sample_user: User,
        db_session: Session,
    ) -> None:
        """Verify deterministic ordering (created_at DESC, id DESC), pagination, and ScanListItem fields."""
        base_time = utc_now()
        # Create 3 scans with distinct creation timestamps
        scan_oldest = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="manual:oldest",
            status="succeeded",
            counts={"critical": 0, "high": 1},
            queued_at=base_time - timedelta(minutes=30),
            created_at=base_time - timedelta(minutes=30),
            created_by_user_id=sample_user.id,
        )
        scan_middle = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="manual:middle",
            status="failed",
            error_code="TIMEOUT",
            error_message="Worker timeout",
            queued_at=base_time - timedelta(minutes=15),
            created_at=base_time - timedelta(minutes=15),
            created_by_user_id=sample_user.id,
        )
        scan_newest = Scan(
            project_id=sample_project.id,
            trigger="pull_request",
            trigger_key="pr:42:head1",
            pr_number=42,
            head_sha="a" * 40,
            pr_title="Add auth feature",
            status="queued",
            queued_at=base_time,
            created_at=base_time,
            created_by_user_id=sample_user.id,
        )
        db_session.add_all([scan_oldest, scan_middle, scan_newest])
        db_session.commit()

        # Page 1: limit=2, offset=0
        resp1 = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params={"limit": 2, "offset": 0},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["total"] == 3
        assert data1["limit"] == 2
        assert data1["offset"] == 0
        assert len(data1["items"]) == 2

        # Verify ordering: newest first, then middle
        assert data1["items"][0]["id"] == str(scan_newest.id)
        assert data1["items"][0]["trigger"] == "pull_request"
        assert data1["items"][0]["status"] == "queued"
        assert data1["items"][0]["pr"] == {
            "number": 42,
            "head_sha": "a" * 40,
            "title": "Add auth feature",
        }

        assert data1["items"][1]["id"] == str(scan_middle.id)
        assert data1["items"][1]["error"] == {
            "code": "TIMEOUT",
            "message": "Worker timeout",
        }

        # Page 2: limit=2, offset=2
        resp2 = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params={"limit": 2, "offset": 2},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 3
        assert data2["limit"] == 2
        assert data2["offset"] == 2
        assert len(data2["items"]) == 1
        assert data2["items"][0]["id"] == str(scan_oldest.id)
        assert data2["items"][0]["counts"] == {"critical": 0, "high": 1}

    def test_list_scans_tenant_isolation(
        self,
        client: TestClient,
        other_client: TestClient,
        sample_project: Project,
        other_project: Project,
        sample_user: User,
        other_user: User,
        db_session: Session,
    ) -> None:
        """Tenant isolation: Users can only see their own scans; foreign project scan listing returns 404."""
        # Create scans for User A (sample_user)
        scan_a1 = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="a1",
            status="succeeded",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        scan_a2 = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="a2",
            status="queued",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        # Create scan for User B (other_user)
        scan_b1 = Scan(
            project_id=other_project.id,
            trigger="manual",
            trigger_key="b1",
            status="succeeded",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=other_user.id,
        )
        db_session.add_all([scan_a1, scan_a2, scan_b1])
        db_session.commit()

        # User A project scans
        resp_a = client.get(f"/api/v1/projects/{sample_project.id}/scans")
        assert resp_a.status_code == 200
        assert resp_a.json()["total"] == 2
        ids_a = {item["id"] for item in resp_a.json()["items"]}
        assert ids_a == {str(scan_a1.id), str(scan_a2.id)}

        # User B attempts to access User A's project scans -> 404 Not Found
        resp_b_cross = other_client.get(f"/api/v1/projects/{sample_project.id}/scans")
        assert resp_b_cross.status_code == 404
        assert f"Project with ID '{sample_project.id}' not found" in resp_b_cross.json()["detail"]

        # User B lists scans cross-project via GET /scans -> only sees User B's scans
        resp_b_all = other_client.get("/api/v1/scans")
        assert resp_b_all.status_code == 200
        assert resp_b_all.json()["total"] == 1
        assert resp_b_all.json()["items"][0]["id"] == str(scan_b1.id)

        # User B attempts GET /scans?project_id=A -> 404 Not Found
        resp_b_filter_a = other_client.get(
            "/api/v1/scans",
            params={"project_id": str(sample_project.id)},
        )
        assert resp_b_filter_a.status_code == 404

        # User A lists scans cross-project via GET /scans -> only sees User A's 2 scans
        resp_a_all = client.get("/api/v1/scans")
        assert resp_a_all.status_code == 200
        assert resp_a_all.json()["total"] == 2

    def test_list_scans_filters_status_trigger_pr(
        self,
        client: TestClient,
        sample_project: Project,
        sample_user: User,
        db_session: Session,
    ) -> None:
        """Filter scans by status, trigger, and pr_number."""
        scan1 = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="t1",
            status="succeeded",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        scan2 = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="t2",
            status="failed",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        scan3 = Scan(
            project_id=sample_project.id,
            trigger="pull_request",
            trigger_key="t3",
            pr_number=99,
            status="queued",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add_all([scan1, scan2, scan3])
        db_session.commit()

        # Filter by status=succeeded
        resp_status = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params={"status": "succeeded"},
        )
        assert resp_status.status_code == 200
        assert resp_status.json()["total"] == 1
        assert resp_status.json()["items"][0]["id"] == str(scan1.id)

        # Filter by trigger=pull_request
        resp_trigger = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params={"trigger": "pull_request"},
        )
        assert resp_trigger.status_code == 200
        assert resp_trigger.json()["total"] == 1
        assert resp_trigger.json()["items"][0]["id"] == str(scan3.id)

        # Filter by pr_number=99
        resp_pr = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params={"pr_number": 99},
        )
        assert resp_pr.status_code == 200
        assert resp_pr.json()["total"] == 1
        assert resp_pr.json()["items"][0]["id"] == str(scan3.id)

        # Multiple statuses: status=succeeded&status=failed
        resp_multi_status = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params=[("status", "succeeded"), ("status", "failed")],
        )
        assert resp_multi_status.status_code == 200
        assert resp_multi_status.json()["total"] == 2

    def test_list_scans_empty_results(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """User with no scans gets empty list with total=0."""
        resp = client.get(f"/api/v1/projects/{sample_project.id}/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["limit"] == 20
        assert data["offset"] == 0

        resp_global = client.get("/api/v1/scans")
        assert resp_global.status_code == 200
        assert resp_global.json()["items"] == []
        assert resp_global.json()["total"] == 0

    def test_list_scans_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
        sample_project: Project,
    ) -> None:
        """Unauthenticated requests return 401."""
        resp1 = unauthenticated_client.get(f"/api/v1/projects/{sample_project.id}/scans")
        assert resp1.status_code == 401

        resp2 = unauthenticated_client.get("/api/v1/scans")
        assert resp2.status_code == 401

    def test_list_scans_validation_errors_return_422(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """Out of bounds pagination or invalid pr_number parameters return 422 Unprocessable Content."""
        assert client.get(f"/api/v1/projects/{sample_project.id}/scans?limit=0").status_code == 422
        assert (
            client.get(f"/api/v1/projects/{sample_project.id}/scans?limit=101").status_code == 422
        )
        assert (
            client.get(f"/api/v1/projects/{sample_project.id}/scans?offset=-1").status_code == 422
        )
        assert (
            client.get(f"/api/v1/projects/{sample_project.id}/scans?pr_number=0").status_code == 422
        )
        assert (
            client.get(f"/api/v1/projects/{sample_project.id}/scans?pr_number=-10").status_code
            == 422
        )

    def test_list_scans_soft_deleted_project_excluded(
        self,
        client: TestClient,
        sample_project: Project,
        sample_user: User,
        db_session: Session,
    ) -> None:
        """Soft-deleted project scans return 404 on project endpoint and are excluded from user scan list."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="del_test",
            status="succeeded",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        sample_project.deleted_at = utc_now()
        db_session.commit()

        # Project endpoint returns 404
        resp_proj = client.get(f"/api/v1/projects/{sample_project.id}/scans")
        assert resp_proj.status_code == 404

        # Cross-project /scans excludes soft-deleted project's scan
        resp_all = client.get("/api/v1/scans")
        assert resp_all.status_code == 200
        assert resp_all.json()["total"] == 0
        assert resp_all.json()["items"] == []

    def test_list_scans_root_and_api_v1_prefixes(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """Both root /projects/{id}/scans and /api/v1/projects/{id}/scans routes succeed."""
        resp_root = client.get(f"/projects/{sample_project.id}/scans")
        assert resp_root.status_code == 200

        resp_v1 = client.get(f"/api/v1/projects/{sample_project.id}/scans")
        assert resp_v1.status_code == 200

        resp_root_scans = client.get("/scans")
        assert resp_root_scans.status_code == 200

        resp_v1_scans = client.get("/api/v1/scans")
        assert resp_v1_scans.status_code == 200

    def test_list_scans_deterministic_tie_breaking(
        self,
        client: TestClient,
        sample_project: Project,
        sample_user: User,
        db_session: Session,
    ) -> None:
        """Multiple scans with identical created_at timestamps are deterministically sorted by Scan.id.desc()."""
        fixed_time = utc_now()
        id_1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        id_2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
        id_3 = uuid.UUID("33333333-3333-3333-3333-333333333333")

        scan1 = Scan(
            id=id_1,
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="tie:1",
            status="succeeded",
            queued_at=fixed_time,
            created_at=fixed_time,
            created_by_user_id=sample_user.id,
        )
        scan2 = Scan(
            id=id_2,
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="tie:2",
            status="succeeded",
            queued_at=fixed_time,
            created_at=fixed_time,
            created_by_user_id=sample_user.id,
        )
        scan3 = Scan(
            id=id_3,
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="tie:3",
            status="succeeded",
            queued_at=fixed_time,
            created_at=fixed_time,
            created_by_user_id=sample_user.id,
        )
        db_session.add_all([scan2, scan1, scan3])
        db_session.commit()

        resp = client.get(f"/api/v1/projects/{sample_project.id}/scans")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 3
        # Should be ordered by id DESC: id_3, id_2, id_1
        assert items[0]["id"] == str(id_3)
        assert items[1]["id"] == str(id_2)
        assert items[2]["id"] == str(id_1)

    def test_list_scans_multi_value_trigger_filter(
        self,
        client: TestClient,
        sample_project: Project,
        sample_user: User,
        db_session: Session,
    ) -> None:
        """Repeated trigger query parameters return the correct combined results."""
        scan_manual = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="trig:manual",
            status="succeeded",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        scan_pr = Scan(
            project_id=sample_project.id,
            trigger="pull_request",
            trigger_key="trig:pr",
            pr_number=10,
            status="succeeded",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        scan_rerun = Scan(
            project_id=sample_project.id,
            trigger="rerun",
            trigger_key="trig:rerun",
            status="succeeded",
            queued_at=utc_now(),
            created_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add_all([scan_manual, scan_pr, scan_rerun])
        db_session.commit()

        # Filter by trigger=manual&trigger=pull_request
        resp = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params=[("trigger", "manual"), ("trigger", "pull_request")],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        triggers = {item["trigger"] for item in data["items"]}
        assert triggers == {"manual", "pull_request"}

    def test_list_scans_cross_project_global_pagination(
        self,
        client: TestClient,
        sample_user: User,
        other_user: User,
        sample_project: Project,
        db_session: Session,
    ) -> None:
        """GET /scans paginates across multiple projects owned by the user and excludes foreign tenant scans."""
        base_time = utc_now()

        project_2 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Second Project",
            status="active",
        )
        foreign_project = Project(
            owner_user_id=other_user.id,
            kind="manual",
            name="Foreign Tenant Project",
            status="active",
        )
        db_session.add_all([project_2, foreign_project])
        db_session.commit()

        # User A Project 1: scan 1 (oldest: -30m) and scan 3 (newest: base_time)
        scan_p1_old = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="p1:old",
            status="succeeded",
            queued_at=base_time - timedelta(minutes=30),
            created_at=base_time - timedelta(minutes=30),
            created_by_user_id=sample_user.id,
        )
        scan_p1_new = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="p1:new",
            status="succeeded",
            queued_at=base_time,
            created_at=base_time,
            created_by_user_id=sample_user.id,
        )
        # User A Project 2: scan 2 (middle: -15m)
        scan_p2_mid = Scan(
            project_id=project_2.id,
            trigger="manual",
            trigger_key="p2:mid",
            status="succeeded",
            queued_at=base_time - timedelta(minutes=15),
            created_at=base_time - timedelta(minutes=15),
            created_by_user_id=sample_user.id,
        )
        # Foreign tenant scan (base_time)
        scan_foreign = Scan(
            project_id=foreign_project.id,
            trigger="manual",
            trigger_key="foreign:scan",
            status="succeeded",
            queued_at=base_time,
            created_at=base_time,
            created_by_user_id=other_user.id,
        )
        db_session.add_all([scan_p1_old, scan_p1_new, scan_p2_mid, scan_foreign])
        db_session.commit()

        # Page 1: limit=2, offset=0
        resp1 = client.get("/api/v1/scans", params={"limit": 2, "offset": 0})
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["total"] == 3
        assert len(data1["items"]) == 2
        assert data1["items"][0]["id"] == str(scan_p1_new.id)
        assert data1["items"][0]["project_id"] == str(sample_project.id)
        assert data1["items"][1]["id"] == str(scan_p2_mid.id)
        assert data1["items"][1]["project_id"] == str(project_2.id)

        # Page 2: limit=2, offset=2
        resp2 = client.get("/api/v1/scans", params={"limit": 2, "offset": 2})
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 3
        assert len(data2["items"]) == 1
        assert data2["items"][0]["id"] == str(scan_p1_old.id)
        assert data2["items"][0]["project_id"] == str(sample_project.id)

        # Ensure foreign tenant scan never appears
        all_ids = {item["id"] for item in data1["items"] + data2["items"]}
        assert str(scan_foreign.id) not in all_ids

    def test_list_scans_invalid_status_and_trigger_return_422(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """Invalid status and trigger query parameters return HTTP 422 Unprocessable Content."""
        # Invalid status on project endpoint
        resp_bad_status_proj = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params={"status": "invalid_status_xyz"},
        )
        assert resp_bad_status_proj.status_code == 422

        # Invalid trigger on project endpoint
        resp_bad_trigger_proj = client.get(
            f"/api/v1/projects/{sample_project.id}/scans",
            params={"trigger": "invalid_trigger_abc"},
        )
        assert resp_bad_trigger_proj.status_code == 422

        # Invalid status on global /scans endpoint
        resp_bad_status_global = client.get(
            "/api/v1/scans",
            params={"status": "invalid_status_xyz"},
        )
        assert resp_bad_status_global.status_code == 422

        # Invalid trigger on global /scans endpoint
        resp_bad_trigger_global = client.get(
            "/api/v1/scans",
            params={"trigger": "invalid_trigger_abc"},
        )
        assert resp_bad_trigger_global.status_code == 422


def _make_canonical(
    *,
    rule_id: str = "rule.security.test",
    source: FindingSource = FindingSource.SEMGREP,
    category: FindingCategory = FindingCategory.INJECTION,
    title: str = "Test Finding",
    file_path: str = "src/test.py",
    start_line: int = 1,
    end_line: int | None = None,
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: FindingConfidence = FindingConfidence.HIGH,
    snippet: str | None = None,
    in_diff: bool = True,
    code_anchor: str | None = None,
    verification_status: VerificationStatus | None = None,
) -> CanonicalFinding:
    """Helper to create a valid CanonicalFinding instance for tests."""
    actual_end_line = end_line if end_line is not None else start_line + 1
    actual_snippet = snippet if snippet is not None else f"code_{file_path}_{start_line}()"
    actual_code_anchor = code_anchor
    if actual_code_anchor is None and (
        category == FindingCategory.HARDCODED_SECRET or source == FindingSource.GITLEAKS
    ):
        actual_code_anchor = hashlib.sha256(rule_id.encode("utf-8")).hexdigest()[:16]

    actual_status = verification_status
    if actual_status is None:
        actual_status = (
            VerificationStatus.AI_GROUNDED
            if source == FindingSource.AI
            else VerificationStatus.SCANNER_DETECTED
        )

    actual_confidence = confidence
    if source == FindingSource.AI and actual_confidence == FindingConfidence.HIGH:
        actual_confidence = FindingConfidence.MEDIUM

    return CanonicalFinding.create_canonical(
        rule_id=rule_id,
        source=source,
        category=category,
        title=title,
        description="Detailed description of test finding.",
        severity=severity,
        confidence=actual_confidence,
        verification_status=actual_status,
        file_path=file_path,
        start_line=start_line,
        end_line=actual_end_line,
        snippet=actual_snippet,
        remediation="Remediation guidance.",
        in_diff=in_diff,
        code_anchor=actual_code_anchor,
    )


class TestScanFindingsEndpoint:
    """Integration and security tests for GET /scans/{scan_id}/findings."""

    def test_list_scan_findings_pagination_and_ordering(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Findings are paginated and ordered by file_path ASC, start_line ASC, id ASC."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:order",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        db_session.commit()

        # Create findings with varying file paths and line numbers
        cf_b20 = _make_canonical(file_path="src/b.py", start_line=20, title="B20")
        cf_a50 = _make_canonical(file_path="src/a.py", start_line=50, title="A50")
        cf_a10 = _make_canonical(file_path="src/a.py", start_line=10, title="A10")
        cf_b5 = _make_canonical(file_path="src/b.py", start_line=5, title="B5")
        cf_c1_x = _make_canonical(
            file_path="src/c.py", start_line=1, title="C1_X", rule_id="rule.x"
        )
        cf_c1_y = _make_canonical(
            file_path="src/c.py", start_line=1, title="C1_Y", rule_id="rule.y"
        )

        persist_scan_findings(
            db_session,
            scan_id=scan.id,
            project_id=sample_project.id,
            findings=[cf_b20, cf_a50, cf_a10, cf_b5, cf_c1_x, cf_c1_y],
        )
        db_session.commit()

        # Page 1 (limit=2, offset=0) -> src/a.py line 10, src/a.py line 50
        resp1 = client.get(f"/api/v1/scans/{scan.id}/findings", params={"limit": 2, "offset": 0})
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["total"] == 6
        assert len(data1["items"]) == 2
        assert data1["limit"] == 2
        assert data1["offset"] == 0
        assert data1["items"][0]["file_path"] == "src/a.py"
        assert data1["items"][0]["title"] == "A10"
        assert data1["items"][1]["file_path"] == "src/a.py"
        assert data1["items"][1]["title"] == "A50"

        # Page 2 (limit=2, offset=2) -> src/b.py line 5, src/b.py line 20
        resp2 = client.get(f"/api/v1/scans/{scan.id}/findings", params={"limit": 2, "offset": 2})
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 6
        assert len(data2["items"]) == 2
        assert data2["items"][0]["file_path"] == "src/b.py"
        assert data2["items"][0]["title"] == "B5"
        assert data2["items"][1]["file_path"] == "src/b.py"
        assert data2["items"][1]["title"] == "B20"

        # Page 3 (limit=2, offset=4) -> src/c.py line 1 (tie broken by id ASC)
        resp3 = client.get(f"/api/v1/scans/{scan.id}/findings", params={"limit": 2, "offset": 4})
        assert resp3.status_code == 200
        data3 = resp3.json()
        assert data3["total"] == 6
        assert len(data3["items"]) == 2
        assert data3["items"][0]["file_path"] == "src/c.py"
        assert data3["items"][1]["file_path"] == "src/c.py"
        assert data3["items"][0]["id"] < data3["items"][1]["id"]

    def test_list_scan_findings_tenant_isolation(
        self,
        client: TestClient,
        other_client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
        other_project: Project,
        other_user: User,
    ) -> None:
        """Tenant cannot view findings of another tenant's scan; fails closed with generic 404."""
        scan_a = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:tenant_a",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        scan_b = Scan(
            project_id=other_project.id,
            trigger="manual",
            trigger_key="scan:findings:tenant_b",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=other_user.id,
        )
        db_session.add_all([scan_a, scan_b])
        db_session.commit()

        cf_a = _make_canonical(title="Tenant A Finding", file_path="src/tenant_a.py")
        cf_b = _make_canonical(title="Tenant B Finding", file_path="src/tenant_b.py")
        persist_scan_findings(
            db_session, scan_id=scan_a.id, project_id=sample_project.id, findings=[cf_a]
        )
        persist_scan_findings(
            db_session, scan_id=scan_b.id, project_id=other_project.id, findings=[cf_b]
        )
        db_session.commit()

        # Other client attempts to view Scan A's findings -> 404
        resp_b_on_a = other_client.get(f"/api/v1/scans/{scan_a.id}/findings")
        assert resp_b_on_a.status_code == 404
        assert resp_b_on_a.json()["detail"] == f"Scan with ID '{scan_a.id}' not found"

        # Client attempts to view Scan B's findings -> 404
        resp_a_on_b = client.get(f"/api/v1/scans/{scan_b.id}/findings")
        assert resp_a_on_b.status_code == 404
        assert resp_a_on_b.json()["detail"] == f"Scan with ID '{scan_b.id}' not found"

        # Nonexistent scan ID returns identical generic 404
        nonexistent_id = uuid.uuid4()
        resp_nonexistent = client.get(f"/api/v1/scans/{nonexistent_id}/findings")
        assert resp_nonexistent.status_code == 404
        assert resp_nonexistent.json()["detail"] == f"Scan with ID '{nonexistent_id}' not found"

    def test_list_scan_findings_soft_deleted_project_returns_404(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Scan findings for a soft-deleted project fail closed with generic 404."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:soft_del",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        db_session.commit()

        cf = _make_canonical(title="Pre-delete Finding", file_path="src/soft_delete.py")
        persist_scan_findings(
            db_session, scan_id=scan.id, project_id=sample_project.id, findings=[cf]
        )
        db_session.commit()

        # Soft delete project
        sample_project.deleted_at = utc_now()
        db_session.commit()

        resp = client.get(f"/api/v1/scans/{scan.id}/findings")
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"Scan with ID '{scan.id}' not found"

    def test_list_scan_findings_filters(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Filter scan findings by status, severity, source, in_diff, and text search q."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:filters",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        db_session.commit()

        cf1 = _make_canonical(
            rule_id="sec.injection.sql",
            source=FindingSource.SEMGREP,
            severity=FindingSeverity.CRITICAL,
            title="SQL Injection vulnerable call",
            file_path="src/database.py",
            in_diff=True,
        )
        cf2 = _make_canonical(
            rule_id="sec.secret.stripe",
            source=FindingSource.GITLEAKS,
            category=FindingCategory.HARDCODED_SECRET,
            severity=FindingSeverity.HIGH,
            title="Stripe Secret API key exposed",
            file_path="config/keys.py",
            snippet="API_KEY = '[REDACTED:sec.secret.stripe]'",
            in_diff=False,
        )
        cf3 = _make_canonical(
            rule_id="perf.ai.memory",
            source=FindingSource.AI,
            severity=FindingSeverity.LOW,
            title="Memory leak in event loop",
            file_path="src/worker.py",
            in_diff=True,
        )

        res = persist_scan_findings(
            db_session,
            scan_id=scan.id,
            project_id=sample_project.id,
            findings=[cf1, cf2, cf3],
        )
        db_session.commit()

        # Update finding 2's persistent status to fixed
        f2 = db_session.get(Finding, res.findings[1].id)
        assert f2 is not None
        f2.status = "fixed"
        db_session.commit()

        base_url = f"/api/v1/scans/{scan.id}/findings"

        # 1. Filter by status
        r_status_fixed = client.get(base_url, params={"status": "fixed"})
        assert r_status_fixed.status_code == 200
        assert r_status_fixed.json()["total"] == 1
        assert r_status_fixed.json()["items"][0]["title"] == "Stripe Secret API key exposed"

        r_status_multi = client.get(base_url, params=[("status", "open"), ("status", "fixed")])
        assert r_status_multi.status_code == 200
        assert r_status_multi.json()["total"] == 3

        # 2. Filter by severity
        r_sev_crit = client.get(base_url, params={"severity": "critical"})
        assert r_sev_crit.status_code == 200
        assert r_sev_crit.json()["total"] == 1
        assert r_sev_crit.json()["items"][0]["title"] == "SQL Injection vulnerable call"

        r_sev_multi = client.get(base_url, params=[("severity", "critical"), ("severity", "high")])
        assert r_sev_multi.status_code == 200
        assert r_sev_multi.json()["total"] == 2

        # 3. Filter by source
        r_src_gl = client.get(base_url, params={"source": "gitleaks"})
        assert r_src_gl.status_code == 200
        assert r_src_gl.json()["total"] == 1
        assert r_src_gl.json()["items"][0]["rule_id"] == "sec.secret.stripe"

        # 4. Filter by in_diff
        r_diff_true = client.get(base_url, params={"in_diff": "true"})
        assert r_diff_true.status_code == 200
        assert r_diff_true.json()["total"] == 2

        r_diff_false = client.get(base_url, params={"in_diff": "false"})
        assert r_diff_false.status_code == 200
        assert r_diff_false.json()["total"] == 1
        assert r_diff_false.json()["items"][0]["title"] == "Stripe Secret API key exposed"

        # 5. Text search q across title, file_path, and rule_id
        r_q_title = client.get(base_url, params={"q": "injection"})
        assert r_q_title.status_code == 200
        assert r_q_title.json()["total"] == 1
        assert r_q_title.json()["items"][0]["title"] == "SQL Injection vulnerable call"

        # Case-insensitivity check
        r_q_case = client.get(base_url, params={"q": "INJECTION"})
        assert r_q_case.status_code == 200
        assert r_q_case.json()["total"] == 1

        r_q_path = client.get(base_url, params={"q": "config/"})
        assert r_q_path.status_code == 200
        assert r_q_path.json()["total"] == 1

        r_q_rule = client.get(base_url, params={"q": "perf.ai"})
        assert r_q_rule.status_code == 200
        assert r_q_rule.json()["total"] == 1

    def test_list_scan_findings_invalid_filter_returns_422(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Invalid pagination and filter query parameters return HTTP 422 Unprocessable Content."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:invalid",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        db_session.commit()

        base_url = f"/api/v1/scans/{scan.id}/findings"

        # Invalid pagination bounds
        assert client.get(base_url, params={"limit": 0}).status_code == 422
        assert client.get(base_url, params={"limit": 101}).status_code == 422
        assert client.get(base_url, params={"offset": -1}).status_code == 422

        # Invalid enum values
        assert client.get(base_url, params={"status": "invalid_status_xyz"}).status_code == 422
        assert client.get(base_url, params={"severity": "extreme_danger"}).status_code == 422
        assert client.get(base_url, params={"source": "unsupported_tool"}).status_code == 422

        # Invalid text search length (min_length=1, max_length=100)
        assert client.get(base_url, params={"q": ""}).status_code == 422
        assert client.get(base_url, params={"q": "a" * 101}).status_code == 422

    def test_list_scan_findings_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Unauthenticated requests fail with HTTP 401 Unauthorized."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:unauth",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        db_session.commit()

        resp = unauthenticated_client.get(f"/api/v1/scans/{scan.id}/findings")
        assert resp.status_code == 401

    def test_list_scan_findings_empty_scan(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Scan with zero findings returns 200 OK with empty items list and total=0."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:empty",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        db_session.commit()

        resp = client.get(f"/api/v1/scans/{scan.id}/findings")
        assert resp.status_code == 200
        assert resp.json() == {
            "items": [],
            "total": 0,
            "limit": 20,
            "offset": 0,
        }

    def test_list_scan_findings_root_and_v1_routes(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Both /scans/{id}/findings and /api/v1/scans/{id}/findings return identical responses."""
        scan = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key="scan:findings:dual_route",
            status="succeeded",
            queued_at=utc_now(),
            created_by_user_id=sample_user.id,
        )
        db_session.add(scan)
        db_session.commit()

        cf = _make_canonical(title="Dual Route Finding", file_path="src/routes.py")
        persist_scan_findings(
            db_session, scan_id=scan.id, project_id=sample_project.id, findings=[cf]
        )
        db_session.commit()

        resp_v1 = client.get(f"/api/v1/scans/{scan.id}/findings")
        resp_root = client.get(f"/scans/{scan.id}/findings")

        assert resp_v1.status_code == 200
        assert resp_root.status_code == 200
        assert resp_v1.json() == resp_root.json()
