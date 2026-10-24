"""Unit and integration tests for Sentinel background worker execution pipeline.

Validates:
- Job dispatch and queue polling using claim_next_job
- Unsupported job type handling (terminal failure, UNSUPPORTED_JOB_TYPE)
- Malformed payload validation and rejection (MALFORMED_PAYLOAD, path safety, NUL bytes)
- Successful scan completion and metadata synchronization
- Partial scan completion and error preservation
- Retryable scanner failures (requeue with exponential backoff)
- Terminal scanner failures and max-attempts exhaustion
- Scanner exception handling (SCANNER_EXECUTION_ERROR)
- Default scanner isolation boundary (ISOLATION_UNAVAILABLE)
- Graceful shutdown and polling loop behavior
- Secret sanitization and payload erasure
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import Job, Project, Scan, User
from app.services.job_service import JobOwnershipError
from app.services.scan_service import MAX_FILE_BYTES, MAX_FILES_COUNT, MAX_TOTAL_BYTES
from app.worker.payload import PayloadValidationError, validate_scan_payload
from app.worker.runner import JobWorker
from app.worker.scanner import (
    CallableScannerEngine,
    DefaultScannerEngine,
    ScanExecutionResult,
    ScanJobPayload,
    ScannedFile,
    ScanStatus,
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
        github_user_id=999111,
        github_login="worker-test-dev",
        display_name="Worker Tester",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def sample_project(db_session: Session, sample_user: User) -> Project:
    """Create a persistent project in the test database."""
    project = Project(
        owner_user_id=sample_user.id,
        kind="manual",
        name="Worker Test Project",
        status="active",
    )
    db_session.add(project)
    db_session.commit()
    return project


def _create_job_for_test(
    session: Session,
    project: Project,
    *,
    job_type: str = "scan",
    status: str = "queued",
    attempts: int = 0,
    max_attempts: int = 3,
    payload: Any = None,
    run_after: datetime | None = None,
) -> tuple[Scan, Job]:
    """Helper to persist a Scan and Job for worker testing."""
    effective_now = run_after or utc_now()
    scan = Scan(
        project_id=project.id,
        trigger="manual",
        trigger_key=f"worker-test-{uuid.uuid4()}",
        status=status,
        report_status="not_applicable",
    )
    session.add(scan)
    session.flush()

    default_payload = {
        "files": [
            {
                "path": "app/auth.py",
                "content": "def login(): pass\n",
                "scanned": True,
                "skip_reason": None,
            }
        ],
        "run_ai": True,
    }
    actual_payload = default_payload if payload is None else payload

    job = Job(
        scan_id=scan.id,
        type=job_type,
        status=status,
        attempts=attempts,
        max_attempts=max_attempts,
        run_after=effective_now,
        payload=actual_payload,
    )
    session.add(job)
    session.commit()
    return scan, job


# ==============================================================================
# 1. Payload Validation Unit Tests
# ==============================================================================


class TestPayloadValidation:
    """Unit tests for validate_scan_payload."""

    def test_valid_payload_parses_successfully(self) -> None:
        raw = {
            "files": [
                {
                    "path": "src/api.py",
                    "content": "x = 42\n",
                    "scanned": True,
                    "skip_reason": None,
                },
                {
                    "path": "README.md",
                    "content": "# Docs\n",
                    "scanned": False,
                    "skip_reason": "unsupported_extension",
                },
            ],
            "run_ai": False,
        }
        parsed = validate_scan_payload(raw)
        assert len(parsed.files) == 2
        assert parsed.files[0].path == "src/api.py"
        assert parsed.files[0].content == "x = 42\n"
        assert parsed.files[0].scanned is True
        assert parsed.files[0].skip_reason is None
        assert parsed.files[1].path == "README.md"
        assert parsed.files[1].scanned is False
        assert parsed.files[1].skip_reason == "unsupported_extension"
        assert parsed.run_ai is False

    @pytest.mark.parametrize(
        ("invalid_payload", "error_match"),
        [
            (None, "Job payload must be a JSON object dictionary"),
            ("not-a-dict", "Job payload must be a JSON object dictionary"),
            ([], "Job payload must be a JSON object dictionary"),
            ({}, "missing required 'files' key"),
            ({"files": "not-a-list"}, "must be a list"),
            ({"files": []}, "cannot be empty"),
            ({"files": ["not-a-dict"]}, "must be a dictionary"),
            ({"files": [{"content": "pass"}]}, "missing required 'path'"),
            ({"files": [{"path": "a.py"}]}, "missing required 'content'"),
            ({"files": [{"path": "", "content": "pass"}]}, "invalid or empty path"),
            ({"files": [{"path": "   ", "content": "pass"}]}, "invalid or empty path"),
            ({"files": [{"path": 123, "content": "pass"}]}, "invalid or empty path"),
            ({"files": [{"path": "../etc/passwd", "content": "pass"}]}, "invalid path"),
            ({"files": [{"path": "/absolute/path.py", "content": "pass"}]}, "invalid path"),
            ({"files": [{"path": "a\x00b.py", "content": "pass"}]}, "invalid path"),
            ({"files": [{"path": "a.py", "content": 123}]}, "content for 'a.py' must be a string"),
            (
                {"files": [{"path": "a.py", "content": "x\x00=1"}]},
                "content for 'a.py' contains invalid NUL bytes",
            ),
            (
                {
                    "files": [
                        {"path": "src/main.py", "content": "a"},
                        {"path": "SRC/MAIN.PY", "content": "b"},
                    ]
                },
                "Duplicate file path '.*' after case-folding",
            ),
            (
                {"files": [{"path": "a.py", "content": "x", "scanned": "not-a-bool"}]},
                "'scanned' for 'a.py' must be a boolean",
            ),
            (
                {"files": [{"path": "a.py", "content": "x", "skip_reason": 123}]},
                "'skip_reason' for 'a.py' must be a string or None",
            ),
            (
                {"files": [{"path": "a.py", "content": "x"}], "run_ai": "yes"},
                "Job payload 'run_ai' must be a boolean",
            ),
        ],
    )
    def test_invalid_payloads_rejected(self, invalid_payload: Any, error_match: str) -> None:
        with pytest.raises(PayloadValidationError, match=error_match):
            validate_scan_payload(invalid_payload)

    def test_payload_max_files_boundary(self) -> None:
        """Exactly 20 files are accepted; 21 files are rejected."""
        valid_files = [
            {"path": f"src/mod_{i}.py", "content": "pass\n"} for i in range(MAX_FILES_COUNT)
        ]
        parsed = validate_scan_payload({"files": valid_files})
        assert len(parsed.files) == MAX_FILES_COUNT

        oversized_files = [
            {"path": f"src/mod_{i}.py", "content": "pass\n"} for i in range(MAX_FILES_COUNT + 1)
        ]
        with pytest.raises(PayloadValidationError, match=r"exceeds maximum of 20 files"):
            validate_scan_payload({"files": oversized_files})

    def test_payload_max_file_bytes_boundary(self) -> None:
        """Exactly 200 KiB (204,800 bytes) accepted; 204,801 bytes rejected."""
        exact_content = "a" * MAX_FILE_BYTES
        parsed = validate_scan_payload({"files": [{"path": "big.py", "content": exact_content}]})
        assert len(parsed.files[0].content) == MAX_FILE_BYTES

        too_big_content = "a" * (MAX_FILE_BYTES + 1)
        with pytest.raises(PayloadValidationError, match=r"exceeds maximum size of 204800 bytes"):
            validate_scan_payload({"files": [{"path": "too_big.py", "content": too_big_content}]})

    def test_payload_max_total_bytes_boundary(self) -> None:
        """Exactly 1 MiB (1,048,576 bytes) total accepted; 1,048,577 bytes rejected."""
        files = [{"path": f"src/part_{i}.py", "content": "x" * 100_000} for i in range(10)]
        files.append({"path": "src/remainder.py", "content": "x" * (MAX_TOTAL_BYTES - 1_000_000)})
        parsed = validate_scan_payload({"files": files})
        assert len(parsed.files) == 11

        oversized_files = [
            {"path": f"src/part_{i}.py", "content": "x" * 100_000} for i in range(10)
        ]
        oversized_files.append(
            {"path": "src/remainder.py", "content": "x" * (MAX_TOTAL_BYTES - 1_000_000 + 1)}
        )
        with pytest.raises(
            PayloadValidationError, match=r"exceeds maximum allowed size of 1048576 bytes"
        ):
            validate_scan_payload({"files": oversized_files})


# ==============================================================================
# 2. Scanner Interface and Isolation Tests
# ==============================================================================


class TestScannerInterface:
    """Unit tests for scanner interface boundary and isolation enforcement."""

    def test_default_scanner_engine_reports_isolation_blocker(self) -> None:
        """Default scanner refuses unisolated host execution and reports isolation blocker."""
        engine = DefaultScannerEngine(sandbox_available=False)
        payload = ScanJobPayload(
            files=[ScannedFile(path="test.py", content="print('hello')")],
            run_ai=True,
        )
        result = engine.scan(payload)
        assert result.status == ScanStatus.FAILED
        assert result.error_code == "ISOLATION_UNAVAILABLE"
        assert "sandbox isolation is not available" in (result.error_message or "")
        assert result.retryable is False

    def test_callable_scanner_engine_adapter(self) -> None:
        """CallableScannerEngine invokes wrapped function and returns result."""

        def mock_scan(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                counts={"total": len(p.files)},
            )

        engine = CallableScannerEngine(mock_scan)
        payload = ScanJobPayload(files=[ScannedFile(path="a.py", content="x=1")])
        result = engine.scan(payload)
        assert result.status == ScanStatus.SUCCEEDED
        assert result.counts == {"total": 1}


# ==============================================================================
# 3. Worker Job Dispatch & Outcome Routing Tests
# ==============================================================================


class TestWorkerDispatchAndExecution:
    """Integration tests for JobWorker dispatching and outcome routing."""

    def test_run_once_empty_queue_returns_false(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        """When no jobs are eligible, run_once returns False without errors."""
        worker = JobWorker(session_factory=session_factory, worker_id="w-empty")
        assert worker.run_once() is False

    def test_successful_scan_execution(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Successful scan updates job and scan to 'succeeded' and records metadata."""
        scan, job = _create_job_for_test(db_session, sample_project)

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                components={"semgrep": "passed", "gitleaks": "passed"},
                counts={"critical": 0, "high": 0, "medium": 0},
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-success",
            scanner=CallableScannerEngine(mock_scanner),
        )

        t0 = utc_now()
        processed = worker.run_once(now=t0)
        assert processed is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "succeeded"
        assert job.locked_by is None
        assert job.locked_until is None
        assert job.payload is None  # Sensitive source payload wiped on completion
        assert scan.status == "succeeded"
        assert scan.error_code is None
        assert scan.error_message is None
        assert scan.finished_at is not None
        assert scan.duration_ms is not None
        assert scan.components == {"semgrep": "passed", "gitleaks": "passed"}
        assert scan.counts == {"critical": 0, "high": 0, "medium": 0}

    def test_partial_scan_execution(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Partial scan marks scan as 'partial' and preserves component/error diagnostics."""
        scan, job = _create_job_for_test(db_session, sample_project)

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.PARTIAL,
                error_code="GITLEAKS_TIMEOUT",
                error_message="Gitleaks scan exceeded 60s timeout",
                components={"semgrep": "passed", "gitleaks": "timeout"},
                counts={"findings": 2},
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-partial",
            scanner=CallableScannerEngine(mock_scanner),
        )

        t0 = utc_now()
        assert worker.run_once(now=t0) is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "succeeded"  # Job execution cycle finished
        assert job.payload is None
        assert scan.status == "partial"  # Scan reflects partial outcome
        assert scan.error_code == "GITLEAKS_TIMEOUT"
        assert scan.error_message == "Gitleaks scan exceeded 60s timeout"
        assert scan.components == {"semgrep": "passed", "gitleaks": "timeout"}
        assert scan.counts == {"findings": 2}

    def test_retryable_scanner_failure_requeues_job(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Retryable failure requeues job with future run_after and preserves payload."""
        scan, job = _create_job_for_test(
            db_session,
            sample_project,
            attempts=0,
            max_attempts=3,
        )

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="TRANSIENT_TIMEOUT",
                error_message="Temporary runner timeout",
                retryable=True,
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-retry",
            scanner=CallableScannerEngine(mock_scanner),
        )

        t0 = utc_now()
        assert worker.run_once(now=t0) is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "queued"
        assert job.attempts == 1
        assert job.locked_by is None
        run_after_utc = (
            job.run_after if job.run_after.tzinfo is not None else job.run_after.replace(tzinfo=UTC)
        )
        assert run_after_utc > t0
        # Payload preserved for subsequent retry attempt
        assert job.payload is not None
        assert job.last_error == "Temporary runner timeout"

        # Scan reverted to queued
        assert scan.status == "queued"
        assert scan.error_code == "TRANSIENT_TIMEOUT"
        assert scan.error_message == "Temporary runner timeout"

    def test_terminal_scanner_failure_marks_job_and_scan_failed(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Non-retryable scanner failure immediately transitions job and scan to 'failed'."""
        scan, job = _create_job_for_test(db_session, sample_project)

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="RULE_SYNTAX_ERROR",
                error_message="Invalid Semgrep rule syntax detected",
                retryable=False,
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-fail",
            scanner=CallableScannerEngine(mock_scanner),
        )

        t0 = utc_now()
        assert worker.run_once(now=t0) is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "failed"
        assert job.locked_by is None
        assert job.payload is None  # Payload wiped on terminal failure
        assert job.last_error == "Invalid Semgrep rule syntax detected"

        assert scan.status == "failed"
        assert scan.error_code == "RULE_SYNTAX_ERROR"
        assert scan.error_message == "Invalid Semgrep rule syntax detected"
        assert scan.finished_at is not None

    def test_retryable_failure_with_max_attempts_exhausted_terminates(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Retryable failure terminates when attempts reach max_attempts."""
        # attempts=2, max_attempts=3 -> claim increments attempts to 3
        scan, job = _create_job_for_test(
            db_session,
            sample_project,
            attempts=2,
            max_attempts=3,
        )

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="TIMEOUT",
                error_message="Persistent timeout",
                retryable=True,
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-exhausted",
            scanner=CallableScannerEngine(mock_scanner),
        )

        t0 = utc_now()
        assert worker.run_once(now=t0) is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "failed"
        assert job.attempts == 3
        assert job.payload is None
        assert scan.status == "failed"
        assert scan.error_code == "TIMEOUT"

    def test_unsupported_job_type_rejected(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Jobs with unsupported type are permanently failed with UNSUPPORTED_JOB_TYPE."""
        scan, job = _create_job_for_test(
            db_session,
            sample_project,
            job_type="unknown_webhook",
        )

        worker = JobWorker(session_factory=session_factory, worker_id="w-type-check")
        assert worker.run_once() is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "failed"
        assert job.payload is None
        assert "Unsupported job type: 'unknown_webhook'" in (job.last_error or "")

        assert scan.status == "failed"
        assert scan.error_code == "UNSUPPORTED_JOB_TYPE"
        assert "Unsupported job type" in (scan.error_message or "")

    def test_malformed_payload_rejected_permanently(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Jobs with malformed payloads are permanently failed without retrying."""
        scan, job = _create_job_for_test(
            db_session,
            sample_project,
            payload={"files": [{"path": "../../etc/shadow", "content": "secret"}]},
        )

        worker = JobWorker(session_factory=session_factory, worker_id="w-payload-check")
        assert worker.run_once() is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "failed"
        assert job.payload is None
        assert "Malformed job payload" in (job.last_error or "")

        assert scan.status == "failed"
        assert scan.error_code == "MALFORMED_PAYLOAD"
        assert "Malformed job payload" in (scan.error_message or "")

    def test_scanner_exception_handled_as_execution_error(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Unexpected scanner exception fails the job with SCANNER_EXECUTION_ERROR."""
        scan, job = _create_job_for_test(db_session, sample_project)

        def crashing_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            raise RuntimeError("Scanner process abruptly died with SIGSEGV")

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-crash",
            scanner=CallableScannerEngine(crashing_scanner),
        )

        assert worker.run_once() is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "failed"
        assert job.payload is None
        assert "Scanner execution failed" in (job.last_error or "")

        assert scan.status == "failed"
        assert scan.error_code == "SCANNER_EXECUTION_ERROR"

    def test_default_scanner_engine_marks_job_failed_due_to_isolation(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """DefaultScannerEngine without sandbox marks scan failed with ISOLATION_UNAVAILABLE."""
        scan, job = _create_job_for_test(db_session, sample_project)

        # Use default scanner engine (no sandbox available)
        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-default-engine",
        )

        assert worker.run_once() is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "failed"
        assert scan.status == "failed"
        assert scan.error_code == "ISOLATION_UNAVAILABLE"
        assert "sandbox isolation is not available" in (scan.error_message or "")

    def test_secret_sanitization_in_failure_messages(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Secrets appearing in scanner failure messages are redacted before database storage."""
        scan, job = _create_job_for_test(db_session, sample_project)

        leak_msg = (
            "Scanner crashed while parsing token "
            "ghp_1234567890abcdef1234567890abcdef123456 and "
            "sk-ant-api03-abcdef1234567890abcdef123456 in file"
        )

        def leaking_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="PARSE_ERR",
                error_message=leak_msg,
                retryable=False,
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-secret-check",
            scanner=CallableScannerEngine(leaking_scanner),
        )

        assert worker.run_once() is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert "ghp_" not in (job.last_error or "")
        assert "sk-ant-" not in (job.last_error or "")
        assert "[REDACTED_SECRET]" in (job.last_error or "")
        assert "ghp_" not in (scan.error_message or "")
        assert "sk-ant-" not in (scan.error_message or "")
        assert "[REDACTED_SECRET]" in (scan.error_message or "")

    def test_database_connection_released_before_scanner_execution(
        self,
        test_engine: Engine,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Database connection must be closed/checked-in before scanner execution starts."""
        _scan, _job = _create_job_for_test(db_session, sample_project)

        pool_events = {"checkout": 0, "checkin": 0}

        def on_checkout(*_: Any) -> None:
            pool_events["checkout"] += 1

        def on_checkin(*_: Any) -> None:
            pool_events["checkin"] += 1

        event.listen(test_engine, "checkout", on_checkout)
        event.listen(test_engine, "checkin", on_checkin)

        scanner_invoked = False
        active_conns_during_scan = -1

        def probe_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            nonlocal scanner_invoked, active_conns_during_scan
            scanner_invoked = True
            # Active connections checked out by this thread:
            active_conns_during_scan = pool_events["checkout"] - pool_events["checkin"]

            # Independent session query should run freely without session contention
            with session_factory() as independent_session:
                res = independent_session.scalar(select(1))
                assert res == 1

            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        try:
            worker = JobWorker(
                session_factory=session_factory,
                worker_id="w-conn-release",
                scanner=CallableScannerEngine(probe_scanner),
            )
            processed = worker.run_once()
            assert processed is True
            assert scanner_invoked is True
            # Proves zero connections were held during the scan
            assert active_conns_during_scan == 0
            assert pool_events["checkout"] > 0
        finally:
            event.remove(test_engine, "checkout", on_checkout)
            event.remove(test_engine, "checkin", on_checkin)

    def test_scan_outlasting_lease_cannot_complete_with_stale_timestamp(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A scan that exceeds its lease duration is rejected on completion and not marked succeeded."""
        scan, job = _create_job_for_test(db_session, sample_project)

        def slow_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-slow-lease",
            lease_duration_sec=30,
            scanner=CallableScannerEngine(slow_scanner),
        )

        t0 = utc_now()
        # Scan finishes 35 seconds later (past the 30-second lease window)
        t_finish = t0 + timedelta(seconds=35)

        with pytest.raises(JobOwnershipError, match=r"Lease for job '.*' expired"):
            worker.run_once(now=t0, completion_now=t_finish)

        db_session.refresh(job)
        db_session.refresh(scan)

        # Job and scan must NOT be marked succeeded
        assert job.status != "succeeded"
        assert scan.status != "succeeded"
        # Remains in running state with expired lease until reaped
        assert job.status == "running"
        assert scan.status == "running"

    def test_completion_and_duration_metadata_use_completion_time(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Completion timestamp and duration_ms accurately reflect the finish time."""
        scan, job = _create_job_for_test(db_session, sample_project)

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-timing",
            lease_duration_sec=120,
            scanner=CallableScannerEngine(mock_scanner),
        )

        t0 = utc_now()
        t_finish = t0 + timedelta(seconds=15)

        assert worker.run_once(now=t0, completion_now=t_finish) is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "succeeded"
        assert scan.status == "succeeded"
        assert scan.finished_at is not None
        # Finished at matches the completion time
        finished_utc = (
            scan.finished_at
            if scan.finished_at.tzinfo is not None
            else scan.finished_at.replace(tzinfo=UTC)
        )
        assert abs((finished_utc - t_finish).total_seconds()) < 1.0
        # Duration calculates from started_at to completion_now (15,000 ms)
        assert scan.duration_ms == 15000

    def test_oversized_payload_fails_terminally_as_malformed(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Oversized file list (21 files) terminally fails as MALFORMED_PAYLOAD with payload erased."""
        oversized_files = [
            {"path": f"src/mod_{i}.py", "content": "pass\n"} for i in range(MAX_FILES_COUNT + 1)
        ]
        scan, job = _create_job_for_test(
            db_session,
            sample_project,
            payload={"files": oversized_files},
        )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-oversize",
        )

        assert worker.run_once() is True

        db_session.refresh(job)
        db_session.refresh(scan)

        assert job.status == "failed"
        assert job.payload is None  # Wiped on terminal failure
        assert "exceeds maximum of 20 files" in (job.last_error or "")

        assert scan.status == "failed"
        assert scan.error_code == "MALFORMED_PAYLOAD"
        assert "exceeds maximum of 20 files" in (scan.error_message or "")


# ==============================================================================
# 4. Graceful Shutdown & Polling Loop Tests
# ==============================================================================


class TestWorkerLifecycleAndShutdown:
    """Unit tests for worker loop control, bounded runs, and graceful shutdown."""

    def test_worker_stop_sets_is_running_false(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Calling stop() transitions is_running from True to False."""
        worker = JobWorker(session_factory=session_factory, worker_id="w-stop")
        assert worker.is_running is True
        worker.stop()
        assert worker.is_running is False

    def test_worker_bounded_iterations_exits_loop(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Passing max_iterations limits the polling loop execution count."""
        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-iter",
            poll_interval_sec=0.01,
        )
        # Empty queue, 3 iterations
        processed = worker.run(max_iterations=3)
        assert processed == 0

    def test_worker_graceful_shutdown_from_separate_thread(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Worker running in a background thread stops gracefully when stop() is called."""
        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-thread",
            poll_interval_sec=0.05,
        )

        worker_thread = threading.Thread(target=worker.run, daemon=True)
        worker_thread.start()

        # Let the worker poll once or twice on an empty queue
        time.sleep(0.1)
        assert worker_thread.is_alive()

        # Signal shutdown and join
        worker.stop()
        worker_thread.join(timeout=2.0)
        assert not worker_thread.is_alive()
