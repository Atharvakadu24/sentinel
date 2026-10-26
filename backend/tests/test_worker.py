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
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import Job, Project, Scan, User
from app.services.job_service import (
    JobInvalidStateError,
    JobOwnershipError,
    JobRenewalError,
    _normalize_datetime,
    claim_next_job,
    complete_job,
    reap_expired_jobs,
    renew_job_lease,
)
from app.services.scan_service import MAX_FILE_BYTES, MAX_FILES_COUNT, MAX_TOTAL_BYTES
from app.worker.payload import PayloadValidationError, validate_scan_payload
from app.worker.runner import JobHeartbeat, JobWorker
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

        claimed = worker.run_once(now=t0, completion_now=t_finish)
        assert claimed is True

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


class TestWorkerReaperIntegration:
    """Integration tests for periodic and explicit reaper execution in JobWorker."""

    def test_worker_reap_expired_jobs_explicit(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Worker can explicitly sweep for and recover expired jobs in a dedicated session."""
        t0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC)
        scan, job = _create_job_for_test(db_session, sample_project, run_after=t0)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-reaper",
            lease_duration_sec=30,
        )
        # Claim job under a crashed worker
        claimed = claim_next_job(db_session, worker_id="w-crashed", lease_duration_sec=30, now=t0)
        assert claimed is not None

        # Lease expires at t0 + 30s; worker reaps at t0 + 35s
        t_reap = t0 + timedelta(seconds=35)
        reaped = worker.reap_expired_jobs(now=t_reap)

        assert len(reaped) == 1
        assert reaped[0].id == job.id

        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status == "queued"
        assert job.locked_by is None
        assert scan.status == "queued"
        assert scan.error_code == "LEASE_EXPIRED"

    def test_worker_run_once_with_reap_true_recovers_job(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """run_once(reap=True) reaps expired jobs before claiming work."""
        t0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC)
        scan, job = _create_job_for_test(db_session, sample_project, run_after=t0)

        claimed = claim_next_job(
            db_session, worker_id="w-stale-prev", lease_duration_sec=30, now=t0
        )
        assert claimed is not None

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-new",
            lease_duration_sec=60,
        )

        t_now = t0 + timedelta(seconds=45)
        worker.run_once(now=t_now, reap=True)

        db_session.refresh(job)
        db_session.refresh(scan)
        # The job was reaped to queued
        assert job.status == "queued"
        assert job.locked_by is None
        assert scan.status == "queued"
        assert scan.error_code == "LEASE_EXPIRED"

    def test_worker_polling_loop_triggers_periodic_reaping(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """JobWorker.run() triggers reaping during polling loop execution."""
        t0 = utc_now() - timedelta(seconds=100)
        scan, job = _create_job_for_test(db_session, sample_project, run_after=t0)

        # Job claimed in the past whose lease is well expired
        claimed = claim_next_job(db_session, worker_id="w-abandoned", lease_duration_sec=30, now=t0)
        assert claimed is not None

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-loop-reaper",
            poll_interval_sec=0.01,
            reaper_interval_sec=0.0,  # Forces reaping on loop cycle
        )

        # Run worker for 1 iteration
        worker.run(max_iterations=1)

        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status == "queued"
        assert job.locked_by is None
        assert scan.status == "queued"
        assert scan.error_code == "LEASE_EXPIRED"

    def test_worker_reaper_catches_and_logs_exception_safely(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Reaper database errors do not crash or raise out of worker.reap_expired_jobs."""
        worker = JobWorker(session_factory=session_factory, worker_id="w-safe-reap")

        with patch(
            "app.worker.runner.reap_expired_jobs", side_effect=RuntimeError("Simulated DB error")
        ):
            result = worker.reap_expired_jobs()
            assert result == []

    def test_stale_worker_process_job_fails_gracefully_when_reaped_mid_flight(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When a job is reaped while scanner is running, worker's completion is rejected and logs warning."""
        scan, job = _create_job_for_test(db_session, sample_project)

        def slow_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            # During scan execution, reaper sweeps and requeues the job
            with session_factory() as s:
                reap_expired_jobs(s, retry_delay_sec=10, now=utc_now() + timedelta(seconds=100))
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-slow-runner",
            lease_duration_sec=10,
            scanner=CallableScannerEngine(slow_scanner),
        )

        t0 = utc_now()
        # Worker claims job
        claim_next_job(db_session, worker_id="w-slow-runner", lease_duration_sec=10, now=t0)

        # Worker processes job; mid-flight scanner triggers reap
        # Completion is safely rejected and returns None without marking job succeeded
        outcome = worker.process_job(
            job_id=job.id, now=t0, completion_now=t0 + timedelta(seconds=20)
        )
        assert outcome is None

        db_session.refresh(job)
        db_session.refresh(scan)
        # Job must NOT be marked succeeded; remains queued from reaper
        assert job.status == "queued"
        assert scan.status == "queued"


class TestWorkerHeartbeatIntegration:
    """Integration tests for worker heartbeat, periodic lease renewal, and outcome safety."""

    def test_scan_outlasting_original_lease_succeeds_with_heartbeat(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A scan running longer than its claim lease succeeds because heartbeat renews it."""
        scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        renewed_confirmed = threading.Event()
        real_renew = renew_job_lease

        def notifying_renew(session: Session, **kwargs: Any) -> Job:
            res = real_renew(session, **kwargs)
            renewed_confirmed.set()
            return res

        def slow_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            assert renewed_confirmed.wait(timeout=2.0), (
                "Heartbeat did not advance locked_until during scan"
            )
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                components={"semgrep": "passed", "gitleaks": "passed"},
                counts={"critical": 0, "high": 0, "medium": 0},
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-heartbeat-success",
            lease_duration_sec=2,
            heartbeat_interval_sec=0.04,
            scanner=CallableScannerEngine(slow_scanner),
        )

        claimed = claim_next_job(
            db_session,
            worker_id="w-heartbeat-success",
            lease_duration_sec=2,
            now=t0,
        )
        assert claimed is not None

        with patch("app.worker.runner.renew_job_lease", side_effect=notifying_renew):
            worker.process_job(job_id=job.id, now=t0)

        assert renewed_confirmed.is_set(), "Heartbeat did not advance locked_until during scan"

        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status == "succeeded"
        assert scan.status == "succeeded"
        assert job.locked_by is None

    def test_heartbeat_thread_exits_on_scan_success_and_failure(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Background heartbeat thread terminates promptly on both scanner success and crash."""
        # 1. Success case
        _scan1, job1 = _create_job_for_test(db_session, sample_project)
        thread_holder_success: list[threading.Thread] = []

        def success_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            for t in threading.enumerate():
                if t.name.startswith("heartbeat-"):
                    thread_holder_success.append(t)
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker1 = JobWorker(
            session_factory=session_factory,
            worker_id="w-exit-succ",
            lease_duration_sec=5,
            heartbeat_interval_sec=0.05,
            scanner=CallableScannerEngine(success_scanner),
        )
        claim_next_job(db_session, worker_id="w-exit-succ", lease_duration_sec=5)
        worker1.process_job(job_id=job1.id)

        assert len(thread_holder_success) >= 1
        assert not thread_holder_success[0].is_alive(), (
            "Heartbeat thread did not terminate on success"
        )

        # 2. Crash/failure case
        _scan2, job2 = _create_job_for_test(db_session, sample_project)
        thread_holder_fail: list[threading.Thread] = []

        def failing_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            for t in threading.enumerate():
                if t.name.startswith("heartbeat-"):
                    thread_holder_fail.append(t)
            raise RuntimeError("Scanner execution crashed")

        worker2 = JobWorker(
            session_factory=session_factory,
            worker_id="w-exit-fail",
            lease_duration_sec=5,
            heartbeat_interval_sec=0.05,
            scanner=CallableScannerEngine(failing_scanner),
        )
        claim_next_job(db_session, worker_id="w-exit-fail", lease_duration_sec=5)
        worker2.process_job(job_id=job2.id)

        assert len(thread_holder_fail) >= 1
        assert not thread_holder_fail[0].is_alive(), (
            "Heartbeat thread did not terminate on scanner crash"
        )

        db_session.refresh(job2)
        assert job2.status == "failed"

    def test_lost_ownership_during_scan_discards_stale_results(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When ownership is lost mid-scan, results are discarded without complete_job or fail_job."""
        scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-stale", lease_duration_sec=5, now=t0)

        ownership_detected = threading.Event()
        real_renew = renew_job_lease

        def wrapped_renew(session: Session, **kwargs: Any) -> Job:
            try:
                return real_renew(session, **kwargs)
            except JobOwnershipError:
                ownership_detected.set()
                raise

        def stealing_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            # Another worker or admin takes ownership while scan is running
            with session_factory() as s:
                j = s.get(Job, job.id)
                assert j is not None
                j.locked_by = "w-thief"
                s.commit()
            assert ownership_detected.wait(timeout=2.0), (
                "Heartbeat did not detect ownership change in time"
            )
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                components={"semgrep": "passed"},
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-stale",
            lease_duration_sec=5,
            heartbeat_interval_sec=0.03,
            scanner=CallableScannerEngine(stealing_scanner),
        )

        with patch("app.worker.runner.renew_job_lease", side_effect=wrapped_renew):
            outcome = worker.process_job(job_id=job.id, now=t0)

        assert outcome is None, "Process job should return None when ownership is lost"

        # Verify job was NOT overwritten to succeeded
        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status == "running"
        assert job.locked_by == "w-thief"
        assert scan.status != "succeeded"

    def test_transient_renewal_database_error_is_resilient(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Transient database errors during heartbeat do not terminate heartbeat prematurely."""
        _scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-transient", lease_duration_sec=5, now=t0)

        second_call_done = threading.Event()
        call_count = 0
        real_renew = renew_job_lease

        def flaky_renew(session: Session, **kwargs: Any) -> Job:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise JobRenewalError("Transient operational connection drop")
            res = real_renew(session, **kwargs)
            second_call_done.set()
            return res

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            assert second_call_done.wait(timeout=2.0), (
                "Heartbeat did not complete second renewal in time"
            )
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-transient",
            lease_duration_sec=5,
            heartbeat_interval_sec=0.03,
            scanner=CallableScannerEngine(mock_scanner),
        )

        with patch("app.worker.runner.renew_job_lease", side_effect=flaky_renew):
            outcome = worker.process_job(job_id=job.id, now=t0)

        assert outcome is not None
        assert call_count >= 2
        db_session.refresh(job)
        assert job.status == "succeeded"

    def test_reaper_race_never_overwrites_reaped_job_state(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Reaped job state in queue is preserved and not overwritten by stale scanner output."""
        scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-raced", lease_duration_sec=5, now=t0)

        reaped_detected = threading.Event()
        real_renew = renew_job_lease

        def wrapped_renew(session: Session, **kwargs: Any) -> Job:
            try:
                return real_renew(session, **kwargs)
            except JobInvalidStateError:
                reaped_detected.set()
                raise

        def reaped_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            # During scan, reaper sweeps and resets job to queued
            with session_factory() as s:
                reap_expired_jobs(s, retry_delay_sec=10, now=t0 + timedelta(seconds=100))
            assert reaped_detected.wait(timeout=2.0), (
                "Heartbeat did not detect reaped job state in time"
            )
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-raced",
            lease_duration_sec=5,
            heartbeat_interval_sec=0.03,
            scanner=CallableScannerEngine(reaped_scanner),
        )

        with patch("app.worker.runner.renew_job_lease", side_effect=wrapped_renew):
            outcome = worker.process_job(job_id=job.id, now=t0)

        assert outcome is None

        db_session.refresh(job)
        db_session.refresh(scan)
        # Reaper set it to queued; worker must not have completed or failed it
        assert job.status == "queued"
        assert scan.status == "queued"

    def test_uncertain_heartbeat_status_discards_findings_for_safety(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When renewals fail continuously and lease expires, findings are discarded safely."""
        _scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-uncertain", lease_duration_sec=2, now=t0)

        renew_attempted = threading.Event()

        def always_fail_renew(session: Session, **kwargs: Any) -> Job:
            renew_attempted.set()
            raise JobRenewalError("Continuous network partitioned error")

        def mock_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            assert renew_attempted.wait(timeout=2.0), "Heartbeat renewal was not attempted in time"
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-uncertain",
            lease_duration_sec=2,
            heartbeat_interval_sec=0.03,
            scanner=CallableScannerEngine(mock_scanner),
        )

        # Finished time is past the 2-second lease
        t_finish = t0 + timedelta(seconds=10)
        with patch("app.worker.runner.renew_job_lease", side_effect=always_fail_renew):
            outcome = worker.process_job(job_id=job.id, now=t0, completion_now=t_finish)

        assert outcome is None, "Findings must be discarded when lease status is uncertain"
        db_session.refresh(job)
        assert job.status == "running"  # Not marked succeeded

    def test_blocked_renewal_at_shutdown_fails_closed_and_prevents_finalization(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When renewal is blocked in DB during shutdown, finalization is prevented and worker fails closed."""
        scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-blocked-hb", lease_duration_sec=10, now=t0)

        renewal_started = threading.Event()
        unblock_renewal = threading.Event()
        real_renew = renew_job_lease

        def blocking_renew(session: Session, **kwargs: Any) -> Job:
            renewal_started.set()
            unblock_renewal.wait(timeout=5.0)
            return real_renew(session, **kwargs)

        def fast_scanner(p: ScanJobPayload) -> ScanExecutionResult:
            assert renewal_started.wait(timeout=2.0), "Renewal did not start in time"
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-blocked-hb",
            lease_duration_sec=10,
            heartbeat_interval_sec=0.01,
            heartbeat_shutdown_timeout_sec=0.05,
            scanner=CallableScannerEngine(fast_scanner),
        )

        try:
            with patch("app.worker.runner.renew_job_lease", side_effect=blocking_renew):
                outcome = worker.process_job(job_id=job.id, now=t0)
        finally:
            unblock_renewal.set()

        # Finalization must NOT be executed: outcome is None, job is NOT succeeded
        assert outcome is None
        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status != "succeeded"
        assert scan.status != "succeeded"

    def test_renewal_returning_after_shutdown_signal_aborts_commit(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A renewal returning from DB after stop event is set rolls back and does not extend lease."""
        _scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-race-commit", lease_duration_sec=10, now=t0)

        db_session.refresh(job)
        initial_locked_until = job.locked_until

        hb = JobHeartbeat(
            session_factory=session_factory,
            job_id=job.id,
            worker_id="w-race-commit",
            interval_sec=0.01,
            lease_extension_sec=60,
            initial_locked_until=initial_locked_until,
            shutdown_timeout_sec=2.0,
        )

        query_executed = threading.Event()
        shutdown_signaled = threading.Event()
        real_renew = renew_job_lease

        def intercepted_renew(session: Session, **kwargs: Any) -> Job:
            result = real_renew(session, **kwargs)
            query_executed.set()
            assert shutdown_signaled.wait(timeout=2.0), "Stop was not signaled in time"
            return result

        with patch("app.worker.runner.renew_job_lease", side_effect=intercepted_renew):
            hb.start()
            assert query_executed.wait(timeout=2.0), "Renewal query did not execute"
            hb._stop_event.set()
            shutdown_signaled.set()
            hb.stop(timeout=2.0)

        # Confirm lease in database was NOT extended to t0 + 60s because commit was aborted
        db_session.refresh(job)
        assert job.locked_until == initial_locked_until
        assert hb.successful_renewals == 0
        assert hb.last_known_locked_until == _normalize_datetime(initial_locked_until)

    def test_shutdown_attempt_during_commit_cannot_interleave_and_commit_wins(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When shutdown attempts to begin while commit is in flight, commit completes first and lease is extended."""
        _scan, job = _create_job_for_test(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-commit-wins", lease_duration_sec=10, now=t0)

        db_session.refresh(job)
        initial_locked_until = job.locked_until

        commit_in_flight = threading.Event()
        release_commit = threading.Event()
        stop_attempt_started = threading.Event()
        stop_completed = threading.Event()

        original_commit = Session.commit

        def intercepted_commit(session_self: Session) -> None:
            if not commit_in_flight.is_set():
                commit_in_flight.set()
                assert stop_attempt_started.wait(timeout=2.0), "Stop attempt was not initiated"
                assert release_commit.wait(timeout=2.0), "Release commit was not signaled"
            original_commit(session_self)

        hb = JobHeartbeat(
            session_factory=session_factory,
            job_id=job.id,
            worker_id="w-commit-wins",
            interval_sec=0.01,
            lease_extension_sec=60,
            initial_locked_until=initial_locked_until,
            shutdown_timeout_sec=2.0,
        )

        with patch.object(Session, "commit", side_effect=intercepted_commit, autospec=True):
            hb.start()
            # 1. Wait until heartbeat thread reaches the commit critical section
            assert commit_in_flight.wait(timeout=2.0), "Heartbeat did not enter commit in time"

            # 2. In a background thread, attempt to stop the heartbeat while commit holds _lock
            def do_stop() -> None:
                stop_attempt_started.set()
                hb.stop(timeout=2.0)
                stop_completed.set()

            stop_thread = threading.Thread(target=do_stop, daemon=True)
            stop_thread.start()

            assert stop_attempt_started.wait(timeout=2.0), "Stop thread did not start"
            # While commit holds _lock, stop cannot acquire _lock to establish shutdown boundary
            assert hb._lock.locked(), "Heartbeat lock should be held by commit critical section"

            # 3. Release commit critical section so commit finishes and releases _lock
            release_commit.set()

            # 4. Stop thread must complete cleanly
            assert stop_completed.wait(timeout=2.0), "Heartbeat stop did not complete cleanly"
            stop_thread.join(timeout=1.0)

        # 5. Assert database effects: lease WAS extended by commit winning the race
        db_session.refresh(job)
        assert job.locked_until is not None
        assert initial_locked_until is not None
        assert job.locked_until > initial_locked_until
        assert hb.successful_renewals == 1
        assert not hb.is_alive
        assert hb.clean_shutdown is True

        # 6. Verify worker finalization: job completes cleanly and clears lease
        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w-commit-wins",
            auto_commit=True,
        )
        assert completed.status == "succeeded"
        assert completed.locked_by is None
        assert completed.locked_until is None

    def test_lease_uncertainty_boundary_conditions(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        """Deterministic boundary checks for JobHeartbeat.is_lease_uncertain()."""
        t0 = utc_now()
        locked_until = t0 + timedelta(seconds=10)

        hb = JobHeartbeat(
            session_factory=session_factory,
            job_id=uuid.uuid4(),
            worker_id="w-boundary",
            interval_sec=1.0,
            lease_extension_sec=30,
            initial_locked_until=locked_until,
        )

        # 1. Check time before locked_until: valid
        assert not hb.is_lease_uncertain(t0 + timedelta(seconds=5))

        # 2. Check time exactly at locked_until: valid (boundary condition: locked_until == now is valid)
        assert not hb.is_lease_uncertain(locked_until)

        # 3. Check time 1 microsecond after locked_until with ZERO failures: UNCERTAIN!
        assert hb.is_lease_uncertain(locked_until + timedelta(microseconds=1))

        # 4. Unknown/missing last-known lease: UNCERTAIN!
        hb_unknown = JobHeartbeat(
            session_factory=session_factory,
            job_id=uuid.uuid4(),
            worker_id="w-boundary",
            interval_sec=1.0,
            lease_extension_sec=30,
            initial_locked_until=None,
        )
        assert hb_unknown.is_lease_uncertain(t0)

        # 5. Ownership lost: UNCERTAIN even before locked_until
        hb.lost_ownership = True
        assert hb.is_lease_uncertain(t0 + timedelta(seconds=5))

        # 6. Transient failures present, but lease has not expired yet: not uncertain
        hb_transient = JobHeartbeat(
            session_factory=session_factory,
            job_id=uuid.uuid4(),
            worker_id="w-boundary",
            interval_sec=1.0,
            lease_extension_sec=30,
            initial_locked_until=locked_until,
        )
        hb_transient.consecutive_transient_failures = 3
        assert not hb_transient.is_lease_uncertain(t0 + timedelta(seconds=5))
        # Once time passes locked_until, it becomes uncertain
        assert hb_transient.is_lease_uncertain(locked_until + timedelta(seconds=1))

    def test_long_running_scan_controlled_time_without_freezing_finalization(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Controlled start time allows long duration without freezing finalization timestamp."""
        t_start = utc_now() - timedelta(seconds=10)
        scan, job = _create_job_for_test(db_session, sample_project, run_after=t_start)
        claim_next_job(
            db_session,
            worker_id="w-long-controlled",
            lease_duration_sec=30,
            now=t_start,
        )

        renew_done = threading.Event()
        real_renew = renew_job_lease

        def notifying_renew(session: Session, **kwargs: Any) -> Job:
            res = real_renew(session, **kwargs)
            renew_done.set()
            return res

        def simulated_long_scan(p: ScanJobPayload) -> ScanExecutionResult:
            assert renew_done.wait(timeout=2.0), "Heartbeat did not renew lease in time"
            return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-long-controlled",
            lease_duration_sec=30,
            heartbeat_interval_sec=0.03,
            scanner=CallableScannerEngine(simulated_long_scan),
        )

        with patch("app.worker.runner.renew_job_lease", side_effect=notifying_renew):
            outcome = worker.process_job(job_id=job.id, now=t_start)

        assert outcome is not None
        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status == "succeeded"
        assert scan.status == "succeeded"
        assert scan.duration_ms is not None
        assert scan.duration_ms >= 10000

    def test_invalid_worker_heartbeat_and_lease_configuration(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        """JobWorker rejects invalid lease durations and heartbeat intervals."""
        # Heartbeat >= Lease
        with pytest.raises(
            ValueError,
            match=r"heartbeat_interval_sec.*must be strictly less than lease_duration_sec",
        ):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=60,
                heartbeat_interval_sec=60,
            )
        with pytest.raises(
            ValueError,
            match=r"heartbeat_interval_sec.*must be strictly less than lease_duration_sec",
        ):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=60,
                heartbeat_interval_sec=80,
            )

        # Zero or negative
        with pytest.raises(ValueError, match="heartbeat_interval_sec must be a positive number"):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=60,
                heartbeat_interval_sec=0,
            )
        with pytest.raises(ValueError, match="heartbeat_interval_sec must be a positive number"):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=60,
                heartbeat_interval_sec=-5,
            )
        with pytest.raises(ValueError, match="lease_duration_sec must be a positive integer"):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=0,
                heartbeat_interval_sec=15,
            )
        with pytest.raises(ValueError, match="lease_duration_sec must be a positive integer"):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=-10,
                heartbeat_interval_sec=15,
            )

        # Booleans
        with pytest.raises(ValueError, match="heartbeat_interval_sec must be a positive number"):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=60,
                heartbeat_interval_sec=True,
            )
        with pytest.raises(ValueError, match="lease_duration_sec must be a positive integer"):
            JobWorker(
                session_factory=session_factory,
                lease_duration_sec=False,
                heartbeat_interval_sec=15,
            )

        # Valid custom configuration
        valid_worker = JobWorker(
            session_factory=session_factory,
            lease_duration_sec=120,
            heartbeat_interval_sec=30.0,
        )
        assert valid_worker.lease_duration_sec == 120
        assert valid_worker.heartbeat_interval_sec == 30.0

    def test_job_heartbeat_context_manager_and_uncertainty_logic(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        """JobHeartbeat context manager starts and stops thread and calculates uncertainty."""
        job_id = uuid.uuid4()
        now = utc_now()
        hb = JobHeartbeat(
            session_factory=session_factory,
            job_id=job_id,
            worker_id="w-hb-unit",
            interval_sec=0.1,
            lease_extension_sec=30,
            initial_locked_until=now + timedelta(seconds=10),
        )
        assert not hb.is_alive
        with hb:
            assert hb.is_alive
        assert not hb.is_alive

        # Without failures, is_lease_uncertain is False
        assert not hb.is_lease_uncertain(now)

        # With transient failures and lapsed lease, is_lease_uncertain is True
        hb.consecutive_transient_failures = 1
        assert hb.is_lease_uncertain(now + timedelta(seconds=20))
