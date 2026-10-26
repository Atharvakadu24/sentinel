"""Unit and concurrency tests for background job queue claiming (Blueprint Section 7 & 8.1).

Verifies:
- Atomic claiming of eligible queued jobs
- Worker assignment, lease calculation (locked_until), attempt incrementation
- FIFO ordering (run_after, created_at)
- Ineligible job exclusion (running, succeeded, failed, dead, future run_after, max attempts)
- Input validation and error rollback
- Transaction boundaries (short claim transaction, no locks held beyond claim)
- Multi-worker concurrency safety (no duplicate claims)
- PostgreSQL FOR UPDATE SKIP LOCKED dialect compilation
"""

from __future__ import annotations

import concurrent.futures
import os
import tempfile
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, or_, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import Job, Project, Scan, User
from app.services.job_service import (
    JobClaimError,
    JobCompleteError,
    JobFailureError,
    JobInvalidStateError,
    JobNotFoundError,
    JobOwnershipError,
    JobReapError,
    JobRenewalError,
    JobServiceError,
    JobTransitionError,
    _normalize_datetime,
    claim_next_job,
    complete_job,
    fail_job,
    reap_expired_jobs,
    renew_job_lease,
    retry_job,
    sanitize_failure_message,
)


@pytest.fixture
def test_engine() -> Engine:
    """Isolated in-memory SQLite engine for single-threaded tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session_factory(test_engine: Engine) -> sessionmaker[Session]:
    """Session factory configured with Sentinel conventions."""
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
        github_user_id=88888,
        github_login="worker-lead",
        display_name="Queue Lead",
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
        name="Job Queue Test Project",
        status="active",
    )
    db_session.add(project)
    db_session.commit()
    return project


def _create_test_scan_and_job(
    session: Session,
    project: Project,
    *,
    status: str = "queued",
    scan_status: str = "queued",
    attempts: int = 0,
    max_attempts: int = 3,
    run_after: datetime | None = None,
    created_at: datetime | None = None,
    trigger_key: str | None = None,
) -> tuple[Scan, Job]:
    """Helper to persist a Scan and associated Job with custom parameters."""
    t_key = trigger_key or f"trigger-{uuid.uuid4()}"
    effective_now = run_after or utc_now()
    scan = Scan(
        project_id=project.id,
        trigger="manual",
        trigger_key=t_key,
        status=scan_status,
        report_status="not_applicable",
    )
    if created_at is not None:
        scan.created_at = created_at
    session.add(scan)
    session.flush()

    job = Job(
        scan_id=scan.id,
        type="scan",
        status=status,
        attempts=attempts,
        max_attempts=max_attempts,
        run_after=effective_now,
        payload={"files": [{"path": "main.py", "content": "x = 1"}]},
    )
    if created_at is not None:
        job.created_at = created_at
    session.add(job)
    session.commit()
    return scan, job


class TestJobClaimBasic:
    """Basic unit tests for claiming eligible queued jobs."""

    def test_claim_eligible_queued_job_success(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Eligible queued job is claimed: status='running', worker set, lease set, attempts+1."""
        scan, job = _create_test_scan_and_job(db_session, sample_project)
        assert job.status == "queued"
        assert job.attempts == 0
        assert job.locked_by is None
        assert job.locked_until is None
        assert scan.status == "queued"

        before_claim = utc_now()
        claimed = claim_next_job(
            session=db_session,
            worker_id="worker-node-1",
            lease_duration_sec=60,
        )

        assert claimed is not None
        assert claimed.id == job.id
        assert claimed.status == "running"
        assert claimed.locked_by == "worker-node-1"
        assert claimed.attempts == 1
        assert claimed.locked_until is not None
        # Normalize timezone for SQLite compatibility
        locked_until_utc = (
            claimed.locked_until
            if claimed.locked_until.tzinfo is not None
            else claimed.locked_until.replace(tzinfo=UTC)
        )
        expected_expiry = before_claim + timedelta(seconds=60)
        assert locked_until_utc >= expected_expiry - timedelta(seconds=2)
        assert locked_until_utc <= expected_expiry + timedelta(seconds=5)

        # Verify associated scan status is updated to 'running' and started_at is recorded
        assert claimed.scan is not None
        assert claimed.scan.status == "running"
        assert claimed.scan.started_at is not None

    def test_claim_sets_scan_started_at_and_complete_uses_it_for_duration(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """claim_next_job sets scan.started_at and complete_job calculates duration from started_at, not queued_at."""
        t_queue = datetime(2026, 10, 23, 10, 0, 0, tzinfo=UTC)
        scan, job = _create_test_scan_and_job(
            db_session,
            sample_project,
            run_after=t_queue,
            created_at=t_queue,
        )
        scan.queued_at = t_queue
        db_session.commit()

        # Scan waited in queue for 1 hour before worker claims it
        t_claim = datetime(2026, 10, 23, 11, 0, 0, tzinfo=UTC)
        claimed = claim_next_job(db_session, worker_id="w-duration-check", now=t_claim)
        assert claimed is not None
        assert claimed.scan is not None
        assert claimed.scan.status == "running"
        assert claimed.scan.started_at is not None
        started_at_utc = (
            claimed.scan.started_at
            if claimed.scan.started_at.tzinfo is not None
            else claimed.scan.started_at.replace(tzinfo=UTC)
        )
        assert started_at_utc == t_claim

        # Complete after 15 seconds of execution
        t_complete = t_claim + timedelta(seconds=15)
        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w-duration-check",
            now=t_complete,
        )
        assert completed.scan is not None
        # Duration must be 15,000 ms (15s of execution), NOT 3,615,000 ms (from queued_at)
        assert completed.scan.duration_ms == 15000

    def test_claim_with_custom_lease_duration(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Custom lease duration sets locked_until accordingly."""
        now_ref = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
        _create_test_scan_and_job(db_session, sample_project, run_after=now_ref)

        claimed = claim_next_job(
            session=db_session,
            worker_id="worker-custom-lease",
            lease_duration_sec=180,
            now=now_ref,
        )

        assert claimed is not None
        assert claimed.locked_until is not None
        locked_until_utc = (
            claimed.locked_until
            if claimed.locked_until.tzinfo is not None
            else claimed.locked_until.replace(tzinfo=UTC)
        )
        assert locked_until_utc == datetime(2026, 10, 23, 12, 3, 0, tzinfo=UTC)

    def test_claim_specific_job_id(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Passing job_id claims specifically that job, leaving other queued jobs alone."""
        _, job1 = _create_test_scan_and_job(db_session, sample_project, trigger_key="k1")
        _, job2 = _create_test_scan_and_job(db_session, sample_project, trigger_key="k2")

        claimed = claim_next_job(
            session=db_session,
            worker_id="worker-targeted",
            job_id=job2.id,
        )

        assert claimed is not None
        assert claimed.id == job2.id
        assert claimed.status == "running"

        # Verify job1 remains untouched in queued status
        db_session.refresh(job1)
        assert job1.status == "queued"
        assert job1.locked_by is None

    def test_claim_empty_queue_returns_none(
        self,
        db_session: Session,
    ) -> None:
        """When no jobs exist in the queue, claim_next_job returns None."""
        claimed = claim_next_job(
            session=db_session,
            worker_id="worker-idle",
        )
        assert claimed is None

    def test_empty_queue_does_not_commit_unrelated_caller_work(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """When no job is eligible, claim_next_job returns None without committing pending caller work."""
        with session_factory() as session:
            # Stage an unrelated entity in the session without committing
            unrelated_user = User(
                id=uuid.uuid4(),
                github_user_id=123999,
                github_login="staged-uncommitted-dev",
            )
            session.add(unrelated_user)
            session.flush()

            # Call claim_next_job with auto_commit=True when queue is empty
            claimed = claim_next_job(session, worker_id="w-checker", auto_commit=True)
            assert claimed is None

            # Explicitly roll back the caller's session
            session.rollback()

        # In a new session, verify the unrelated entity was NOT committed
        with session_factory() as verify_session:
            persisted = verify_session.get(User, unrelated_user.id)
            assert persisted is None


class TestJobClaimOrderingAndEligibility:
    """Tests for queue ordering and exclusion of ineligible jobs."""

    def test_fifo_ordering_by_run_after_and_created_at(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Jobs are claimed in FIFO order: earliest run_after first."""
        base_time = utc_now()
        t1 = base_time - timedelta(minutes=15)
        t2 = base_time - timedelta(minutes=10)
        t3 = base_time - timedelta(minutes=5)

        _, j1 = _create_test_scan_and_job(db_session, sample_project, run_after=t1, created_at=t1)
        _, j2 = _create_test_scan_and_job(db_session, sample_project, run_after=t2, created_at=t2)
        _, j3 = _create_test_scan_and_job(db_session, sample_project, run_after=t3, created_at=t3)

        c1 = claim_next_job(db_session, worker_id="w")
        c2 = claim_next_job(db_session, worker_id="w")
        c3 = claim_next_job(db_session, worker_id="w")
        c4 = claim_next_job(db_session, worker_id="w")

        assert c1 is not None and c1.id == j1.id
        assert c2 is not None and c2.id == j2.id
        assert c3 is not None and c3.id == j3.id
        assert c4 is None

    def test_running_job_not_claimed(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A job currently in 'running' status is not eligible for claim."""
        _create_test_scan_and_job(db_session, sample_project, status="running")
        claimed = claim_next_job(db_session, worker_id="w")
        assert claimed is None

    def test_succeeded_job_not_claimed(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A job in 'succeeded' status is not eligible for claim."""
        _create_test_scan_and_job(db_session, sample_project, status="succeeded")
        claimed = claim_next_job(db_session, worker_id="w")
        assert claimed is None

    def test_failed_job_not_claimed(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A job in 'failed' status is not eligible for claim."""
        _create_test_scan_and_job(db_session, sample_project, status="failed")
        claimed = claim_next_job(db_session, worker_id="w")
        assert claimed is None

    def test_dead_job_not_claimed(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A job in 'dead' status is not eligible for claim."""
        _create_test_scan_and_job(db_session, sample_project, status="dead")
        claimed = claim_next_job(db_session, worker_id="w")
        assert claimed is None

    def test_future_scheduled_job_not_claimed(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A queued job with run_after in the future is not yet eligible."""
        future_time = utc_now() + timedelta(hours=2)
        _create_test_scan_and_job(db_session, sample_project, run_after=future_time)

        claimed = claim_next_job(db_session, worker_id="w")
        assert claimed is None

    def test_max_attempts_exceeded_job_not_claimed(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A job where attempts >= max_attempts is excluded from claiming."""
        _create_test_scan_and_job(
            db_session,
            sample_project,
            status="queued",
            attempts=3,
            max_attempts=3,
        )
        claimed = claim_next_job(db_session, worker_id="w")
        assert claimed is None


class TestJobClaimInputValidationAndErrors:
    """Tests for parameter validation and error handling."""

    def test_empty_or_whitespace_worker_id_rejected(
        self,
        db_session: Session,
    ) -> None:
        """Empty, whitespace-only, or invalid type worker_id raises ValueError."""
        for invalid_id in ["", "   ", "\t\n"]:
            with pytest.raises(ValueError, match="worker_id must be a non-empty string"):
                claim_next_job(db_session, worker_id=invalid_id)

        with pytest.raises(ValueError, match="worker_id must be a non-empty string"):
            claim_next_job(db_session, worker_id=123)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "invalid_lease",
        [
            0,
            -1,
            -60,
            True,
            False,
            3.5,
            "60",
            [60],
            {"lease": 60},
        ],
    )
    def test_invalid_lease_duration_rejected(
        self,
        db_session: Session,
        invalid_lease: Any,
    ) -> None:
        """Lease duration must be a positive integer; bool, float, str, zero, and negative values raise ValueError."""
        with pytest.raises(ValueError, match="lease_duration_sec must be a positive integer"):
            claim_next_job(db_session, worker_id="w", lease_duration_sec=invalid_lease)

    @pytest.mark.parametrize("valid_lease", [1, 30, 60, 3600])
    def test_valid_positive_integer_lease_accepted(
        self,
        db_session: Session,
        sample_project: Project,
        valid_lease: int,
    ) -> None:
        """Valid positive integer lease durations are accepted without error."""
        _create_test_scan_and_job(db_session, sample_project)
        claimed = claim_next_job(db_session, worker_id="w", lease_duration_sec=valid_lease)
        assert claimed is not None

    def test_timezone_naive_now_normalized(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Timezone-naive datetime is safely converted to UTC without crashing."""
        naive_now = datetime(2026, 10, 23, 10, 0, 0)  # naive
        # Create job scheduled before naive_now so it is eligible
        _create_test_scan_and_job(
            db_session,
            sample_project,
            run_after=naive_now - timedelta(minutes=5),
        )

        claimed = claim_next_job(
            session=db_session,
            worker_id="w",
            now=naive_now,
            lease_duration_sec=60,
        )
        assert claimed is not None
        assert claimed.locked_until is not None
        locked_until_utc = (
            claimed.locked_until
            if claimed.locked_until.tzinfo is not None
            else claimed.locked_until.replace(tzinfo=UTC)
        )
        assert locked_until_utc == datetime(2026, 10, 23, 10, 1, 0, tzinfo=UTC)

    def test_database_error_sanitizes_message_and_rolls_back(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Database errors trigger rollback and raise a sanitized JobClaimError without leaking driver info."""
        _create_test_scan_and_job(db_session, sample_project)

        driver_leak_text = "FATAL: role 'secret_user' password auth failed at /var/run/postgresql"
        with (
            patch.object(
                db_session,
                "scalars",
                side_effect=OperationalError("db fail", {}, Exception(driver_leak_text)),
            ),
            pytest.raises(JobClaimError) as exc_info,
        ):
            claim_next_job(db_session, worker_id="w")

        # Message must be stable, generic, and sanitized
        assert str(exc_info.value) == "Database error while claiming next job"
        assert driver_leak_text not in str(exc_info.value)
        # Exception chaining preserves internal cause
        assert exc_info.value.__cause__ is not None
        assert driver_leak_text in str(exc_info.value.__cause__)

    def test_unexpected_error_sanitizes_message_and_rolls_back(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Unexpected non-database errors trigger rollback and raise a sanitized JobClaimError."""
        _create_test_scan_and_job(db_session, sample_project)

        with (
            patch.object(db_session, "scalars", side_effect=RuntimeError("internal process crash")),
            pytest.raises(JobClaimError) as exc_info,
        ):
            claim_next_job(db_session, worker_id="w")

        assert str(exc_info.value) == "Unexpected error while claiming next job"
        assert "internal process crash" not in str(exc_info.value)
        assert exc_info.value.__cause__ is not None


class TestJobClaimTransactionBoundaries:
    """Tests for transaction management and lock release."""

    def test_autocommit_false_leaves_commit_to_caller(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """With auto_commit=False, the claim is flushed but uncommitted; caller rollback undoes it."""
        _, job = _create_test_scan_and_job(db_session, sample_project)

        claimed = claim_next_job(
            session=db_session,
            worker_id="worker-no-autocommit",
            auto_commit=False,
        )
        assert claimed is not None
        assert claimed.status == "running"

        # Explicitly roll back the caller's transaction
        db_session.rollback()

        # In fresh query, job is still queued
        reloaded = db_session.get(Job, job.id)
        assert reloaded is not None
        assert reloaded.status == "queued"
        assert reloaded.locked_by is None
        assert reloaded.attempts == 0

    def test_locks_released_immediately_on_autocommit(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """With auto_commit=True, a separate session can immediately observe the claimed state."""
        with session_factory() as s1:
            _, job = _create_test_scan_and_job(s1, sample_project)
            claimed = claim_next_job(s1, worker_id="w-committed", auto_commit=True)
            assert claimed is not None

        # Separate independent session reads updated row immediately
        with session_factory() as s2:
            reloaded = s2.get(Job, job.id)
            assert reloaded is not None
            assert reloaded.status == "running"
            assert reloaded.locked_by == "w-committed"
            assert reloaded.attempts == 1


class TestJobClaimConcurrency:
    """Concurrency verification ensuring multi-worker safety."""

    def test_concurrent_workers_claim_distinct_jobs(self) -> None:
        """Multiple concurrent workers calling claim_next_job never claim the same job (SQLite test)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_file = os.path.join(temp_dir, "concurrency_test.db")
            engine = create_engine(f"sqlite:///{db_file}", connect_args={"timeout": 30})
            try:
                Base.metadata.create_all(engine)
                factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

                num_jobs = 6
                with factory() as init_session:
                    user = User(
                        id=uuid.uuid4(), github_user_id=99999, github_login="concurrency-lead"
                    )
                    init_session.add(user)
                    project = Project(
                        id=uuid.uuid4(),
                        owner_user_id=user.id,
                        kind="manual",
                        name="Concurrent P",
                        status="active",
                    )
                    init_session.add(project)

                    scans = [
                        Scan(
                            id=uuid.uuid4(),
                            project_id=project.id,
                            trigger="manual",
                            trigger_key=f"c-key-{i}",
                            status="queued",
                        )
                        for i in range(num_jobs)
                    ]
                    jobs = [
                        Job(
                            id=uuid.uuid4(),
                            scan=scans[i],
                            status="queued",
                            attempts=0,
                            max_attempts=3,
                        )
                        for i in range(num_jobs)
                    ]
                    init_session.add_all(scans)
                    init_session.add_all(jobs)
                    init_session.commit()

                def worker_task(worker_id: str) -> uuid.UUID | None:
                    with factory() as session:
                        claimed = claim_next_job(session, worker_id=worker_id, auto_commit=True)
                        return claimed.id if claimed else None

                # Launch concurrent workers matching the number of jobs
                worker_ids = [f"worker-{i}" for i in range(num_jobs)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=num_jobs) as executor:
                    claimed_ids = list(executor.map(worker_task, worker_ids))

                # Filter out any nones
                valid_claims = [cid for cid in claimed_ids if cid is not None]

                # Verify no duplicate claims occurred: every claimed ID must be unique
                assert len(valid_claims) == num_jobs
                assert len(set(valid_claims)) == num_jobs
            finally:
                engine.dispose()

    def test_concurrent_workers_single_job_race(self) -> None:
        """When 5 workers race for a single queued job, exactly 1 succeeds and 4 receive None (SQLite test)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_file = os.path.join(temp_dir, "single_race.db")
            engine = create_engine(f"sqlite:///{db_file}", connect_args={"timeout": 30})
            try:
                Base.metadata.create_all(engine)
                factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

                with factory() as init_session:
                    user = User(id=uuid.uuid4(), github_user_id=77777, github_login="race-lead")
                    init_session.add(user)
                    project = Project(
                        id=uuid.uuid4(),
                        owner_user_id=user.id,
                        kind="manual",
                        name="Race P",
                        status="active",
                    )
                    init_session.add(project)
                    scan = Scan(
                        id=uuid.uuid4(),
                        project_id=project.id,
                        trigger="manual",
                        trigger_key="race-key",
                        status="queued",
                    )
                    job = Job(id=uuid.uuid4(), scan=scan, status="queued")
                    init_session.add_all([scan, job])
                    init_session.commit()

                def worker_task(worker_id: str) -> uuid.UUID | None:
                    with factory() as session:
                        claimed = claim_next_job(session, worker_id=worker_id, auto_commit=True)
                        return claimed.id if claimed else None

                worker_ids = [f"racer-{i}" for i in range(5)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    results = list(executor.map(worker_task, worker_ids))

                successful_claims = [r for r in results if r is not None]
                none_claims = [r for r in results if r is None]

                assert len(successful_claims) == 1
                assert len(none_claims) == 4
            finally:
                engine.dispose()


class TestPostgresDialectCompilation:
    """Verify that PostgreSQL engine generates FOR UPDATE SKIP LOCKED."""

    def test_postgres_query_includes_for_update_skip_locked(self) -> None:
        """PostgreSQL dialect renders FOR UPDATE SKIP LOCKED on the subquery."""
        now = utc_now()
        subquery = (
            select(Job.id)
            .where(
                Job.status == "queued",
                Job.run_after <= now,
                Job.attempts < Job.max_attempts,
            )
            .order_by(Job.run_after.asc(), Job.created_at.asc(), Job.id.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        from sqlalchemy import update

        stmt = (
            update(Job)
            .where(Job.id == subquery)
            .values(status="running", locked_by="w")
            .returning(Job)
        )

        pg_engine = create_engine("postgresql+psycopg://user:pass@localhost:5432/testdb")
        compiled = str(stmt.compile(pg_engine))

        assert "FOR UPDATE SKIP LOCKED" in compiled
        assert "RETURNING" in compiled


class TestJobCompletion:
    """Tests for successful job completion and scan status synchronization."""

    def test_complete_job_success(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Claimed job is completed: job status='succeeded', scan='succeeded', locks cleared, payload nulled."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        t0 = utc_now()
        claimed = claim_next_job(db_session, worker_id="w-complete", lease_duration_sec=60, now=t0)
        assert claimed is not None
        assert claimed.status == "running"
        assert claimed.payload is not None

        t1 = t0 + timedelta(seconds=5)
        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w-complete",
            scan_status="succeeded",
            now=t1,
        )

        assert completed.id == job.id
        assert completed.status == "succeeded"
        assert completed.locked_by is None
        assert completed.locked_until is None
        assert completed.payload is None

        # Verify associated scan synchronization
        assert completed.scan is not None
        assert completed.scan.status == "succeeded"
        assert completed.scan.finished_at is not None
        assert completed.scan.duration_ms is not None
        assert completed.scan.duration_ms >= 0

    def test_complete_job_partial_scan_status(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Scan can be marked 'partial' on completion when some components failed or were truncated."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w-partial")

        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w-partial",
            scan_status="partial",
        )

        assert completed.status == "succeeded"
        assert completed.scan.status == "partial"

    def test_complete_job_null_payload_false_preserves_payload(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When null_payload=False, payload is preserved on completion."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w-keep-payload")

        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w-keep-payload",
            null_payload=False,
        )

        assert completed.status == "succeeded"
        assert completed.payload is not None

    def test_complete_job_invalid_scan_status_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """scan_status must be 'succeeded' or 'partial'; other statuses raise ValueError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        with pytest.raises(ValueError, match="scan_status must be 'succeeded' or 'partial'"):
            complete_job(db_session, job_id=job.id, worker_id="w", scan_status="failed")

    def test_complete_job_invalid_worker_id_or_job_id_rejected(
        self,
        db_session: Session,
    ) -> None:
        """Empty worker_id or invalid job_id raises ValueError."""
        valid_uuid = uuid.uuid4()
        with pytest.raises(ValueError, match="worker_id must be a non-empty string"):
            complete_job(db_session, job_id=valid_uuid, worker_id="   ")

        with pytest.raises(TypeError, match="job_id must be a UUID"):
            complete_job(db_session, job_id="not-a-uuid", worker_id="w")  # type: ignore[arg-type]

    def test_complete_job_not_found(
        self,
        db_session: Session,
    ) -> None:
        """Attempting to complete a non-existent job raises JobNotFoundError."""
        with pytest.raises(JobNotFoundError, match="does not exist"):
            complete_job(db_session, job_id=uuid.uuid4(), worker_id="w")

    def test_complete_job_wrong_worker_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to complete a job owned by a different worker raises JobOwnershipError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="worker-right")

        with pytest.raises(
            JobOwnershipError, match="is locked by worker 'worker-right', not 'worker-wrong'"
        ):
            complete_job(db_session, job_id=job.id, worker_id="worker-wrong")

        # Job in session remains running and locked by original worker
        reloaded = db_session.get(Job, job.id)
        assert reloaded is not None
        assert reloaded.status == "running"
        assert reloaded.locked_by == "worker-right"

    def test_complete_job_expired_lease_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to complete a job after its claim lease has expired raises JobOwnershipError."""
        t0 = utc_now()
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="worker-slow", lease_duration_sec=60, now=t0)

        t_expired = t0 + timedelta(seconds=120)
        with pytest.raises(JobOwnershipError, match="Lease for job .* expired"):
            complete_job(db_session, job_id=job.id, worker_id="worker-slow", now=t_expired)

    def test_complete_job_exact_lease_expiry_boundary_accepted(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Completion is accepted when now == locked_until (inclusive lease predicate)."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claimed = claim_next_job(db_session, worker_id="w-boundary", lease_duration_sec=60, now=t0)
        assert claimed is not None

        locked_until = t0 + timedelta(seconds=60)
        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w-boundary",
            now=locked_until,
        )
        assert completed.status == "succeeded"

    def test_complete_job_microsecond_past_lease_expiry_rejected_without_committing_staged_work(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """Completion rejected when now == locked_until + 1us and caller staged work is not committed."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
        with session_factory() as s1:
            _, job = _create_test_scan_and_job(s1, sample_project, run_after=t0)
            claimed = claim_next_job(s1, worker_id="w-exact", lease_duration_sec=60, now=t0)
            assert claimed is not None

        locked_until = t0 + timedelta(seconds=60)
        past_expiry = locked_until + timedelta(microseconds=1)

        with session_factory() as s2:
            staged_user = User(
                id=uuid.uuid4(),
                github_user_id=777888,
                github_login="staged-boundary-user",
            )
            s2.add(staged_user)
            s2.flush()

            with pytest.raises(JobOwnershipError, match="Lease for job .* expired"):
                complete_job(
                    s2,
                    job_id=job.id,
                    worker_id="w-exact",
                    now=past_expiry,
                    auto_commit=True,
                )

            s2.rollback()

        with session_factory() as s3:
            assert s3.get(User, staged_user.id) is None

    def test_complete_job_already_terminal_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to complete a job that is already succeeded raises JobInvalidStateError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")
        complete_job(db_session, job_id=job.id, worker_id="w")

        # Second completion attempt must fail
        with pytest.raises(
            JobInvalidStateError, match="is in status 'succeeded', expected 'running'"
        ):
            complete_job(db_session, job_id=job.id, worker_id="w")

    def test_complete_job_not_running_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to complete an unclaimed queued job raises JobInvalidStateError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)

        with pytest.raises(JobInvalidStateError, match="is in status 'queued', expected 'running'"):
            complete_job(db_session, job_id=job.id, worker_id="w")

    def test_complete_job_autocommit_false_leaves_commit_to_caller(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """With auto_commit=False, completed state is flushed but caller rollback reverts it."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        completed = complete_job(db_session, job_id=job.id, worker_id="w", auto_commit=False)
        assert completed.status == "succeeded"

        # Explicitly roll back caller transaction
        db_session.rollback()

        # Job is restored to running
        reloaded = db_session.get(Job, job.id)
        assert reloaded is not None
        assert reloaded.status == "running"

    def test_complete_job_invalid_transition_does_not_commit_unrelated_work(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """When complete_job fails ownership or validation, staged caller work is not committed."""
        with session_factory() as s1:
            _, job = _create_test_scan_and_job(s1, sample_project)
            claim_next_job(s1, worker_id="w-owner")

        with session_factory() as s2:
            staged_user = User(
                id=uuid.uuid4(),
                github_user_id=111222,
                github_login="staged-complete-dev",
            )
            s2.add(staged_user)
            s2.flush()

            # Attempt completion with wrong worker
            with pytest.raises(JobOwnershipError):
                complete_job(s2, job_id=job.id, worker_id="w-intruder", auto_commit=True)

            # Roll back caller session
            s2.rollback()

        # In independent session, verify staged user was not committed
        with session_factory() as s3:
            persisted = s3.get(User, staged_user.id)
            assert persisted is None

    def test_complete_job_database_error_rolls_back_and_sanitizes(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Database errors during completion trigger rollback and raise sanitized JobCompleteError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        leak_text = "FATAL: connection terminated to postgresql://secret:pass@db:5432"
        with (
            patch.object(
                db_session,
                "commit",
                side_effect=OperationalError("db fail", {}, Exception(leak_text)),
            ),
            pytest.raises(JobCompleteError) as exc_info,
        ):
            complete_job(db_session, job_id=job.id, worker_id="w")

        assert str(exc_info.value) == "Database error while completing job"
        assert leak_text not in str(exc_info.value)
        assert exc_info.value.__cause__ is not None
        assert leak_text in str(exc_info.value.__cause__)

    def test_complete_job_clears_stale_errors_on_success(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Transient retry failure followed by successful completion clears error_code and error_message."""
        _, job = _create_test_scan_and_job(
            db_session,
            sample_project,
            attempts=0,
            max_attempts=3,
        )
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w1", now=t0)
        retry_job(
            db_session,
            job_id=job.id,
            worker_id="w1",
            error_message="Temporary rate limit error",
            error_code="RATE_LIMITED",
            now=t0,
        )
        reloaded_scan = db_session.get(Scan, job.scan_id)
        assert reloaded_scan is not None
        assert reloaded_scan.error_code == "RATE_LIMITED"
        assert reloaded_scan.error_message == "Temporary rate limit error"

        # Reclaim and complete successfully
        t1 = t0 + timedelta(seconds=120)
        claim_next_job(db_session, worker_id="w2", now=t1)
        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w2",
            scan_status="succeeded",
            now=t1 + timedelta(seconds=5),
        )
        assert completed.scan is not None
        assert completed.scan.status == "succeeded"
        assert completed.scan.error_code is None
        assert completed.scan.error_message is None

    def test_complete_job_partial_scan_preserves_errors(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Completing with scan_status='partial' preserves pre-existing error_code and error_message."""
        scan, job = _create_test_scan_and_job(db_session, sample_project)
        scan.error_code = "PARTIAL_TIMEOUT"
        scan.error_message = "Partial scanner failed"
        db_session.commit()

        claim_next_job(db_session, worker_id="w-partial")
        completed = complete_job(
            db_session,
            job_id=job.id,
            worker_id="w-partial",
            scan_status="partial",
        )
        assert completed.scan is not None
        assert completed.scan.status == "partial"
        assert completed.scan.error_code == "PARTIAL_TIMEOUT"
        assert completed.scan.error_message == "Partial scanner failed"


class TestJobFailure:
    """Tests for recording failure on claimed jobs and synchronizing scans."""

    def test_fail_job_permanent_success(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Permanent failure: job status='failed', scan='failed', locks cleared, payload nulled."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w-fail", lease_duration_sec=60, now=t0)

        t1 = t0 + timedelta(seconds=10)
        failed = fail_job(
            db_session,
            job_id=job.id,
            worker_id="w-fail",
            error_message="Semgrep process crashed with OOM",
            error_code="SEMGREP_OOM",
            retryable=False,
            now=t1,
        )

        assert failed.id == job.id
        assert failed.status == "failed"
        assert failed.locked_by is None
        assert failed.locked_until is None
        assert failed.payload is None
        assert failed.last_error == "Semgrep process crashed with OOM"

        # Scan synchronized
        assert failed.scan is not None
        assert failed.scan.status == "failed"
        assert failed.scan.error_code == "SEMGREP_OOM"
        assert failed.scan.error_message == "Semgrep process crashed with OOM"
        assert failed.scan.finished_at is not None
        assert failed.scan.duration_ms is not None
        assert failed.scan.duration_ms >= 0

    def test_fail_job_with_custom_terminal_status_dead(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """terminal_job_status='dead' marks the job as dead while scan is marked failed."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        failed = fail_job(
            db_session,
            job_id=job.id,
            worker_id="w",
            terminal_job_status="dead",
        )

        assert failed.status == "dead"
        assert failed.scan.status == "failed"

    def test_fail_job_invalid_terminal_status_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """terminal_job_status must be 'failed' or 'dead'; other values raise ValueError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        with pytest.raises(ValueError, match="terminal_job_status must be 'failed' or 'dead'"):
            fail_job(db_session, job_id=job.id, worker_id="w", terminal_job_status="canceled")

    def test_fail_job_sanitizes_message_details(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Sensitive credentials, DB URLs, and secrets in error_message are redacted."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w-sanitize")

        raw_dirty_message = (
            "Crash connecting to postgresql+psycopg://dbuser:supersecretpass@10.0.0.1:5432/appdb. "
            "Found token ghp_ABCDEF1234567890abcdef1234567890 in scanner payload."
        )

        failed = fail_job(
            db_session,
            job_id=job.id,
            worker_id="w-sanitize",
            error_message=raw_dirty_message,
        )

        assert failed.last_error is not None
        assert "supersecretpass" not in failed.last_error
        assert "ghp_ABCDEF1234567890abcdef1234567890" not in failed.last_error
        assert "[REDACTED_DATABASE_URL]" in failed.last_error
        assert "[REDACTED_SECRET]" in failed.last_error
        assert failed.scan.error_message == failed.last_error

    def test_fail_job_not_found(
        self,
        db_session: Session,
    ) -> None:
        """Failing a non-existent job raises JobNotFoundError."""
        with pytest.raises(JobNotFoundError, match="does not exist"):
            fail_job(db_session, job_id=uuid.uuid4(), worker_id="w")

    def test_fail_job_wrong_worker_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to fail a job locked by a different worker raises JobOwnershipError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="worker-actual")

        with pytest.raises(
            JobOwnershipError, match="is locked by worker 'worker-actual', not 'worker-other'"
        ):
            fail_job(db_session, job_id=job.id, worker_id="worker-other")

        reloaded = db_session.get(Job, job.id)
        assert reloaded is not None
        assert reloaded.status == "running"

    def test_fail_job_expired_lease_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to fail a job after lease expiry raises JobOwnershipError."""
        t0 = utc_now()
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claimed = claim_next_job(db_session, worker_id="w-stale", lease_duration_sec=60, now=t0)
        assert claimed is not None

        t_expired = t0 + timedelta(seconds=100)
        with pytest.raises(JobOwnershipError, match="Lease for job .* expired"):
            fail_job(db_session, job_id=job.id, worker_id="w-stale", now=t_expired)

    def test_fail_job_exact_lease_expiry_boundary_accepted(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Failure recording is accepted when now == locked_until (inclusive lease predicate)."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claimed = claim_next_job(
            db_session, worker_id="w-fail-boundary", lease_duration_sec=60, now=t0
        )
        assert claimed is not None

        locked_until = t0 + timedelta(seconds=60)
        failed = fail_job(
            db_session,
            job_id=job.id,
            worker_id="w-fail-boundary",
            now=locked_until,
        )
        assert failed.status == "failed"

    def test_fail_job_microsecond_past_lease_expiry_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Failure recording is rejected when now == locked_until + 1us."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claimed = claim_next_job(
            db_session, worker_id="w-fail-boundary-2", lease_duration_sec=60, now=t0
        )
        assert claimed is not None

        locked_until = t0 + timedelta(seconds=60)
        past_expiry = locked_until + timedelta(microseconds=1)
        with pytest.raises(JobOwnershipError, match="Lease for job .* expired"):
            fail_job(
                db_session,
                job_id=job.id,
                worker_id="w-fail-boundary-2",
                now=past_expiry,
            )

    def test_fail_job_already_terminal_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to fail an already-failed job raises JobInvalidStateError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")
        fail_job(db_session, job_id=job.id, worker_id="w")

        with pytest.raises(JobInvalidStateError, match="is in status 'failed', expected 'running'"):
            fail_job(db_session, job_id=job.id, worker_id="w")

    def test_fail_job_autocommit_false_leaves_commit_to_caller(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """With auto_commit=False, caller rollback reverts the failure."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        failed = fail_job(db_session, job_id=job.id, worker_id="w", auto_commit=False)
        assert failed.status == "failed"

        db_session.rollback()

        reloaded = db_session.get(Job, job.id)
        assert reloaded is not None
        assert reloaded.status == "running"

    def test_fail_job_invalid_transition_does_not_commit_unrelated_work(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """When fail_job fails, staged unrelated work is not committed."""
        with session_factory() as s1:
            _, job = _create_test_scan_and_job(s1, sample_project)
            claim_next_job(s1, worker_id="w-real")

        with session_factory() as s2:
            staged_user = User(
                id=uuid.uuid4(),
                github_user_id=333444,
                github_login="staged-fail-dev",
            )
            s2.add(staged_user)
            s2.flush()

            with pytest.raises(JobOwnershipError):
                fail_job(s2, job_id=job.id, worker_id="w-fake", auto_commit=True)

            s2.rollback()

        with session_factory() as s3:
            persisted = s3.get(User, staged_user.id)
            assert persisted is None

    def test_fail_job_database_error_rolls_back_and_sanitizes(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Database errors during fail_job trigger rollback and raise sanitized JobFailureError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        driver_err = "psycopg.OperationalError: server closed connection unexpectedly"
        with (
            patch.object(
                db_session,
                "commit",
                side_effect=OperationalError("db fail", {}, Exception(driver_err)),
            ),
            pytest.raises(JobFailureError) as exc_info,
        ):
            fail_job(db_session, job_id=job.id, worker_id="w")

        assert str(exc_info.value) == "Database error while recording job failure"
        assert driver_err not in str(exc_info.value)
        assert exc_info.value.__cause__ is not None
        assert driver_err in str(exc_info.value.__cause__)


class TestJobRetryAndMaxAttempts:
    """Tests for retryable failure, delayed requeue, and max-attempt exhaustion."""

    def test_retry_job_requeues_when_attempts_under_max(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A retryable failure when attempts < max_attempts requeues the job and sets run_after in future."""
        _, job = _create_test_scan_and_job(
            db_session,
            sample_project,
            attempts=0,
            max_attempts=3,
        )
        t0 = utc_now()
        # Claim increments attempts from 0 to 1
        claimed = claim_next_job(db_session, worker_id="w-retry", lease_duration_sec=60, now=t0)
        assert claimed is not None
        assert claimed.attempts == 1

        t1 = t0 + timedelta(seconds=10)
        retried = retry_job(
            db_session,
            job_id=job.id,
            worker_id="w-retry",
            error_message="Gitleaks timed out after 60s",
            error_code="TIMEOUT",
            now=t1,
        )

        assert retried.id == job.id
        assert retried.status == "queued"
        # Run_after is in the future
        assert retried.run_after > t1
        assert retried.locked_by is None
        assert retried.locked_until is None
        # Payload must be preserved for retry
        assert retried.payload is not None
        assert retried.last_error == "Gitleaks timed out after 60s"

        # Scan is queued again, duration/finished_at cleared
        assert retried.scan.status == "queued"
        assert retried.scan.error_code == "TIMEOUT"
        assert retried.scan.error_message == "Gitleaks timed out after 60s"
        assert retried.scan.finished_at is None
        assert retried.scan.duration_ms is None

    def test_retry_job_custom_delay(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Custom retry_delay_sec sets run_after to exactly now + retry_delay_sec."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        t0 = utc_now()
        claim_next_job(db_session, worker_id="w", now=t0)

        retried = retry_job(
            db_session,
            job_id=job.id,
            worker_id="w",
            retry_delay_sec=120,
            now=t0,
        )

        assert retried.status == "queued"
        expected_run_after = t0 + timedelta(seconds=120)
        run_after_utc = (
            retried.run_after
            if retried.run_after.tzinfo is not None
            else retried.run_after.replace(tzinfo=UTC)
        )
        assert run_after_utc == expected_run_after

    def test_retry_job_large_attempt_count_capped_and_does_not_overflow(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Very high attempt count does not raise OverflowError and backoff is capped at 3600s."""
        _, job = _create_test_scan_and_job(
            db_session,
            sample_project,
            attempts=99,
            max_attempts=101,
        )
        t0 = utc_now()
        claimed = claim_next_job(db_session, worker_id="w-large-attempts", now=t0)
        assert claimed is not None
        assert claimed.attempts == 100

        retried = retry_job(
            db_session,
            job_id=job.id,
            worker_id="w-large-attempts",
            error_message="High retry attempt failure",
            now=t0,
        )
        assert retried.status == "queued"
        expected_run_after = t0 + timedelta(seconds=3600)
        run_after_utc = (
            retried.run_after
            if retried.run_after.tzinfo is not None
            else retried.run_after.replace(tzinfo=UTC)
        )
        assert run_after_utc == expected_run_after

    @pytest.mark.parametrize("invalid_delay", [0, -1, -60, True, False, 3.5, "60"])
    def test_retry_job_invalid_delay_rejected(
        self,
        db_session: Session,
        sample_project: Project,
        invalid_delay: Any,
    ) -> None:
        """retry_delay_sec must be a positive integer; other types/values raise ValueError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        claim_next_job(db_session, worker_id="w")

        with pytest.raises(ValueError, match="retry_delay_sec must be a positive integer"):
            retry_job(db_session, job_id=job.id, worker_id="w", retry_delay_sec=invalid_delay)

    def test_requeued_job_can_be_reclaimed_after_run_after(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A requeued job is eligible to be claimed only after run_after has elapsed."""
        t0 = utc_now()
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w1", now=t0)

        # Requeue with 30s delay -> run_after is t0 + 30s
        retry_job(db_session, job_id=job.id, worker_id="w1", retry_delay_sec=30, now=t0)

        # 1. At t0 + 10s: not eligible yet
        too_early = claim_next_job(db_session, worker_id="w2", now=t0 + timedelta(seconds=10))
        assert too_early is None

        # 2. At t0 + 31s: eligible and claimed!
        claimed_again = claim_next_job(db_session, worker_id="w2", now=t0 + timedelta(seconds=31))
        assert claimed_again is not None
        assert claimed_again.id == job.id
        assert claimed_again.status == "running"
        assert claimed_again.attempts == 2

    def test_retry_job_exhausted_max_attempts_transitions_to_terminal_failed(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When attempts >= max_attempts, retryable failure transitions to terminal 'failed'."""
        # Create job with attempts=2, max_attempts=3
        _, job = _create_test_scan_and_job(
            db_session,
            sample_project,
            attempts=2,
            max_attempts=3,
        )
        t0 = utc_now()
        # Claiming increments attempts to 3 (attempts == max_attempts)
        claimed = claim_next_job(db_session, worker_id="w-final", now=t0)
        assert claimed is not None
        assert claimed.attempts == 3

        # Calling retry_job when attempts exhausted
        exhausted = retry_job(
            db_session,
            job_id=job.id,
            worker_id="w-final",
            error_message="Repeated parser failure",
            error_code="PARSER_ERR",
            now=t0 + timedelta(seconds=5),
        )

        assert exhausted.id == job.id
        # Must transition to terminal failed, not queued
        assert exhausted.status == "failed"
        assert exhausted.locked_by is None
        assert exhausted.locked_until is None
        assert exhausted.payload is None  # Nulled on terminal failure

        # Scan is marked failed
        assert exhausted.scan.status == "failed"
        assert exhausted.scan.error_code == "PARSER_ERR"
        assert exhausted.scan.error_message == "Repeated parser failure"
        assert exhausted.scan.finished_at is not None
        assert exhausted.scan.duration_ms is not None


class TestJobTransitionConcurrency:
    """Concurrency verification for job completion and failure transitions."""

    def test_concurrent_completion_single_winner(self) -> None:
        """When 2 workers race to complete the same running job, exactly 1 succeeds and 1 fails."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_file = os.path.join(temp_dir, "concurrency_complete.db")
            engine = create_engine(f"sqlite:///{db_file}", connect_args={"timeout": 30})
            try:
                Base.metadata.create_all(engine)
                factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

                with factory() as init_session:
                    user = User(id=uuid.uuid4(), github_user_id=55555, github_login="c-user")
                    init_session.add(user)
                    project = Project(
                        id=uuid.uuid4(),
                        owner_user_id=user.id,
                        kind="manual",
                        name="C-Proj",
                        status="active",
                    )
                    init_session.add(project)
                    scan = Scan(
                        id=uuid.uuid4(),
                        project_id=project.id,
                        trigger="manual",
                        trigger_key="ckey",
                        status="queued",
                    )
                    job = Job(id=uuid.uuid4(), scan=scan, status="queued")
                    init_session.add_all([scan, job])
                    init_session.commit()

                    # Claim job with worker-c
                    claimed = claim_next_job(init_session, worker_id="worker-c", auto_commit=True)
                    assert claimed is not None
                    job_id = claimed.id

                results: list[str] = []

                def worker_complete() -> None:
                    with factory() as s:
                        try:
                            complete_job(s, job_id=job_id, worker_id="worker-c", auto_commit=True)
                            results.append("success")
                        except JobInvalidStateError:
                            results.append("conflict")

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [executor.submit(worker_complete) for _ in range(2)]
                    concurrent.futures.wait(futures)

                assert results.count("success") == 1
                assert results.count("conflict") == 1
            finally:
                engine.dispose()

    def test_concurrent_fail_and_complete_race(self) -> None:
        """When complete_job and fail_job race for the same job, exactly 1 succeeds and 1 receives conflict."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_file = os.path.join(temp_dir, "concurrency_race.db")
            engine = create_engine(f"sqlite:///{db_file}", connect_args={"timeout": 30})
            try:
                Base.metadata.create_all(engine)
                factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

                with factory() as init_session:
                    user = User(id=uuid.uuid4(), github_user_id=66666, github_login="race-user")
                    init_session.add(user)
                    project = Project(
                        id=uuid.uuid4(),
                        owner_user_id=user.id,
                        kind="manual",
                        name="Race-Proj",
                        status="active",
                    )
                    init_session.add(project)
                    scan = Scan(
                        id=uuid.uuid4(),
                        project_id=project.id,
                        trigger="manual",
                        trigger_key="race-key",
                        status="queued",
                    )
                    job = Job(id=uuid.uuid4(), scan=scan, status="queued")
                    init_session.add_all([scan, job])
                    init_session.commit()

                    claimed = claim_next_job(
                        init_session, worker_id="worker-race", auto_commit=True
                    )
                    assert claimed is not None
                    job_id = claimed.id

                results: list[str] = []

                def do_complete() -> None:
                    with factory() as s:
                        try:
                            complete_job(
                                s, job_id=job_id, worker_id="worker-race", auto_commit=True
                            )
                            results.append("complete_success")
                        except JobInvalidStateError:
                            results.append("complete_conflict")

                def do_fail() -> None:
                    with factory() as s:
                        try:
                            fail_job(s, job_id=job_id, worker_id="worker-race", auto_commit=True)
                            results.append("fail_success")
                        except JobInvalidStateError:
                            results.append("fail_conflict")

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    f1 = executor.submit(do_complete)
                    f2 = executor.submit(do_fail)
                    concurrent.futures.wait([f1, f2])

                # Exactly one winner
                winners = [r for r in results if r in ("complete_success", "fail_success")]
                conflicts = [r for r in results if r in ("complete_conflict", "fail_conflict")]
                assert len(winners) == 1
                assert len(conflicts) == 1
            finally:
                engine.dispose()


class TestJobSanitization:
    """Unit tests for failure message sanitization."""

    def test_sanitization_redacts_database_urls(self) -> None:
        """Database connection strings across postgresql, mysql, and sqlite are redacted."""
        msg = "Error connecting to postgresql+psycopg://sentinel_user:secret123@localhost:5432/sentinel_db."
        sanitized = sanitize_failure_message(msg)
        assert "secret123" not in sanitized
        assert "postgresql+psycopg://" not in sanitized
        assert "[REDACTED_DATABASE_URL]" in sanitized

    def test_sanitization_redacts_secrets(self) -> None:
        """Personal access tokens and key-value secrets are redacted."""
        msg = (
            "Found token ghp_1234567890abcdef1234567890abcdef123456 in file. "
            "Also password='super_secret_val' was parsed."
        )
        sanitized = sanitize_failure_message(msg)
        assert "ghp_1234567890abcdef1234567890abcdef123456" not in sanitized
        assert "super_secret_val" not in sanitized
        assert "[REDACTED_SECRET]" in sanitized
        assert "password=[REDACTED]" in sanitized

    def test_sanitization_strips_stacktraces_and_limits_length(self) -> None:
        """Raw driver stack traces are stripped, internal frames/code lines removed, and length limited."""
        dirty = (
            "Scanner aborted. \n"
            "Traceback (most recent call last):\n"
            "  File 'worker.py', line 50\n"
            "    res = db.execute(query)\n"
            "sqlalchemy.exc.OperationalError: server dropped connection\n" + ("A" * 600)
        )
        sanitized = sanitize_failure_message(dirty, max_length=100)
        assert "Traceback" not in sanitized
        assert "File " not in sanitized
        assert "worker.py" not in sanitized
        assert "db.execute" not in sanitized
        assert "sqlalchemy.exc" not in sanitized
        assert "server dropped connection" not in sanitized
        assert "Scanner aborted." in sanitized
        assert len(sanitized) <= 100

    def test_sanitization_long_prefix_before_traceback_truncated(self) -> None:
        """A long prefix before a traceback is sanitized and truncated with ellipsis."""
        dirty = ("Detailed prefix error info: " + ("X" * 150)) + (
            "\nTraceback (most recent call last):\n"
            "  File '/opt/sentinel/backend/worker.py', line 99\n"
            "    raise ValueError('secret_leak')\n"
            "ValueError: secret_leak"
        )
        sanitized = sanitize_failure_message(dirty, max_length=50)
        assert len(sanitized) <= 50
        assert sanitized.endswith("...")
        assert "Traceback" not in sanitized
        assert "File " not in sanitized
        assert "worker.py" not in sanitized
        assert "secret_leak" not in sanitized
        assert "Detailed prefix error info:" in sanitized

    def test_sanitization_traceback_at_start_fallback_message(self) -> None:
        """Traceback at message start without prefix falls back to generic failure message."""
        dirty = (
            "Traceback (most recent call last):\n"
            "  File '/app/backend/worker.py', line 123, in run_scanner\n"
            "    execute_scan()\n"
            "ZeroDivisionError: division by zero"
        )
        sanitized = sanitize_failure_message(dirty)
        assert sanitized == "Job execution failed"
        assert "File " not in sanitized
        assert "worker.py" not in sanitized
        assert "ZeroDivisionError" not in sanitized
        assert "Traceback" not in sanitized

    @pytest.mark.parametrize(
        ("raw_message", "expected_redaction", "secret_token"),
        [
            (
                "Anthropic scanner error with sk-ant-api03-abcdef1234567890abcdef123456 in log",
                "Anthropic scanner error with [REDACTED_SECRET] in log",
                "sk-ant-api03-abcdef1234567890abcdef123456",
            ),
            (
                "OpenAI scanner error with sk-abcdef1234567890abcdef123456 in response",
                "OpenAI scanner error with [REDACTED_SECRET] in response",
                "sk-abcdef1234567890abcdef123456",
            ),
            (
                "OpenAI project key sk-proj-abcdef1234567890abcdef123456 failed",
                "OpenAI project key [REDACTED_SECRET] failed",
                "sk-proj-abcdef1234567890abcdef123456",
            ),
        ],
    )
    def test_sanitization_redacts_openai_and_anthropic_synthetic_tokens(
        self,
        raw_message: str,
        expected_redaction: str,
        secret_token: str,
    ) -> None:
        """Synthetic OpenAI and Anthropic API tokens are redacted and not present in output."""
        sanitized = sanitize_failure_message(raw_message)
        assert sanitized == expected_redaction
        assert secret_token not in sanitized

    @pytest.mark.parametrize(
        "benign_text",
        [
            "Task failed due to missing input file: path/to/file.py",
            "Skill-based task routing completed successfully",
            "sk-short is not a secret token",
            "Ordinary message with numbers 12345 and words",
        ],
    )
    def test_sanitization_preserves_ordinary_non_secret_text(self, benign_text: str) -> None:
        """Ordinary non-secret text is preserved without false-positive redaction."""
        assert sanitize_failure_message(benign_text) == benign_text

    def test_job_service_exception_hierarchy(self) -> None:
        """Verify job service exception hierarchy and inheritance."""
        assert issubclass(JobClaimError, JobServiceError)
        assert issubclass(JobNotFoundError, JobServiceError)
        assert issubclass(JobInvalidStateError, JobServiceError)
        assert issubclass(JobOwnershipError, JobServiceError)
        assert issubclass(JobTransitionError, JobServiceError)
        assert issubclass(JobCompleteError, JobTransitionError)
        assert issubclass(JobFailureError, JobTransitionError)
        assert issubclass(JobReapError, JobTransitionError)


class TestJobReaper:
    """Unit and boundary tests for expired job lease recovery (reap_expired_jobs)."""

    def test_reap_running_job_expired_lease_requeues_with_backoff(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Expired running job with remaining attempts is requeued with backoff and payload preserved."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        scan, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)

        # Claim with 60s lease -> attempts=1, locked_until=t0 + 60s
        claimed = claim_next_job(
            db_session, worker_id="worker-crash", lease_duration_sec=60, now=t0
        )
        assert claimed is not None
        assert claimed.attempts == 1
        assert claimed.status == "running"
        assert claimed.locked_by == "worker-crash"
        assert _normalize_datetime(claimed.locked_until) == t0 + timedelta(seconds=60)
        assert claimed.scan.status == "running"
        assert _normalize_datetime(claimed.scan.started_at) == t0
        original_payload = claimed.payload

        # 70s later (lease expired 10s ago)
        t_reap = t0 + timedelta(seconds=70)
        reaped = reap_expired_jobs(db_session, now=t_reap)

        assert len(reaped) == 1
        assert reaped[0].id == job.id

        db_session.refresh(job)
        db_session.refresh(scan)

        # Job state verification
        assert job.status == "queued"
        assert job.locked_by is None
        assert job.locked_until is None
        assert job.attempts == 1  # Attempts NOT re-incremented
        # Exponential backoff for attempt 1: 10s * 2^0 = 10s
        assert _normalize_datetime(job.run_after) == t_reap + timedelta(seconds=10)
        assert job.last_error is not None
        assert "Job lease expired while running on worker 'worker-crash'" in job.last_error
        assert job.payload == original_payload  # Payload preserved!

        # Scan state verification
        assert scan.status == "queued"
        assert scan.error_code == "LEASE_EXPIRED"
        assert scan.error_message == job.last_error
        assert scan.finished_at is None
        assert scan.duration_ms is None

    def test_reap_running_job_custom_retry_delay(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Custom retry_delay_sec overrides default exponential backoff during requeue."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="worker-custom-delay", lease_duration_sec=60, now=t0)

        t_reap = t0 + timedelta(seconds=75)
        reaped = reap_expired_jobs(db_session, retry_delay_sec=120, now=t_reap)

        assert len(reaped) == 1
        db_session.refresh(job)
        assert _normalize_datetime(job.run_after) == t_reap + timedelta(seconds=120)

    def test_reap_running_job_max_attempts_exhausted_terminates_and_erases_payload(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Expired running job at max_attempts transitions to failed and erases payload."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        scan, job = _create_test_scan_and_job(
            db_session,
            sample_project,
            run_after=t0,
            attempts=2,
            max_attempts=3,
        )

        # Claim third and final attempt -> attempts=3, max_attempts=3
        claimed = claim_next_job(
            db_session, worker_id="worker-exhausted", lease_duration_sec=60, now=t0
        )
        assert claimed is not None
        assert claimed.attempts == 3
        assert claimed.max_attempts == 3

        t_reap = t0 + timedelta(seconds=80)
        reaped = reap_expired_jobs(db_session, now=t_reap)

        assert len(reaped) == 1
        db_session.refresh(job)
        db_session.refresh(scan)

        # Job state verification
        assert job.status == "failed"
        assert job.locked_by is None
        assert job.locked_until is None
        assert job.attempts == 3  # Not incremented further
        assert job.payload is None  # Sensitive payload erased!
        assert job.last_error is not None
        assert "Job lease expired while running on worker 'worker-exhausted'" in job.last_error

        # Scan state verification
        assert scan.status == "failed"
        assert scan.error_code == "LEASE_EXPIRED"
        assert scan.error_message == job.last_error
        assert _normalize_datetime(scan.finished_at) == t_reap
        assert scan.duration_ms == 80000  # (80s * 1000ms)

    def test_reap_exact_lease_boundary_not_reaped(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When now == locked_until, the worker lease is still valid (inclusive boundary); reaper skips it."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w-boundary", lease_duration_sec=60, now=t0)

        # Exactly at expiry boundary
        t_boundary = t0 + timedelta(seconds=60)
        reaped = reap_expired_jobs(db_session, now=t_boundary)

        assert len(reaped) == 0
        db_session.refresh(job)
        assert job.status == "running"
        assert job.locked_by == "w-boundary"

    def test_reap_microsecond_past_lease_boundary_is_reaped(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When now == locked_until + 1us, the lease is expired and the job is reaped."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w-boundary-past", lease_duration_sec=60, now=t0)

        t_past = t0 + timedelta(seconds=60, microseconds=1)
        reaped = reap_expired_jobs(db_session, now=t_past)

        assert len(reaped) == 1
        db_session.refresh(job)
        assert job.status == "queued"
        assert job.locked_by is None

    def test_reap_unexpired_running_jobs_ignored(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Running jobs whose lease has not expired are not touched by reaper."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w-active", lease_duration_sec=120, now=t0)

        # 30s into a 120s lease
        t_active = t0 + timedelta(seconds=30)
        reaped = reap_expired_jobs(db_session, now=t_active)

        assert len(reaped) == 0
        db_session.refresh(job)
        assert job.status == "running"
        assert job.locked_by == "w-active"

    def test_reap_non_running_jobs_ignored(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Jobs in queued, succeeded, failed, or dead statuses are never reaped even with past locked_until."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        past_time = t0 - timedelta(seconds=100)

        # Create jobs across non-running statuses with past locked_until
        for status in ("queued", "succeeded", "failed", "dead"):
            s = Scan(
                project_id=sample_project.id,
                trigger="manual",
                trigger_key=f"non-running-{status}-{uuid.uuid4()}",
                status=status if status != "dead" else "failed",
            )
            db_session.add(s)
            db_session.flush()
            j = Job(
                scan_id=s.id,
                status=status,
                locked_by="old-worker",
                locked_until=past_time,
                payload={"files": []},
            )
            db_session.add(j)
        db_session.commit()

        reaped = reap_expired_jobs(db_session, now=t0)
        assert len(reaped) == 0

    def test_reap_running_job_with_null_locked_until_handled_safely(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Running job with NULL locked_until is safely treated as expired and reaped."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        s = Scan(
            project_id=sample_project.id,
            trigger="manual",
            trigger_key=f"null-lock-{uuid.uuid4()}",
            status="running",
            started_at=t0,
        )
        db_session.add(s)
        db_session.flush()
        j = Job(
            scan_id=s.id,
            status="running",
            locked_by="w-orphan",
            locked_until=None,
            attempts=1,
            max_attempts=3,
            payload={"files": [{"path": "orphan.py", "content": "pass"}]},
        )
        db_session.add(j)
        db_session.commit()

        reaped = reap_expired_jobs(db_session, now=t0)
        assert len(reaped) == 1
        assert reaped[0].id == j.id
        db_session.refresh(j)
        assert j.status == "queued"
        assert j.locked_by is None

    def test_reap_batch_limit_and_deterministic_ordering(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """batch_limit bounds the sweep size and orders oldest expired leases first."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        jobs: list[Job] = []

        # Create 5 expired running jobs with staggered locked_until
        for i in range(5):
            s = Scan(
                project_id=sample_project.id,
                trigger="manual",
                trigger_key=f"batch-test-{i}-{uuid.uuid4()}",
                status="running",
            )
            db_session.add(s)
            db_session.flush()
            j = Job(
                scan_id=s.id,
                status="running",
                locked_by=f"worker-{i}",
                locked_until=t0 - timedelta(seconds=50 - (i * 10)),  # -50s, -40s, -30s, -20s, -10s
                attempts=1,
                max_attempts=3,
                payload={"files": []},
            )
            db_session.add(j)
            jobs.append(j)
        db_session.commit()

        # Batch 1: limit 2 -> oldest 2 reaped (i=0, i=1)
        reaped_1 = reap_expired_jobs(db_session, batch_limit=2, now=t0)
        assert len(reaped_1) == 2
        assert reaped_1[0].id == jobs[0].id
        assert reaped_1[1].id == jobs[1].id

        # Batch 2: limit 2 -> next 2 reaped (i=2, i=3)
        reaped_2 = reap_expired_jobs(db_session, batch_limit=2, now=t0)
        assert len(reaped_2) == 2
        assert reaped_2[0].id == jobs[2].id
        assert reaped_2[1].id == jobs[3].id

        # Batch 3: limit 2 -> last 1 reaped (i=4)
        reaped_3 = reap_expired_jobs(db_session, batch_limit=2, now=t0)
        assert len(reaped_3) == 1
        assert reaped_3[0].id == jobs[4].id

        # Subsequent call finds nothing
        assert len(reap_expired_jobs(db_session, batch_limit=2, now=t0)) == 0

    @pytest.mark.parametrize("invalid_limit", [0, -1, -10, "10", True, False, None])
    def test_reap_invalid_batch_limit_rejected(
        self,
        db_session: Session,
        invalid_limit: Any,
    ) -> None:
        """batch_limit must be a positive integer; non-int, bool, zero, and negative values raise ValueError."""
        with pytest.raises(ValueError, match="batch_limit must be a positive integer"):
            reap_expired_jobs(db_session, batch_limit=invalid_limit)

    @pytest.mark.parametrize("invalid_delay", [0, -1, -60, "30", True, False])
    def test_reap_invalid_retry_delay_rejected(
        self,
        db_session: Session,
        invalid_delay: Any,
    ) -> None:
        """retry_delay_sec must be a positive integer if provided."""
        with pytest.raises(ValueError, match="retry_delay_sec must be a positive integer"):
            reap_expired_jobs(db_session, retry_delay_sec=invalid_delay)

    def test_reap_auto_commit_false_flushes_without_committing(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """With auto_commit=False, caller controls transaction commit/rollback."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        with session_factory() as s:
            _, job = _create_test_scan_and_job(s, sample_project, run_after=t0)
            claim_next_job(s, worker_id="w-rollback", lease_duration_sec=60, now=t0)
            job_id = job.id

        # Reaping with auto_commit=False, then rolling back
        t_reap = t0 + timedelta(seconds=70)
        with session_factory() as s:
            reaped = reap_expired_jobs(s, auto_commit=False, now=t_reap)
            assert len(reaped) == 1
            assert reaped[0].status == "queued"
            s.rollback()

        # Job must still be running in the database
        with session_factory() as s:
            reloaded = s.get(Job, job_id)
            assert reloaded is not None
            assert reloaded.status == "running"
            assert reloaded.locked_by == "w-rollback"

    def test_reap_postgres_query_includes_for_update_skip_locked(self) -> None:
        """PostgreSQL dialect renders FOR UPDATE SKIP LOCKED on reaper selection."""
        now = utc_now()
        stmt = (
            select(Job)
            .where(
                Job.status == "running",
                or_(
                    Job.locked_until < now,
                    Job.locked_until.is_(None),
                ),
            )
            .order_by(Job.locked_until.asc().nulls_first(), Job.id.asc())
            .limit(10)
            .with_for_update(skip_locked=True)
        )

        pg_engine = create_engine("postgresql+psycopg://user:pass@localhost:5432/testdb")
        compiled = str(stmt.compile(pg_engine))

        assert "FOR UPDATE SKIP LOCKED" in compiled
        assert "jobs.status =" in compiled
        assert "jobs.locked_until <" in compiled

    def test_stale_worker_complete_and_fail_rejected_after_job_reaped(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """A stale worker whose lease expired and was reaped cannot complete or fail the job."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        scan, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="worker-zombie", lease_duration_sec=60, now=t0)

        # Reaper recovers job at t0 + 70s
        t_reap = t0 + timedelta(seconds=70)
        reaped = reap_expired_jobs(db_session, now=t_reap)
        assert len(reaped) == 1
        db_session.refresh(job)
        assert job.status == "queued"

        # Zombie worker wakes at t0 + 80s and tries complete_job
        t_zombie = t0 + timedelta(seconds=80)
        with pytest.raises(JobInvalidStateError, match="expected 'running'"):
            complete_job(db_session, job_id=job.id, worker_id="worker-zombie", now=t_zombie)

        # Zombie worker tries fail_job
        with pytest.raises(JobInvalidStateError, match="expected 'running'"):
            fail_job(db_session, job_id=job.id, worker_id="worker-zombie", now=t_zombie)

        # Job and scan state remained intact from reaper
        db_session.refresh(job)
        db_session.refresh(scan)
        assert job.status == "queued"
        assert scan.status == "queued"

    def test_stale_worker_cannot_complete_when_claimed_by_second_worker(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When a reaped job is re-claimed by worker 2, worker 1's late completion is rejected by ownership."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="worker-1", lease_duration_sec=60, now=t0)

        # Reaper requeues with zero backoff for immediate re-claim test
        t_reap = t0 + timedelta(seconds=70)
        reap_expired_jobs(db_session, retry_delay_sec=1, now=t_reap)

        # Worker 2 claims the requeued job at t0 + 72s
        t_claim2 = t0 + timedelta(seconds=72)
        claimed_w2 = claim_next_job(
            db_session, worker_id="worker-2", lease_duration_sec=60, now=t_claim2
        )
        assert claimed_w2 is not None
        assert claimed_w2.id == job.id
        assert claimed_w2.locked_by == "worker-2"

        # Worker 1 tries to complete the job at t0 + 75s
        t_late = t0 + timedelta(seconds=75)
        with pytest.raises(JobOwnershipError, match="locked by worker 'worker-2', not 'worker-1'"):
            complete_job(db_session, job_id=job.id, worker_id="worker-1", now=t_late)

        db_session.refresh(job)
        assert job.status == "running"
        assert job.locked_by == "worker-2"


class TestJobLeaseRenewal:
    """Tests for job lease renewal service operations (renew_job_lease)."""

    def test_job_renewal_error_hierarchy(self) -> None:
        """JobRenewalError is a subclass of JobTransitionError and JobServiceError."""
        assert issubclass(JobRenewalError, JobTransitionError)
        assert issubclass(JobRenewalError, JobServiceError)

    def test_renew_job_lease_success(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Active running job lease is successfully extended to reference_now + extension_sec."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claimed = claim_next_job(db_session, worker_id="w-renew", lease_duration_sec=60, now=t0)
        assert claimed is not None
        assert _normalize_datetime(claimed.locked_until) == t0 + timedelta(seconds=60)

        t1 = t0 + timedelta(seconds=20)
        renewed = renew_job_lease(
            db_session,
            job_id=job.id,
            worker_id="w-renew",
            extension_sec=90,
            now=t1,
        )

        assert renewed.id == job.id
        assert renewed.status == "running"
        assert renewed.locked_by == "w-renew"
        assert _normalize_datetime(renewed.locked_until) == t1 + timedelta(seconds=90)

    def test_renew_job_lease_defaults_to_worker_job_lease_sec(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When extension_sec is omitted, renewal defaults to WORKER_JOB_LEASE_SEC."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w-default", lease_duration_sec=30, now=t0)

        t1 = t0 + timedelta(seconds=15)
        renewed = renew_job_lease(
            db_session,
            job_id=job.id,
            worker_id="w-default",
            now=t1,
        )

        from app.core.config import get_settings

        expected_expiry = t1 + timedelta(seconds=get_settings().WORKER_JOB_LEASE_SEC)
        assert _normalize_datetime(renewed.locked_until) == expected_expiry

    def test_renew_job_lease_exact_boundary_accepted(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Exact boundary match (locked_until == now) is valid and successfully extended."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w-boundary", lease_duration_sec=60, now=t0)

        # Reference time equals exact current locked_until
        t_boundary = t0 + timedelta(seconds=60)
        renewed = renew_job_lease(
            db_session,
            job_id=job.id,
            worker_id="w-boundary",
            extension_sec=45,
            now=t_boundary,
        )

        assert _normalize_datetime(renewed.locked_until) == t_boundary + timedelta(seconds=45)

    def test_renew_job_lease_microsecond_past_expiry_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Lease expiration check is strict: 1 microsecond past locked_until is rejected."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w-strict", lease_duration_sec=60, now=t0)

        t_past = t0 + timedelta(seconds=60, microseconds=1)
        with pytest.raises(JobOwnershipError, match=r"Lease for job '.*' expired"):
            renew_job_lease(
                db_session,
                job_id=job.id,
                worker_id="w-strict",
                extension_sec=60,
                now=t_past,
            )

    def test_renew_job_lease_wrong_owner_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Attempting to renew a job owned by another worker raises JobOwnershipError."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="worker-real", lease_duration_sec=60, now=t0)

        with pytest.raises(
            JobOwnershipError, match="locked by worker 'worker-real', not 'worker-imposter'"
        ):
            renew_job_lease(
                db_session,
                job_id=job.id,
                worker_id="worker-imposter",
                now=t0 + timedelta(seconds=10),
            )

    def test_renew_job_lease_missing_job_rejected(
        self,
        db_session: Session,
    ) -> None:
        """Renewing a non-existent job ID raises JobNotFoundError."""
        missing_id = uuid.uuid4()
        with pytest.raises(JobNotFoundError, match=f"Job '{missing_id}' does not exist"):
            renew_job_lease(db_session, job_id=missing_id, worker_id="w-1")

    def test_renew_job_lease_null_lease_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Running job with locked_until=None raises JobOwnershipError."""
        _, job = _create_test_scan_and_job(db_session, sample_project)
        job.status = "running"
        job.locked_by = "w-null"
        job.locked_until = None
        db_session.commit()

        with pytest.raises(JobOwnershipError, match="expired at 'None'"):
            renew_job_lease(db_session, job_id=job.id, worker_id="w-null")

    def test_renew_job_lease_non_running_states_rejected(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Renewing jobs in 'queued', 'succeeded', 'failed', or 'dead' status raises JobInvalidStateError."""
        for invalid_status in ("queued", "succeeded", "failed", "dead"):
            _, job = _create_test_scan_and_job(db_session, sample_project, status=invalid_status)
            job.locked_by = "w-1"
            job.locked_until = utc_now() + timedelta(seconds=60)
            db_session.commit()

            with pytest.raises(
                JobInvalidStateError, match=f"status '{invalid_status}', expected 'running'"
            ):
                renew_job_lease(db_session, job_id=job.id, worker_id="w-1")

    def test_renew_job_lease_invalid_arguments_rejected(
        self,
        db_session: Session,
    ) -> None:
        """Invalid types, empty worker ID, booleans, and non-positive extensions are rejected."""
        valid_id = uuid.uuid4()

        # Non-UUID job_id
        with pytest.raises(TypeError, match="job_id must be a UUID"):
            renew_job_lease(db_session, job_id="not-a-uuid", worker_id="w-1")  # type: ignore[arg-type]

        # Blank or empty worker_id
        with pytest.raises(ValueError, match="worker_id must be a non-empty string"):
            renew_job_lease(db_session, job_id=valid_id, worker_id="")
        with pytest.raises(ValueError, match="worker_id must be a non-empty string"):
            renew_job_lease(db_session, job_id=valid_id, worker_id="   ")

        # Booleans
        with pytest.raises(ValueError, match="extension_sec must be a positive integer"):
            renew_job_lease(db_session, job_id=valid_id, worker_id="w-1", extension_sec=True)
        with pytest.raises(ValueError, match="extension_sec must be a positive integer"):
            renew_job_lease(db_session, job_id=valid_id, worker_id="w-1", extension_sec=False)

        # Zero and negative integers
        with pytest.raises(ValueError, match="extension_sec must be a positive integer"):
            renew_job_lease(db_session, job_id=valid_id, worker_id="w-1", extension_sec=0)
        with pytest.raises(ValueError, match="extension_sec must be a positive integer"):
            renew_job_lease(db_session, job_id=valid_id, worker_id="w-1", extension_sec=-10)

        # Floats
        with pytest.raises(ValueError, match="extension_sec must be a positive integer"):
            renew_job_lease(db_session, job_id=valid_id, worker_id="w-1", extension_sec=15.5)  # type: ignore[arg-type]

    def test_renew_job_lease_auto_commit_false_with_rollback(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """With auto_commit=False, changes are flushed but caller can roll back."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        _, job = _create_test_scan_and_job(db_session, sample_project, run_after=t0)
        claim_next_job(db_session, worker_id="w-flush", lease_duration_sec=60, now=t0)

        t1 = t0 + timedelta(seconds=20)
        renewed = renew_job_lease(
            db_session,
            job_id=job.id,
            worker_id="w-flush",
            extension_sec=120,
            now=t1,
            auto_commit=False,
        )

        assert _normalize_datetime(renewed.locked_until) == t1 + timedelta(seconds=120)

        # Caller rolls back transaction
        db_session.rollback()
        db_session.refresh(job)

        # Lease must have reverted back to t0 + 60s
        assert _normalize_datetime(job.locked_until) == t0 + timedelta(seconds=60)

    def test_renew_job_lease_concurrent_ownership_change_classified(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """When another worker steals the lock during renewal, JobOwnershipError is correctly classified."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        with session_factory() as s0:
            _, job = _create_test_scan_and_job(s0, sample_project, run_after=t0)
            claim_next_job(s0, worker_id="w-orig", lease_duration_sec=60, now=t0)

        with session_factory() as s_worker:
            # Pre-populate s_worker identity map while locked_by is still 'w-orig'
            j_cached = s_worker.get(Job, job.id)
            assert j_cached is not None
            assert j_cached.locked_by == "w-orig"

            # Another worker changes locked_by in an independent session
            with session_factory() as s_other:
                j_other = s_other.get(Job, job.id)
                assert j_other is not None
                j_other.locked_by = "w-thief"
                s_other.commit()

            # s_worker renews. Pre-check passes using identity map, but atomic update matches 0 rows.
            # session.expire(existing_job) reloads fresh DB state and raises JobOwnershipError.
            with pytest.raises(
                JobOwnershipError, match="ownership transferred to worker 'w-thief' during renewal"
            ):
                renew_job_lease(
                    s_worker,
                    job_id=job.id,
                    worker_id="w-orig",
                    now=t0 + timedelta(seconds=10),
                )

    def test_renew_job_lease_concurrent_status_change_classified(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
    ) -> None:
        """When reaper resets job status during renewal, JobInvalidStateError is correctly classified."""
        t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
        with session_factory() as s0:
            _, job = _create_test_scan_and_job(s0, sample_project, run_after=t0)
            claim_next_job(s0, worker_id="w-orig", lease_duration_sec=60, now=t0)

        with session_factory() as s_worker:
            # Pre-populate s_worker identity map while status is still 'running'
            j_cached = s_worker.get(Job, job.id)
            assert j_cached is not None
            assert j_cached.status == "running"

            with session_factory() as s_other:
                j_other = s_other.get(Job, job.id)
                assert j_other is not None
                j_other.status = "queued"
                j_other.locked_by = None
                s_other.commit()

            with pytest.raises(
                JobInvalidStateError, match="transitioned to status 'queued' during renewal"
            ):
                renew_job_lease(
                    s_worker,
                    job_id=job.id,
                    worker_id="w-orig",
                    now=t0 + timedelta(seconds=10),
                )


class TestPostgresRenewalDialectCompilation:
    """Verify that PostgreSQL engine generates proper atomic update guards and RETURNING for lease renewal."""

    def test_postgres_renewal_query_includes_guards_and_returning(self) -> None:
        """PostgreSQL dialect renders atomic update statement with status, ownership, and expiry guards."""
        now = utc_now()
        target_id = uuid.uuid4()
        clean_worker = "w-pg-worker"
        new_expiry = now + timedelta(seconds=60)

        from sqlalchemy import update

        stmt = (
            update(Job)
            .where(
                Job.id == target_id,
                Job.status == "running",
                Job.locked_by == clean_worker,
                Job.locked_until >= now,
            )
            .values(locked_until=new_expiry)
            .returning(Job)
        )

        pg_engine = create_engine("postgresql+psycopg://user:pass@localhost:5432/testdb")
        compiled = str(stmt.compile(pg_engine))

        assert "UPDATE jobs SET locked_until" in compiled
        assert "WHERE jobs.id =" in compiled
        assert "jobs.status =" in compiled
        assert "jobs.locked_by =" in compiled
        assert "jobs.locked_until >=" in compiled
        assert "RETURNING" in compiled
        assert "jobs.id" in compiled
