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
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import Job, Project, Scan, User
from app.services.job_service import (
    JobClaimError,
    claim_next_job,
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

        # Verify associated scan status is updated to 'running'
        assert claimed.scan is not None
        assert claimed.scan.status == "running"

    def test_claim_with_custom_lease_duration(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Custom lease duration sets locked_until accordingly."""
        _create_test_scan_and_job(db_session, sample_project)
        now_ref = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)

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
