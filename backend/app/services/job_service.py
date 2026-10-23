"""Background job queue service for transactional job claiming and status transitions.

Implements Blueprint Section 7 (Worker process and queue polling), Section 8.1
(Job model and queue mechanics), and Threat Mitigation T13 (Worker concurrency and leases).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utc_now
from app.db.models import Job


class JobServiceError(Exception):
    """Base exception for job service operations."""


class JobClaimError(JobServiceError):
    """Raised when an error occurs during job claiming."""


def claim_next_job(
    session: Session,
    *,
    worker_id: str,
    job_id: uuid.UUID | None = None,
    lease_duration_sec: int | None = None,
    now: datetime | None = None,
    auto_commit: bool = True,
) -> Job | None:
    """Atomically claim one eligible queued job for an execution worker.

    Uses an atomic `UPDATE ... WHERE id = (SELECT id FROM jobs ... FOR UPDATE SKIP LOCKED)`
    pattern to guarantee that concurrent workers never claim the same job across both
    PostgreSQL and SQLite execution environments.

    When a job is successfully claimed:
    1. `job.status` transitions from 'queued' to 'running'.
    2. `job.locked_by` is assigned to `worker_id`.
    3. `job.locked_until` is set to `current_time + lease_duration`.
    4. `job.attempts` is incremented by 1.
    5. The associated `scan.status` transitions from 'queued' to 'running'.
    6. If `auto_commit=True` (default), the claim transaction is committed immediately
       so that database row locks are released before long-running analysis begins.

    Args:
        session: Active SQLAlchemy database session.
        worker_id: Non-empty identifier for the claiming worker.
        job_id: Optional specific Job UUID to claim if eligible.
        lease_duration_sec: Optional lease duration in seconds. Defaults to
            settings.WORKER_JOB_LEASE_SEC (60s). Must be a positive integer.
        now: Reference timestamp for eligibility check and lease computation.
            Defaults to utc_now().
        auto_commit: If True (default), commits the claim transaction immediately,
            releasing database locks before returning. If False, only flushes.
            If no job is eligible, returns None without committing or rolling back.

    Returns:
        The claimed Job instance, or None if no eligible job was available.

    Raises:
        ValueError: If worker_id is empty or lease_duration_sec is not a positive integer.
        JobClaimError: If an unexpected database error occurs during claiming.
    """
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ValueError("worker_id must be a non-empty string")
    clean_worker_id = worker_id.strip()

    if lease_duration_sec is not None:
        if (
            not isinstance(lease_duration_sec, int)
            or isinstance(lease_duration_sec, bool)
            or lease_duration_sec <= 0
        ):
            raise ValueError("lease_duration_sec must be a positive integer")
        effective_lease = lease_duration_sec
    else:
        effective_lease = get_settings().WORKER_JOB_LEASE_SEC

    if now is None:
        current_time = utc_now()
    elif now.tzinfo is None:
        current_time = now.replace(tzinfo=UTC)
    else:
        current_time = now

    subquery_conditions: list[Any] = [
        Job.status == "queued",
        Job.run_after <= current_time,
        Job.attempts < Job.max_attempts,
    ]
    if job_id is not None:
        subquery_conditions.append(Job.id == job_id)

    # Subquery selects exactly one eligible queued job using FOR UPDATE SKIP LOCKED
    subquery = (
        select(Job.id)
        .where(*subquery_conditions)
        .order_by(Job.run_after.asc(), Job.created_at.asc(), Job.id.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )

    # Atomic update assigns worker lock, increments attempts, and transitions status
    stmt = (
        update(Job)
        .where(Job.id == subquery)
        .values(
            status="running",
            locked_by=clean_worker_id,
            locked_until=current_time + timedelta(seconds=effective_lease),
            attempts=Job.attempts + 1,
        )
        .returning(Job)
    )

    try:
        claimed_job = session.scalars(stmt).first()
        if claimed_job is None:
            return None

        # Synchronize associated Scan status to 'running'
        if claimed_job.scan is not None and claimed_job.scan.status == "queued":
            claimed_job.scan.status = "running"

        if auto_commit:
            session.commit()
        else:
            session.flush()

        return claimed_job
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobClaimError("Database error while claiming next job") from exc
    except Exception as exc:
        session.rollback()
        raise JobClaimError("Unexpected error while claiming next job") from exc
