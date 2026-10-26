"""Background job queue service for transactional job claiming, completion, and failure transitions.

Implements Blueprint Section 7 (Worker process and queue polling), Section 8.1
(Job model and queue mechanics), and Threat Mitigation T13 (Worker concurrency and leases).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import utc_now
from app.db.models import Job

# Regex patterns for failure message sanitization
_RE_DB_URL = re.compile(
    r"(?:postgres(?:ql)?(?:\+[a-z0-9_]+)?|mysql(?:\+[a-z0-9_]+)?|sqlite(?:\+[a-z0-9_]+)?)://[^\s,;'\"\)\]\}]+",
    re.IGNORECASE,
)
_RE_SECRETS = re.compile(
    r"\b(?:"
    r"ghp_[a-zA-Z0-9]{20,}|"
    r"github_pat_[a-zA-Z0-9_]{20,}|"
    r"gho_[a-zA-Z0-9]{20,}|"
    r"glpat-[a-zA-Z0-9\-_]{20,}|"
    r"AIza[0-9A-Za-z-_]{35}|"
    r"sk-ant-[a-zA-Z0-9_\-]{20,}|"
    r"sk-[a-zA-Z0-9_\-]{20,}"
    r")\b"
)
_RE_KEY_VALUE_SECRETS = re.compile(
    r"(?i)\b(password|passwd|secret|api_key|token|auth_token)\s*[:=]\s*['\"]?[^\s'\",;]+",
)
_RE_VALID_ERROR_CODE = re.compile(r"^[A-Z0-9_\-]{1,64}$")


class JobServiceError(Exception):
    """Base exception for job service operations."""


class JobClaimError(JobServiceError):
    """Raised when an error occurs during job claiming."""


class JobNotFoundError(JobServiceError):
    """Raised when a specified job does not exist."""


class JobInvalidStateError(JobServiceError):
    """Raised when a job is in an invalid state for the requested transition."""


class JobOwnershipError(JobServiceError):
    """Raised when worker ownership or lease is invalid or expired for a job transition."""


class JobTransitionError(JobServiceError):
    """Base exception for database or execution failures during job state transitions."""


class JobCompleteError(JobTransitionError):
    """Raised when an error occurs during job completion."""


class JobFailureError(JobTransitionError):
    """Raised when an error occurs during job failure recording."""


class JobReapError(JobTransitionError):
    """Raised when an error occurs during expired job reaping."""


class JobRenewalError(JobTransitionError):
    """Raised when an error occurs during job lease renewal."""


def _normalize_datetime(dt: datetime | None) -> datetime | None:
    """Ensure datetime has timezone info for consistent comparison across dialects."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def sanitize_failure_message(message: str | None, max_length: int = 500) -> str:
    """Sanitize failure details to avoid leaking source code, secrets, URLs, or driver traces."""
    if not message or not message.strip():
        return "Job execution failed"
    clean = message.replace("\x00", "").strip()

    # Truncate at the first occurrence of traceback marker to prevent frame/source leakage
    tb_marker = "Traceback (most recent call last):"
    if tb_marker in clean:
        prefix = clean.split(tb_marker, 1)[0].strip()
        clean = prefix if prefix else "Job execution failed"

    clean = _RE_DB_URL.sub("[REDACTED_DATABASE_URL]", clean)
    clean = _RE_SECRETS.sub("[REDACTED_SECRET]", clean)
    clean = _RE_KEY_VALUE_SECRETS.sub(r"\1=[REDACTED]", clean)

    # Strip raw driver exception prefixes and clean lines
    lines = clean.splitlines()
    clean_lines = [
        line.strip()
        for line in lines
        if line.strip()
        and not any(
            marker in line
            for marker in (
                "sqlalchemy.exc.",
                "psycopg.errors.",
                "psycopg.OperationalError",
            )
        )
    ]
    clean = " ".join(" ".join(clean_lines).split())
    if not clean:
        clean = "Job execution failed"
    if len(clean) > max_length:
        clean = clean[: max_length - 3] + "..."
    return clean


def _clean_error_code(code: str | None) -> str | None:
    """Validate and normalize a structured error code."""
    if code is None:
        return None
    cleaned = code.strip().upper()
    if not cleaned:
        return None
    if not _RE_VALID_ERROR_CODE.match(cleaned):
        raise ValueError(
            f"error_code must be an alphanumeric identifier (up to 64 chars), got '{code}'"
        )
    return cleaned


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
            claimed_job.scan.started_at = current_time

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


def complete_job(
    session: Session,
    *,
    job_id: uuid.UUID,
    worker_id: str,
    scan_status: str = "succeeded",
    now: datetime | None = None,
    null_payload: bool = True,
    auto_commit: bool = True,
) -> Job:
    """Transition a currently claimed job and its associated scan to completion.

    Verifies expected worker ownership and that the claim lease has not expired.
    Synchronizes the associated scan to the appropriate terminal success status
    (e.g. 'succeeded' or 'partial') and calculates duration.

    Args:
        session: Active SQLAlchemy database session.
        job_id: UUID of the Job to complete.
        worker_id: Non-empty identifier for the completing worker.
        scan_status: Target status for the associated scan ('succeeded' or 'partial').
        now: Reference timestamp for lease verification and finished_at.
        null_payload: If True (default), nulls the job payload on completion
            to prevent persistent storage of submitted source code.
        auto_commit: If True (default), commits the transaction immediately.
            If False, only flushes changes to the session.

    Returns:
        The updated Job instance.

    Raises:
        ValueError: If worker_id is empty, job_id is invalid, or scan_status is unsupported.
        JobNotFoundError: If the job does not exist.
        JobInvalidStateError: If the job is not in 'running' status.
        JobOwnershipError: If worker_id does not match locked_by or lease has expired.
        JobCompleteError: If a database error occurs during completion.
    """
    if not isinstance(job_id, uuid.UUID):
        raise TypeError("job_id must be a UUID")
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ValueError("worker_id must be a non-empty string")
    clean_worker_id = worker_id.strip()

    if scan_status not in ("succeeded", "partial"):
        raise ValueError(f"scan_status must be 'succeeded' or 'partial', got '{scan_status}'")

    if now is None:
        current_time = utc_now()
    elif now.tzinfo is None:
        current_time = now.replace(tzinfo=UTC)
    else:
        current_time = now

    # Inspect current state first to provide precise domain exceptions without modifying session
    try:
        existing_job = session.get(Job, job_id)
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobCompleteError("Database error while inspecting job status") from exc

    if existing_job is None:
        raise JobNotFoundError(f"Job '{job_id}' does not exist")
    if existing_job.status != "running":
        raise JobInvalidStateError(
            f"Job '{job_id}' is in status '{existing_job.status}', expected 'running'"
        )
    if existing_job.locked_by != clean_worker_id:
        raise JobOwnershipError(
            f"Job '{job_id}' is locked by worker '{existing_job.locked_by}', not '{clean_worker_id}'"
        )
    locked_until_utc = _normalize_datetime(existing_job.locked_until)
    if locked_until_utc is None or locked_until_utc < current_time:
        raise JobOwnershipError(
            f"Lease for job '{job_id}' expired at '{existing_job.locked_until}' (current time: '{current_time}')"
        )

    update_values: dict[str, Any] = {
        "status": "succeeded",
        "locked_by": None,
        "locked_until": None,
    }
    if null_payload:
        update_values["payload"] = None

    # Atomic UPDATE ensures concurrent workers cannot double-transition the job
    stmt = (
        update(Job)
        .where(
            Job.id == job_id,
            Job.status == "running",
            Job.locked_by == clean_worker_id,
            Job.locked_until >= current_time,
        )
        .values(**update_values)
        .returning(Job)
        .execution_options(synchronize_session="fetch")
    )

    try:
        completed_job = session.scalars(stmt).first()
        if completed_job is None:
            raise JobInvalidStateError(
                f"Job '{job_id}' could not be transitioned due to a concurrent conflict"
            )

        # Synchronize associated scan
        if completed_job.scan is not None:
            completed_job.scan.status = scan_status
            if scan_status == "succeeded":
                completed_job.scan.error_code = None
                completed_job.scan.error_message = None
            completed_job.scan.finished_at = current_time
            ref_start = (
                completed_job.scan.started_at or completed_job.scan.queued_at or current_time
            )
            ref_start_utc = _normalize_datetime(ref_start)
            if ref_start_utc is not None:
                duration = (current_time - ref_start_utc).total_seconds() * 1000
                completed_job.scan.duration_ms = max(0, int(duration))

        if auto_commit:
            session.commit()
        else:
            session.flush()

        return completed_job
    except JobInvalidStateError:
        raise
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobCompleteError("Database error while completing job") from exc
    except Exception as exc:
        session.rollback()
        raise JobCompleteError("Unexpected error while completing job") from exc


def fail_job(
    session: Session,
    *,
    job_id: uuid.UUID,
    worker_id: str,
    error_message: str | None = None,
    error_code: str | None = None,
    retryable: bool = False,
    retry_delay_sec: int | None = None,
    terminal_job_status: str = "failed",
    now: datetime | None = None,
    auto_commit: bool = True,
) -> Job:
    """Record a failure for a currently claimed job and synchronize its scan.

    If retryable=True and the job has remaining attempts (attempts < max_attempts),
    requeues the job with a scheduled run_after in the future and returns the associated
    scan to 'queued' status.
    If retryable=False or attempts have reached max_attempts, transitions the job to
    terminal failure (default: 'failed') and scan to 'failed'.

    Args:
        session: Active SQLAlchemy database session.
        job_id: UUID of the Job to fail.
        worker_id: Non-empty identifier for the failing worker.
        error_message: Optional raw or formatted failure details (sanitized before storage).
        error_code: Optional structured error code (e.g. 'SCANNER_TIMEOUT', 'SEMGREP_FAILED').
        retryable: If True, attempts to requeue the job if attempts < max_attempts.
        retry_delay_sec: Optional seconds delay before requeued job is eligible for claiming.
            Must be a positive integer if provided. Defaults to exponential backoff.
        terminal_job_status: Job terminal status if not requeued ('failed' or 'dead').
        now: Reference timestamp for lease verification and finished_at.
        auto_commit: If True (default), commits the transaction immediately.

    Returns:
        The updated Job instance.

    Raises:
        ValueError: If worker_id is empty, retry_delay_sec is invalid, or terminal_job_status is invalid.
        JobNotFoundError: If the job does not exist.
        JobInvalidStateError: If the job is not in 'running' status.
        JobOwnershipError: If worker_id does not match locked_by or lease has expired.
        JobFailureError: If a database error occurs during failure recording.
    """
    if not isinstance(job_id, uuid.UUID):
        raise TypeError("job_id must be a UUID")
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ValueError("worker_id must be a non-empty string")
    clean_worker_id = worker_id.strip()

    if terminal_job_status not in ("failed", "dead"):
        raise ValueError(
            f"terminal_job_status must be 'failed' or 'dead', got '{terminal_job_status}'"
        )

    if retry_delay_sec is not None and (
        not isinstance(retry_delay_sec, int)
        or isinstance(retry_delay_sec, bool)
        or retry_delay_sec <= 0
    ):
        raise ValueError("retry_delay_sec must be a positive integer")

    clean_code = _clean_error_code(error_code)
    sanitized_msg = sanitize_failure_message(error_message)

    if now is None:
        current_time = utc_now()
    elif now.tzinfo is None:
        current_time = now.replace(tzinfo=UTC)
    else:
        current_time = now

    try:
        existing_job = session.get(Job, job_id)
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobFailureError("Database error while inspecting job status") from exc

    if existing_job is None:
        raise JobNotFoundError(f"Job '{job_id}' does not exist")
    if existing_job.status != "running":
        raise JobInvalidStateError(
            f"Job '{job_id}' is in status '{existing_job.status}', expected 'running'"
        )
    if existing_job.locked_by != clean_worker_id:
        raise JobOwnershipError(
            f"Job '{job_id}' is locked by worker '{existing_job.locked_by}', not '{clean_worker_id}'"
        )
    locked_until_utc = _normalize_datetime(existing_job.locked_until)
    if locked_until_utc is None or locked_until_utc < current_time:
        raise JobOwnershipError(
            f"Lease for job '{job_id}' expired at '{existing_job.locked_until}' (current time: '{current_time}')"
        )

    # Determine retry eligibility based on attempts already recorded
    is_requeue = retryable and (existing_job.attempts < existing_job.max_attempts)

    if is_requeue:
        if retry_delay_sec is not None:
            delay = retry_delay_sec
        else:
            # Default exponential backoff: 10s * 2^(attempts-1), bounded exponent, capped at 3600s
            attempt_exp = min(max(0, existing_job.attempts - 1), 12)
            delay = min(3600, 10 * (2**attempt_exp))

        scheduled_run_after = current_time + timedelta(seconds=delay)
        update_values: dict[str, Any] = {
            "status": "queued",
            "run_after": scheduled_run_after,
            "locked_by": None,
            "locked_until": None,
            "last_error": sanitized_msg,
            # Payload preserved for subsequent attempt
        }
    else:
        update_values = {
            "status": terminal_job_status,
            "locked_by": None,
            "locked_until": None,
            "last_error": sanitized_msg,
            "payload": None,  # Sensitive payload nulled on terminal failure
        }

    stmt = (
        update(Job)
        .where(
            Job.id == job_id,
            Job.status == "running",
            Job.locked_by == clean_worker_id,
            Job.locked_until >= current_time,
        )
        .values(**update_values)
        .returning(Job)
        .execution_options(synchronize_session="fetch")
    )

    try:
        failed_job = session.scalars(stmt).first()
        if failed_job is None:
            raise JobInvalidStateError(
                f"Job '{job_id}' could not be transitioned due to a concurrent conflict"
            )

        if failed_job.scan is not None:
            if is_requeue:
                failed_job.scan.status = "queued"
                failed_job.scan.error_code = clean_code
                failed_job.scan.error_message = sanitized_msg
                failed_job.scan.finished_at = None
                failed_job.scan.duration_ms = None
            else:
                failed_job.scan.status = "failed"
                failed_job.scan.error_code = clean_code or (
                    "MAX_ATTEMPTS_EXCEEDED" if retryable else None
                )
                failed_job.scan.error_message = sanitized_msg
                failed_job.scan.finished_at = current_time
                ref_start = failed_job.scan.started_at or failed_job.scan.queued_at or current_time
                ref_start_utc = _normalize_datetime(ref_start)
                if ref_start_utc is not None:
                    duration = (current_time - ref_start_utc).total_seconds() * 1000
                    failed_job.scan.duration_ms = max(0, int(duration))

        if auto_commit:
            session.commit()
        else:
            session.flush()

        return failed_job
    except JobInvalidStateError:
        raise
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobFailureError("Database error while recording job failure") from exc
    except Exception as exc:
        session.rollback()
        raise JobFailureError("Unexpected error while recording job failure") from exc


def retry_job(
    session: Session,
    *,
    job_id: uuid.UUID,
    worker_id: str,
    error_message: str | None = None,
    error_code: str | None = None,
    retry_delay_sec: int | None = None,
    terminal_job_status: str = "failed",
    now: datetime | None = None,
    auto_commit: bool = True,
) -> Job:
    """Convenience helper to record a retryable failure for a claimed job.

    Requeues the job if attempts < max_attempts; otherwise transitions to terminal failure.
    """
    return fail_job(
        session,
        job_id=job_id,
        worker_id=worker_id,
        error_message=error_message,
        error_code=error_code,
        retryable=True,
        retry_delay_sec=retry_delay_sec,
        terminal_job_status=terminal_job_status,
        now=now,
        auto_commit=auto_commit,
    )


def renew_job_lease(
    session: Session,
    *,
    job_id: uuid.UUID,
    worker_id: str,
    extension_sec: int | None = None,
    now: datetime | None = None,
    auto_commit: bool = True,
) -> Job:
    """Extend the claim lease for an active running job on behalf of its current worker.

    Implements Threat Mitigation T13 (Worker concurrency and leases) and Blueprint
    Section 7/8.1 queue resilience.

    A healthy worker processing a long-running scan invokes this operation periodically
    (heartbeat) to advance `locked_until` so that the expired-job lease reaper does not
    prematurely reclaim or terminate the job.

    Requirements and Guards:
    1. Validates that job_id is a valid UUID, worker_id is a non-empty string, and
       extension_sec is a positive integer (rejects booleans, non-integers, and non-positive numbers).
    2. Defaults extension_sec to WORKER_JOB_LEASE_SEC if not explicitly specified.
    3. Inspects current state: validates that the job exists, is currently in 'running'
       status, is owned by the supplied worker (locked_by matches), and has an unexpired lease
       (locked_until >= current_time). An exact boundary match (locked_until == now) is valid;
       NULL or expired leases are rejected.
    4. Atomically updates `locked_until` to `now + extension_sec`, guarded by:
       - Job.id == job_id
       - Job.status == "running"
       - Job.locked_by == worker_id
       - Job.locked_until >= current_time
    5. Detects concurrent conflicts: if atomic update returns 0 rows, re-inspects state to
       raise the appropriate domain exception (JobNotFoundError, JobInvalidStateError,
       or JobOwnershipError) rather than silently failing.
    6. Respects auto_commit: commits on success if True; flushes without committing caller's
       transaction if False. On unexpected errors or SQLAlchemy failures, rolls back and raises
       JobRenewalError.

    Args:
        session: Active SQLAlchemy database session.
        job_id: UUID of the running Job whose lease to extend.
        worker_id: Non-empty identifier for the owning worker.
        extension_sec: Positive integer seconds to extend the lease from reference timestamp.
            Defaults to settings.WORKER_JOB_LEASE_SEC.
        now: Reference timestamp for lease verification and new expiry calculation.
            Defaults to utc_now().
        auto_commit: If True (default), commits the transaction immediately.
            If False, flushes changes to the session.

    Returns:
        The updated Job instance with extended locked_until.

    Raises:
        TypeError: If job_id is not a UUID.
        ValueError: If worker_id is empty/whitespace or extension_sec is invalid.
        JobNotFoundError: If the job does not exist.
        JobInvalidStateError: If the job is not in 'running' status.
        JobOwnershipError: If worker_id does not match locked_by, or the lease has expired.
        JobRenewalError: If a database error occurs during lease renewal.
    """
    if not isinstance(job_id, uuid.UUID):
        raise TypeError("job_id must be a UUID")
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ValueError("worker_id must be a non-empty string")
    clean_worker_id = worker_id.strip()

    if extension_sec is None:
        effective_extension = get_settings().WORKER_JOB_LEASE_SEC
    elif (
        isinstance(extension_sec, bool) or not isinstance(extension_sec, int) or extension_sec <= 0
    ):
        raise ValueError("extension_sec must be a positive integer")
    else:
        effective_extension = extension_sec

    if now is None:
        current_time = utc_now()
    elif now.tzinfo is None:
        current_time = now.replace(tzinfo=UTC)
    else:
        current_time = now

    # Inspect current state first to provide precise domain exceptions without modifying session
    try:
        existing_job = session.get(Job, job_id)
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobRenewalError("Database error while inspecting job status") from exc

    if existing_job is None:
        raise JobNotFoundError(f"Job '{job_id}' does not exist")
    if existing_job.status != "running":
        raise JobInvalidStateError(
            f"Job '{job_id}' is in status '{existing_job.status}', expected 'running'"
        )
    if existing_job.locked_by != clean_worker_id:
        raise JobOwnershipError(
            f"Job '{job_id}' is locked by worker '{existing_job.locked_by}', not '{clean_worker_id}'"
        )
    locked_until_utc = _normalize_datetime(existing_job.locked_until)
    if locked_until_utc is None or locked_until_utc < current_time:
        raise JobOwnershipError(
            f"Lease for job '{job_id}' expired at '{existing_job.locked_until}' (current time: '{current_time}')"
        )

    new_locked_until = current_time + timedelta(seconds=effective_extension)

    # Atomic UPDATE ensures concurrent workers or reaper cannot update after ownership is lost
    stmt = (
        update(Job)
        .where(
            Job.id == job_id,
            Job.status == "running",
            Job.locked_by == clean_worker_id,
            Job.locked_until >= current_time,
        )
        .values(locked_until=new_locked_until)
        .returning(Job)
        .execution_options(synchronize_session="fetch")
    )

    try:
        renewed_job = session.scalars(stmt).first()
        if renewed_job is None:
            # Re-inspect to classify concurrent state change precisely.
            # Expire cached existing_job in identity map so session.get() queries current database state.
            session.expire(existing_job)
            conflicted = session.get(Job, job_id)
            if conflicted is None:
                raise JobNotFoundError(f"Job '{job_id}' does not exist")
            if conflicted.status != "running":
                raise JobInvalidStateError(
                    f"Job '{job_id}' transitioned to status '{conflicted.status}' during renewal"
                )
            if conflicted.locked_by != clean_worker_id:
                raise JobOwnershipError(
                    f"Job '{job_id}' ownership transferred to worker '{conflicted.locked_by}' during renewal"
                )
            conflicted_until = _normalize_datetime(conflicted.locked_until)
            if conflicted_until is None or conflicted_until < current_time:
                raise JobOwnershipError(
                    f"Lease for job '{job_id}' expired at '{conflicted.locked_until}' during renewal"
                )
            raise JobInvalidStateError(
                f"Job '{job_id}' could not be renewed due to a concurrent conflict"
            )

        if auto_commit:
            session.commit()
        else:
            session.flush()

        return renewed_job
    except (JobNotFoundError, JobInvalidStateError, JobOwnershipError):
        raise
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobRenewalError("Database error while renewing job lease") from exc
    except Exception as exc:
        session.rollback()
        raise JobRenewalError("Unexpected error while renewing job lease") from exc


def reap_expired_jobs(
    session: Session,
    *,
    batch_limit: int = 10,
    retry_delay_sec: int | None = None,
    now: datetime | None = None,
    auto_commit: bool = True,
) -> list[Job]:
    """Recover and reconcile jobs left in 'running' status with expired leases.

    Implements Threat Mitigation T13 (Worker concurrency and leases) and Blueprint
    Section 7/8.1 queue resilience.

    A job is considered expired if its status is 'running' and either its claim lease
    has lapsed (locked_until < current_time) or locked_until is NULL. The lease boundary
    is strictly inclusive: when locked_until == current_time, the worker's lease remains
    valid and the job will not be reaped.

    For expired jobs:
    1. If attempts < max_attempts:
       Requeues the job with bounded exponential backoff (or explicit retry_delay_sec),
       clears lease ownership (locked_by=None, locked_until=None), updates run_after,
       records sanitized last_error, resets associated scan state to 'queued' with
       error_code='LEASE_EXPIRED', and preserves the job payload for subsequent execution.
    2. If attempts >= max_attempts:
       Transitions the job to terminal failure ('failed'), clears lease ownership,
       erases sensitive payload (payload=None) per Threat Mitigation T3, marks the
       associated scan 'failed' with error_code='LEASE_EXPIRED', and calculates
       non-negative duration_ms.
    3. Attempts are NEVER incremented during reaping: claim_next_job already increments
       the attempt counter at claim time.

    Uses `SELECT ... FOR UPDATE SKIP LOCKED` where supported by the database dialect
    (PostgreSQL) to ensure multiple concurrent reapers never process the same expired
    job or block each other. All Job and Scan mutations are executed within the same
    transaction boundary.

    Args:
        session: Active SQLAlchemy database session.
        batch_limit: Maximum number of expired jobs to recover in one sweep.
            Must be a positive integer. Defaults to 10.
        retry_delay_sec: Optional seconds delay before requeued job is eligible
            for claiming. Must be a positive integer if provided. Defaults to
            exponential backoff matching fail_job conventions.
        now: Reference timestamp for lease expiration check and state transitions.
            Defaults to utc_now().
        auto_commit: If True (default), commits the transaction immediately.
            If False, flushes changes to the session.

    Returns:
        List of Job instances that were successfully reaped in this sweep.

    Raises:
        ValueError: If batch_limit or retry_delay_sec is invalid.
        JobReapError: If a database error occurs during reaping.
    """
    if not isinstance(batch_limit, int) or isinstance(batch_limit, bool) or batch_limit <= 0:
        raise ValueError("batch_limit must be a positive integer")

    if retry_delay_sec is not None and (
        not isinstance(retry_delay_sec, int)
        or isinstance(retry_delay_sec, bool)
        or retry_delay_sec <= 0
    ):
        raise ValueError("retry_delay_sec must be a positive integer")

    if now is None:
        current_time = utc_now()
    elif now.tzinfo is None:
        current_time = now.replace(tzinfo=UTC)
    else:
        current_time = now

    stmt = (
        select(Job)
        .where(
            Job.status == "running",
            or_(
                Job.locked_until < current_time,
                Job.locked_until.is_(None),
            ),
        )
        .order_by(Job.locked_until.asc().nulls_first(), Job.id.asc())
        .limit(batch_limit)
        .with_for_update(skip_locked=True)
    )

    try:
        expired_jobs = list(session.scalars(stmt).all())
        if not expired_jobs:
            return []

        for job in expired_jobs:
            old_worker = job.locked_by or "unknown"
            sanitized_msg = sanitize_failure_message(
                f"Job lease expired while running on worker '{old_worker}'"
            )

            # Determine retry eligibility based on attempts recorded at claim time
            if job.attempts < job.max_attempts:
                # Requeue with backoff
                if retry_delay_sec is not None:
                    delay = retry_delay_sec
                else:
                    attempt_exp = min(max(0, job.attempts - 1), 12)
                    delay = min(3600, 10 * (2**attempt_exp))

                scheduled_run_after = current_time + timedelta(seconds=delay)
                job.status = "queued"
                job.run_after = scheduled_run_after
                job.locked_by = None
                job.locked_until = None
                job.last_error = sanitized_msg
                # Payload is preserved for subsequent attempt

                if job.scan is not None:
                    job.scan.status = "queued"
                    job.scan.error_code = "LEASE_EXPIRED"
                    job.scan.error_message = sanitized_msg
                    job.scan.finished_at = None
                    job.scan.duration_ms = None
            else:
                # Terminal failure
                job.status = "failed"
                job.locked_by = None
                job.locked_until = None
                job.last_error = sanitized_msg
                job.payload = None  # Sensitive payload erased on terminal failure

                if job.scan is not None:
                    job.scan.status = "failed"
                    job.scan.error_code = "LEASE_EXPIRED"
                    job.scan.error_message = sanitized_msg
                    job.scan.finished_at = current_time
                    ref_start = job.scan.started_at or job.scan.queued_at or current_time
                    ref_start_utc = _normalize_datetime(ref_start)
                    if ref_start_utc is not None:
                        duration = (current_time - ref_start_utc).total_seconds() * 1000
                        job.scan.duration_ms = max(0, int(duration))

        if auto_commit:
            session.commit()
        else:
            session.flush()

        return expired_jobs
    except SQLAlchemyError as exc:
        session.rollback()
        raise JobReapError("Database error while reaping expired jobs") from exc
    except Exception as exc:
        session.rollback()
        raise JobReapError("Unexpected error while reaping expired jobs") from exc
