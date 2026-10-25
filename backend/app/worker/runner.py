"""Worker execution pipeline and polling runner.

Implements Blueprint Section 7 (Worker process and queue polling)
and Threat Mitigations T2 (Subprocess isolation) and T13 (Worker concurrency).
"""

from __future__ import annotations

import logging
import signal
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import utc_now
from app.db.models import Job
from app.db.session import dispose_engine, get_session_factory, session_scope
from app.services.job_service import (
    JobInvalidStateError,
    JobOwnershipError,
    claim_next_job,
    complete_job,
    fail_job,
    reap_expired_jobs,
    sanitize_failure_message,
)
from app.worker.payload import PayloadValidationError, validate_scan_payload
from app.worker.scanner import (
    DefaultScannerEngine,
    ScanExecutionResult,
    ScannerInterface,
    ScanStatus,
)

logger = logging.getLogger("sentinel.worker")


class JobWorker:
    """Production background worker for Sentinel scan queue polling and execution."""

    def __init__(
        self,
        session_factory: sessionmaker[Session] | None = None,
        *,
        worker_id: str | None = None,
        scanner: ScannerInterface | None = None,
        poll_interval_sec: float | None = None,
        lease_duration_sec: int | None = None,
        reaper_interval_sec: float | None = None,
    ) -> None:
        self.session_factory = session_factory or get_session_factory()
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:12]}"
        self.scanner: ScannerInterface = scanner or DefaultScannerEngine()
        settings = get_settings()
        self.poll_interval_sec = (
            poll_interval_sec
            if poll_interval_sec is not None
            else settings.WORKER_POLL_INTERVAL_SEC
        )
        self.lease_duration_sec = (
            lease_duration_sec if lease_duration_sec is not None else settings.WORKER_JOB_LEASE_SEC
        )
        self.reaper_interval_sec = (
            reaper_interval_sec
            if reaper_interval_sec is not None
            else settings.WORKER_REAPER_INTERVAL_SEC
        )
        self._last_reap_mono: float = 0.0
        self._stop_event = threading.Event()

    @property
    def is_running(self) -> bool:
        """Return True if worker is active and not signaled to stop."""
        return not self._stop_event.is_set()

    def stop(self) -> None:
        """Signal the worker loop to stop gracefully after completing in-flight work."""
        self._stop_event.set()

    def reap_expired_jobs(
        self,
        *,
        batch_limit: int = 10,
        retry_delay_sec: int | None = None,
        now: datetime | None = None,
    ) -> list[Job]:
        """Sweep and recover expired jobs in a dedicated short transaction.

        Args:
            batch_limit: Maximum number of expired jobs to recover in this sweep.
            retry_delay_sec: Optional override for requeue backoff delay.
            now: Reference timestamp for test injection.

        Returns:
            List of recovered Job instances.
        """
        try:
            with session_scope(self.session_factory) as session:
                return reap_expired_jobs(
                    session,
                    batch_limit=batch_limit,
                    retry_delay_sec=retry_delay_sec,
                    now=now,
                    auto_commit=True,
                )
        except Exception as exc:  # noqa: BLE001 - keep worker safe across reaper errors
            logger.error(
                "Worker %s error during expired job reaping: %s",
                self.worker_id,
                sanitize_failure_message(str(exc)),
            )
            return []

    def run_once(
        self,
        now: datetime | None = None,
        *,
        completion_now: datetime | None = None,
        reap: bool = False,
    ) -> bool:
        """Poll and process at most one job from the queue.

        Args:
            now: Reference timestamp for testing claim eligibility and lease expiry.
            completion_now: Optional explicit timestamp for testing completion timing.
            reap: If True, sweeps for and recovers expired jobs before claiming.

        Returns:
            True if an eligible job was claimed and processed, False if queue was empty.
        """
        if reap:
            self.reap_expired_jobs(now=now)

        claim_time = now or utc_now()

        # Step 1: Claim next eligible job in a dedicated short transaction
        with session_scope(self.session_factory) as session:
            claimed_job = claim_next_job(
                session,
                worker_id=self.worker_id,
                lease_duration_sec=self.lease_duration_sec,
                now=claim_time,
                auto_commit=True,
            )

        if claimed_job is None:
            return False

        job_id = claimed_job.id

        # Step 2: Process the claimed job across decoupled database phases
        self.process_job(job_id=job_id, now=now, completion_now=completion_now)
        return True

    def process_job(
        self,
        job_id: uuid.UUID,
        *,
        now: datetime | None = None,
        completion_now: datetime | None = None,
    ) -> Job | None:
        """Execute the analysis pipeline for a claimed job across decoupled phases.

        Phase 1: Validate active claim and extract payload in a short session.
        Phase 2: Execute scanner outside any open database session or connection.
        Phase 3: Record completion or failure in a fresh short session.

        Args:
            job_id: UUID of the claimed Job to execute.
            now: Reference timestamp for lease validation and test injection.
            completion_now: Optional reference timestamp for testing completion timing.

        Returns:
            The updated Job instance, or None if the job was not found.
        """
        start_time = now or utc_now()
        raw_payload: Any = None
        job_type: str = ""

        # Phase 1: Retrieve claimed job, validate state and ownership, extract payload
        with session_scope(self.session_factory) as session:
            job = session.get(Job, job_id)
            if job is None:
                logger.warning("Job %s not found for processing", job_id)
                return None

            # Verify ownership and running state
            if job.status != "running" or job.locked_by != self.worker_id:
                logger.warning(
                    "Job %s status='%s' locked_by='%s' is not active for worker %s",
                    job_id,
                    job.status,
                    job.locked_by,
                    self.worker_id,
                )
                return job

            # Check if lease expired before processing started
            if job.locked_until is not None:
                locked_until_utc = (
                    job.locked_until
                    if job.locked_until.tzinfo is not None
                    else job.locked_until.replace(tzinfo=UTC)
                )
                if locked_until_utc < start_time:
                    logger.warning("Job %s lease expired before processing started", job_id)
                    return job

            job_type = job.type
            raw_payload = job.payload

        # Phase 1.1: Validate supported job type
        if job_type != "scan":
            logger.error("Job %s rejected: unsupported job type '%s'", job_id, job_type)
            fail_time = completion_now or (now if now is not None else utc_now())
            with session_scope(self.session_factory) as session:
                return fail_job(
                    session,
                    job_id=job_id,
                    worker_id=self.worker_id,
                    error_message=f"Unsupported job type: '{job_type}'",
                    error_code="UNSUPPORTED_JOB_TYPE",
                    retryable=False,
                    now=fail_time,
                    auto_commit=True,
                )

        # Phase 1.2: Validate payload structure and content safety
        try:
            payload = validate_scan_payload(raw_payload)
        except PayloadValidationError as err:
            sanitized_err = sanitize_failure_message(str(err))
            logger.error("Job %s payload validation failed: %s", job_id, sanitized_err)
            fail_time = completion_now or (now if now is not None else utc_now())
            with session_scope(self.session_factory) as session:
                return fail_job(
                    session,
                    job_id=job_id,
                    worker_id=self.worker_id,
                    error_message=f"Malformed job payload: {sanitized_err}",
                    error_code="MALFORMED_PAYLOAD",
                    retryable=False,
                    now=fail_time,
                    auto_commit=True,
                )

        # Phase 2: Execute scanner completely outside any database session or connection
        try:
            scan_result = self.scanner.scan(payload)
        except Exception as exc:  # noqa: BLE001 - catch unexpected scanner crashes to fail job
            sanitized_exc = sanitize_failure_message(str(exc))
            logger.error("Job %s scanner execution raised error: %s", job_id, sanitized_exc)
            fail_time = completion_now or (now if now is not None else utc_now())
            with session_scope(self.session_factory) as session:
                return fail_job(
                    session,
                    job_id=job_id,
                    worker_id=self.worker_id,
                    error_message=f"Scanner execution failed: {sanitized_exc}",
                    error_code="SCANNER_EXECUTION_ERROR",
                    retryable=False,
                    now=fail_time,
                    auto_commit=True,
                )

        # Phase 3: Route scanner outcome through existing lifecycle functions in a fresh session
        finished_time = completion_now or (now if now is not None else utc_now())
        with session_scope(self.session_factory) as session:
            return self._handle_scan_result(
                session=session,
                job_id=job_id,
                scan_result=scan_result,
                current_time=finished_time,
            )

    def _handle_scan_result(
        self,
        *,
        session: Session,
        job_id: uuid.UUID,
        scan_result: ScanExecutionResult,
        current_time: datetime,
    ) -> Job:
        """Route the structured scanner execution result to job and scan state."""

        if scan_result.status == ScanStatus.SUCCEEDED:
            completed_job = complete_job(
                session,
                job_id=job_id,
                worker_id=self.worker_id,
                scan_status="succeeded",
                now=current_time,
                null_payload=True,
                auto_commit=False,
            )
            if completed_job.scan is not None:
                if scan_result.components is not None:
                    completed_job.scan.components = scan_result.components
                if scan_result.counts is not None:
                    completed_job.scan.counts = scan_result.counts
            session.commit()
            logger.info("Job %s completed successfully", job_id)
            return completed_job

        elif scan_result.status == ScanStatus.PARTIAL:
            completed_job = complete_job(
                session,
                job_id=job_id,
                worker_id=self.worker_id,
                scan_status="partial",
                now=current_time,
                null_payload=True,
                auto_commit=False,
            )
            if completed_job.scan is not None:
                if scan_result.components is not None:
                    completed_job.scan.components = scan_result.components
                if scan_result.counts is not None:
                    completed_job.scan.counts = scan_result.counts
                if scan_result.error_code is not None:
                    completed_job.scan.error_code = scan_result.error_code
                if scan_result.error_message is not None:
                    completed_job.scan.error_message = sanitize_failure_message(
                        scan_result.error_message
                    )
            session.commit()
            logger.warning("Job %s completed with partial results", job_id)
            return completed_job

        elif scan_result.status == ScanStatus.FAILED:
            failed_job = fail_job(
                session,
                job_id=job_id,
                worker_id=self.worker_id,
                error_message=scan_result.error_message or "Scan execution failed",
                error_code=scan_result.error_code,
                retryable=scan_result.retryable,
                retry_delay_sec=scan_result.retry_delay_sec,
                now=current_time,
                auto_commit=True,
            )
            logger.warning(
                "Job %s marked %s (retryable=%s, error_code=%s)",
                job_id,
                failed_job.status,
                scan_result.retryable,
                scan_result.error_code,
            )
            return failed_job

        else:
            return fail_job(
                session,
                job_id=job_id,
                worker_id=self.worker_id,
                error_message=f"Unknown scan status: '{scan_result.status}'",
                error_code="INVALID_SCAN_STATUS",
                retryable=False,
                now=current_time,
                auto_commit=True,
            )

    def run(self, max_iterations: int | None = None) -> int:
        """Run the worker polling loop until stopped or max_iterations reached.

        Args:
            max_iterations: Optional limit on loop iterations (useful for tests and bounded runs).

        Returns:
            Total count of jobs processed during execution.
        """
        processed_count = 0
        iterations = 0
        logger.info(
            "Worker %s started polling loop (interval=%.2fs)",
            self.worker_id,
            self.poll_interval_sec,
        )

        while not self._stop_event.is_set():
            if max_iterations is not None and iterations >= max_iterations:
                break
            iterations += 1

            # Check if it is time to sweep and reap expired jobs
            current_mono = time.monotonic()
            if (
                self._last_reap_mono <= 0.0
                or (current_mono - self._last_reap_mono) >= self.reaper_interval_sec
            ):
                reaped = self.reap_expired_jobs()
                self._last_reap_mono = current_mono
                if reaped:
                    logger.info(
                        "Worker %s reaped %d expired job(s)",
                        self.worker_id,
                        len(reaped),
                    )

            try:
                claimed = self.run_once()
                if claimed:
                    processed_count += 1
                    # Promptly poll next job without sleeping if more work might be queued
                    if not self._stop_event.is_set():
                        continue
            except (JobOwnershipError, JobInvalidStateError) as exc:
                logger.warning(
                    "Worker %s encounter expected concurrency conflict: %s",
                    self.worker_id,
                    sanitize_failure_message(str(exc)),
                )
            except Exception as exc:  # noqa: BLE001 - keep polling loop alive across unhandled errors
                logger.error(
                    "Worker %s error during polling cycle: %s",
                    self.worker_id,
                    sanitize_failure_message(str(exc)),
                )

            # Avoid tight polling loop: wait for poll_interval_sec or until signaled to stop
            self._stop_event.wait(self.poll_interval_sec)

        logger.info("Worker %s stopped. Total jobs processed: %d", self.worker_id, processed_count)
        return processed_count


def setup_signal_handlers(worker: JobWorker) -> None:
    """Register termination signal handlers to initiate graceful worker shutdown."""

    def handler(signum: int, frame: Any) -> None:
        logger.info("Received termination signal %d; initiating graceful shutdown...", signum)
        worker.stop()

    signal.signal(signal.SIGINT, handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)


def main() -> None:
    """Standalone CLI entry point for Sentinel worker process."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    worker = JobWorker()
    setup_signal_handlers(worker)
    logger.info("Starting Sentinel worker %s", worker.worker_id)
    try:
        worker.run()
    finally:
        dispose_engine()
