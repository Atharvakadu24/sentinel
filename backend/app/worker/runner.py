"""Worker execution pipeline and polling runner.

Implements Blueprint Section 7 (Worker process and queue polling)
and Threat Mitigations T2 (Subprocess isolation) and T13 (Worker concurrency).
"""

from __future__ import annotations

import inspect
import logging
import signal
import threading
import time
import types
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Self

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import utc_now
from app.db.models import Job, Scan
from app.db.session import dispose_engine, get_session_factory, session_scope
from app.domain.paths import normalize_and_validate_path
from app.services.finding_service import persist_scan_findings
from app.services.github_client import (
    GitHubAppClient,
    GitHubClientError,
    GitHubRateLimitError,
)
from app.services.job_service import (
    JobInvalidStateError,
    JobNotFoundError,
    JobOwnershipError,
    _normalize_datetime,
    claim_next_job,
    complete_job,
    fail_job,
    reap_expired_jobs,
    renew_job_lease,
    sanitize_failure_message,
)
from app.services.scan_service import (
    MAX_FILE_BYTES,
    MAX_FILES_COUNT,
    MAX_TOTAL_BYTES,
    is_extension_supported,
    is_minified_or_generated,
)
from app.worker.payload import (
    GitHubPRScanJobPayload,
    PayloadValidationError,
    validate_github_pr_scan_payload,
    validate_scan_payload,
)
from app.worker.scanner import (
    DefaultScannerEngine,
    ScanExecutionResult,
    ScanJobPayload,
    ScannedFile,
    ScannerInterface,
    ScanStatus,
)

logger = logging.getLogger("sentinel.worker")


def _scanner_supports_cancel_event(scanner: ScannerInterface) -> bool:
    """Return True if scanner.scan accepts a `cancel_event` keyword argument."""
    try:
        sig = inspect.signature(scanner.scan)
    except (TypeError, ValueError):
        return False

    return any(
        param.kind == inspect.Parameter.VAR_KEYWORD
        or (
            param.name == "cancel_event"
            and param.kind
            in (
                inspect.Parameter.KEYWORD_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        )
        for param in sig.parameters.values()
    )


class JobHeartbeat:
    """Scoped background lease renewal heartbeat for long-running worker jobs.

    Runs a daemon background thread while the worker executes synchronous scanner analysis.
    Periodically extends the job lease in dedicated, short-lived database transactions via
    session_scope(), ensuring that active scans outlasting WORKER_JOB_LEASE_SEC are not reaped
    by the expired-job lease reaper.

    Implements:
    - Dedicated short-lived session per renewal (zero DB connections held during scanning).
    - Event-based wait using threading.Event.wait(interval_sec) without busy-waiting.
    - Outcome classification:
        * Confirmed lost ownership / invalid state (JobOwnershipError, JobInvalidStateError,
          JobNotFoundError): marks lost_ownership=True, stops renewals, and instructs caller
          to discard scan results.
        * Transient errors (SQLAlchemyError, OperationalError, JobRenewalError): logs sanitized
          warning and continues attempting renewal while lease remains valid.
        * Worker shutdown: stops cleanly without bypassing worker shutdown semantics.
    - Context manager interface for deterministic start, stop, and join coordination.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        job_id: uuid.UUID,
        worker_id: str,
        interval_sec: float,
        lease_extension_sec: int,
        initial_locked_until: datetime | None = None,
        worker_stop_event: threading.Event | None = None,
        scan_cancel_event: threading.Event | None = None,
        shutdown_timeout_sec: float = 2.0,
    ) -> None:
        self.session_factory = session_factory
        self.job_id = job_id
        self.worker_id = worker_id
        self.interval_sec = interval_sec
        self.lease_extension_sec = lease_extension_sec
        self.last_known_locked_until: datetime | None = _normalize_datetime(initial_locked_until)
        self.worker_stop_event = worker_stop_event
        self.scan_cancel_event = scan_cancel_event or threading.Event()
        self.shutdown_timeout_sec = shutdown_timeout_sec

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._renewal_lock = threading.Lock()

        # Outcome state
        self.lost_ownership: bool = False
        self.consecutive_transient_failures: int = 0
        self.last_transient_error: str | None = None
        self.successful_renewals: int = 0
        self.clean_shutdown: bool = True
        self._in_flight: bool = False

    @property
    def is_alive(self) -> bool:
        """Return True if background heartbeat thread is currently running."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def is_renewal_in_flight(self) -> bool:
        """Return True if a lease renewal transaction is actively executing."""
        with self._lock:
            return self._in_flight

    def is_lease_uncertain(self, reference_time: datetime | None = None) -> bool:
        """Return True if the lease has expired or is in an unknown/uncertain state.

        Preserves safety: if transient failures or delays prevented lease extension and
        the last known lease has lapsed, findings must not be committed to prevent overwriting
        newer worker or reaper state.

        Lease expiry is verified independently of the transient failure counter: an expired
        or missing lease is never treated as healthy simply because no transient exceptions
        were recorded.
        """
        with self._lock:
            if self.lost_ownership:
                return True  # Confirmed lost ownership cannot be reported as valid/healthy

            if self.last_known_locked_until is None:
                return True  # Unknown/null lease cannot be confirmed valid

            check_time = reference_time or utc_now()
            check_time_utc = _normalize_datetime(check_time)
            last_utc = _normalize_datetime(self.last_known_locked_until)

            if last_utc is None or check_time_utc is None:
                return True

            # Strict boundary: locked_until == now is still valid; strictly less than is expired
            return last_utc < check_time_utc

    def renew_once(self, now: datetime | None = None) -> bool:
        """Execute a single lease renewal in a dedicated short transaction.

        Returns:
            True if heartbeat should continue running, False if ownership is lost
            or heartbeat should terminate.
        """
        with self._renewal_lock:
            with self._lock:
                if self._stop_event.is_set() or (
                    self.worker_stop_event is not None and self.worker_stop_event.is_set()
                ):
                    return False
                self._in_flight = True

            try:
                current_time = now or utc_now()
                with session_scope(self.session_factory) as session:
                    bind = session.get_bind()
                    if bind is not None and getattr(bind.dialect, "name", "") == "postgresql":
                        # Bounded statement timeout for PostgreSQL to prevent queries hanging indefinitely
                        session.execute(text("SET LOCAL statement_timeout = '3000'"))

                    renewed = renew_job_lease(
                        session,
                        job_id=self.job_id,
                        worker_id=self.worker_id,
                        extension_sec=self.lease_extension_sec,
                        now=current_time,
                        auto_commit=False,
                    )
                    renewed_scan = getattr(renewed, "scan", None)
                    renewed_scan_status: str | None = (
                        getattr(renewed_scan, "status", None) if renewed_scan is not None else None
                    )
                    renewed_locked_until = _normalize_datetime(renewed.locked_until)

                    # Synchronized pre-commit decision and commit execution:
                    # Holds _lock to ensure stop() cannot interleave between the stop check
                    # and session.commit(). If shutdown wins the lock first, session rolls back
                    # and counters/lease timestamps are not updated. If commit wins, it completes
                    # before shutdown establishes its boundary.
                    with self._lock:
                        if self._stop_event.is_set() or (
                            self.worker_stop_event is not None and self.worker_stop_event.is_set()
                        ):
                            session.rollback()
                            logger.info(
                                "Worker %s aborted in-flight lease renewal commit for job %s due to shutdown signal",
                                self.worker_id,
                                self.job_id,
                            )
                            return False

                        session.commit()

                        self.last_known_locked_until = renewed_locked_until
                        self.consecutive_transient_failures = 0
                        self.last_transient_error = None
                        self.successful_renewals += 1
                        if renewed_scan_status in ("canceled", "superseded"):
                            self.scan_cancel_event.set()

                    logger.debug(
                        "Heartbeat extended lease for job %s until %s (worker: %s)",
                        self.job_id,
                        self.last_known_locked_until,
                        self.worker_id,
                    )
                    return True
            except (JobOwnershipError, JobInvalidStateError, JobNotFoundError) as exc:
                with self._lock:
                    self.lost_ownership = True
                sanitized = sanitize_failure_message(str(exc))
                logger.warning(
                    "Worker %s lost ownership of job %s during lease renewal: %s",
                    self.worker_id,
                    self.job_id,
                    sanitized,
                )
                return False
            except Exception as exc:  # noqa: BLE001 - keep heartbeat alive across transient DB errors
                with self._lock:
                    self.consecutive_transient_failures += 1
                    self.last_transient_error = sanitize_failure_message(str(exc))
                logger.warning(
                    "Worker %s encountered transient error renewing lease for job %s (failure count: %d): %s",
                    self.worker_id,
                    self.job_id,
                    self.consecutive_transient_failures,
                    self.last_transient_error,
                )
                return True
            finally:
                with self._lock:
                    self._in_flight = False

    def _run_heartbeat(self) -> None:
        """Background loop executing periodic lease renewal."""
        while not self._stop_event.is_set():
            # Wait for interval_sec or until signaled to stop
            if self._stop_event.wait(self.interval_sec):
                break

            # If worker is shutting down or signaled to stop, exit cleanly
            if self.worker_stop_event is not None and self.worker_stop_event.is_set():
                break

            should_continue = self.renew_once()
            if not should_continue:
                break

    def start(self) -> None:
        """Start the background heartbeat thread."""
        self._thread = threading.Thread(
            target=self._run_heartbeat,
            name=f"heartbeat-{self.job_id}-{self.worker_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float | None = None) -> bool:
        """Signal the heartbeat thread to stop and wait for it to cleanly terminate.

        Synchronizes with renew_once(): boundedly acquires _lock so that if a renewal
        commit is actively executing, that critical section finishes before shutdown
        establishes its boundary. If shutdown wins the lock first, _stop_event is set so
        that renew_once() safely aborts and rolls back.

        Returns:
            True if heartbeat cleanly terminated within timeout, False if it timed out.
        """
        start_mono = time.monotonic()
        effective_timeout = timeout if timeout is not None else self.shutdown_timeout_sec

        lock_acquired = self._lock.acquire(timeout=effective_timeout)
        if lock_acquired:
            try:
                self._stop_event.set()
            finally:
                self._lock.release()
        else:
            self._stop_event.set()

        elapsed = time.monotonic() - start_mono
        remaining_timeout = max(0.0, effective_timeout - elapsed)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=remaining_timeout)

        with self._lock:
            self.clean_shutdown = self._thread is None or not self._thread.is_alive()
            if not self.clean_shutdown:
                logger.critical(
                    "Worker %s heartbeat thread for job %s failed to terminate within %.1fs timeout (is_alive=%s, in_flight=%s)",
                    self.worker_id,
                    self.job_id,
                    effective_timeout,
                    self.is_alive,
                    self._in_flight,
                )
            return self.clean_shutdown

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.stop()


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
        heartbeat_interval_sec: float | None = None,
        reaper_interval_sec: float | None = None,
        heartbeat_shutdown_timeout_sec: float | None = None,
        github_client_factory: Callable[[], GitHubAppClient] | None = None,
    ) -> None:
        self.session_factory = session_factory or get_session_factory()
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:12]}"
        self.scanner: ScannerInterface = scanner or DefaultScannerEngine()
        self._github_client_factory = github_client_factory
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

        if heartbeat_shutdown_timeout_sec is not None:
            if (
                isinstance(heartbeat_shutdown_timeout_sec, bool)
                or not isinstance(heartbeat_shutdown_timeout_sec, (int, float))
                or heartbeat_shutdown_timeout_sec <= 0
            ):
                raise ValueError("heartbeat_shutdown_timeout_sec must be a positive number")
            self.heartbeat_shutdown_timeout_sec = float(heartbeat_shutdown_timeout_sec)
        else:
            self.heartbeat_shutdown_timeout_sec = 2.0

        # Validation for worker queue lease and heartbeat parameters
        if (
            isinstance(self.lease_duration_sec, bool)
            or not isinstance(self.lease_duration_sec, int)
            or self.lease_duration_sec <= 0
        ):
            raise ValueError("lease_duration_sec must be a positive integer")

        if heartbeat_interval_sec is not None:
            if (
                isinstance(heartbeat_interval_sec, bool)
                or not isinstance(heartbeat_interval_sec, (int, float))
                or heartbeat_interval_sec <= 0
            ):
                raise ValueError("heartbeat_interval_sec must be a positive number")
            self.heartbeat_interval_sec = float(heartbeat_interval_sec)
        elif self.lease_duration_sec < settings.WORKER_HEARTBEAT_SEC:
            # Scale down heartbeat interval to remain strictly less than lease duration
            self.heartbeat_interval_sec = max(0.1, float(self.lease_duration_sec) / 3.0)
        else:
            self.heartbeat_interval_sec = float(settings.WORKER_HEARTBEAT_SEC)

        if self.heartbeat_interval_sec >= self.lease_duration_sec:
            raise ValueError(
                f"heartbeat_interval_sec ({self.heartbeat_interval_sec}) must be strictly less "
                f"than lease_duration_sec ({self.lease_duration_sec})"
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
        initial_locked_until: datetime | None = None

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

            if job.scan is not None and job.scan.status in ("canceled", "superseded"):
                logger.info(
                    "Job %s skipped scanner execution because scan %s is already '%s'",
                    job_id,
                    job.scan.id,
                    job.scan.status,
                )
                return self._finalize_canceled_scan_job(
                    session=session,
                    job_id=job_id,
                    scan_status=job.scan.status,
                    current_time=start_time,
                )

            job_type = job.type
            raw_payload = job.payload
            initial_locked_until = job.locked_until

            if job_type == "github_pr_scan":
                try:
                    pr_payload_check = validate_github_pr_scan_payload(raw_payload)
                except PayloadValidationError:
                    pr_payload_check = None
                if pr_payload_check is not None:
                    scan_obj = job.scan
                    proj_obj = scan_obj.project if scan_obj is not None else None
                    inst_obj = proj_obj.installation if proj_obj is not None else None
                    if (
                        scan_obj is None
                        or proj_obj is None
                        or proj_obj.kind != "github"
                        or proj_obj.deleted_at is not None
                        or proj_obj.status != "active"
                    ):
                        fail_time = completion_now or start_time
                        return fail_job(
                            session,
                            job_id=job_id,
                            worker_id=self.worker_id,
                            error_message="Target GitHub project is no longer active",
                            error_code="PROJECT_INACTIVE",
                            retryable=False,
                            now=fail_time,
                            auto_commit=True,
                        )
                    if (
                        inst_obj is None
                        or inst_obj.status != "active"
                        or inst_obj.installation_id != pr_payload_check.installation_id
                        or proj_obj.github_repo_id != pr_payload_check.github_repo_id
                    ):
                        fail_time = completion_now or start_time
                        return fail_job(
                            session,
                            job_id=job_id,
                            worker_id=self.worker_id,
                            error_message="GitHub installation or repository mapping is inactive or mismatched",
                            error_code="INSTALLATION_INACTIVE",
                            retryable=False,
                            now=fail_time,
                            auto_commit=True,
                        )

        # Phase 1.1: Validate supported job type and payload structure
        manual_payload: ScanJobPayload | None = None
        pr_payload: GitHubPRScanJobPayload | None = None
        try:
            if job_type == "scan":
                manual_payload = validate_scan_payload(raw_payload)
            elif job_type == "github_pr_scan":
                pr_payload = validate_github_pr_scan_payload(raw_payload)
            else:
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
        # Scoped background heartbeat periodically renews the lease for long-running scans
        scan_result: ScanExecutionResult
        pr_files_summary: list[dict[str, Any]] | None = None
        scan_cancel_event = threading.Event()
        heartbeat = JobHeartbeat(
            session_factory=self.session_factory,
            job_id=job_id,
            worker_id=self.worker_id,
            interval_sec=self.heartbeat_interval_sec,
            lease_extension_sec=self.lease_duration_sec,
            initial_locked_until=initial_locked_until,
            worker_stop_event=self._stop_event,
            scan_cancel_event=scan_cancel_event,
            shutdown_timeout_sec=self.heartbeat_shutdown_timeout_sec,
        )
        try:
            with heartbeat:
                effective_payload = manual_payload
                early_result: ScanExecutionResult | None = None
                if pr_payload is not None:
                    (
                        effective_payload,
                        pr_files_summary,
                        early_result,
                    ) = self._build_pr_scan_input(
                        pr_payload,
                        cancel_event=scan_cancel_event,
                    )

                if early_result is not None:
                    scan_result = early_result
                else:
                    assert effective_payload is not None
                    if _scanner_supports_cancel_event(self.scanner):
                        scan_result = self.scanner.scan(  # type: ignore[call-arg]
                            effective_payload,
                            cancel_event=scan_cancel_event,
                        )
                    else:
                        scan_result = self.scanner.scan(effective_payload)
        except Exception as exc:  # noqa: BLE001 - catch unexpected scanner crashes to fail job
            # If heartbeat failed to terminate cleanly or renewal is in-flight, fail closed without updating DB
            if heartbeat.is_alive or heartbeat.is_renewal_in_flight or not heartbeat.clean_shutdown:
                logger.critical(
                    "Job %s scanner crashed but heartbeat thread failed to shut down cleanly (is_alive=%s, in_flight=%s, clean=%s); failing closed without updating job",
                    job_id,
                    heartbeat.is_alive,
                    heartbeat.is_renewal_in_flight,
                    heartbeat.clean_shutdown,
                )
                return None

            # If ownership was confirmed lost during scan, discard crash result
            if heartbeat.lost_ownership:
                logger.warning(
                    "Job %s scanner crashed after worker %s lost lease ownership; discarding stale error",
                    job_id,
                    self.worker_id,
                )
                return None
            if heartbeat.is_lease_uncertain(completion_now or utc_now()):
                logger.warning(
                    "Job %s scanner crashed with uncertain lease status on worker %s; discarding stale error",
                    job_id,
                    self.worker_id,
                )
                return None

            sanitized_exc = sanitize_failure_message(str(exc))
            logger.error("Job %s scanner execution raised error: %s", job_id, sanitized_exc)
            fail_time = completion_now or utc_now()
            crash_result = ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SCANNER_EXECUTION_ERROR",
                error_message=f"Scanner execution failed: {sanitized_exc}",
                retryable=False,
            )
            with session_scope(self.session_factory) as session:
                return self._handle_scan_result(
                    session=session,
                    job_id=job_id,
                    scan_result=crash_result,
                    current_time=fail_time,
                )

        finished_time = completion_now or utc_now()

        # If heartbeat failed to terminate cleanly or renewal is in-flight, fail closed without updating DB
        if heartbeat.is_alive or heartbeat.is_renewal_in_flight or not heartbeat.clean_shutdown:
            logger.critical(
                "Job %s scanner succeeded but heartbeat thread failed to shut down cleanly (is_alive=%s, in_flight=%s, clean=%s); failing closed without updating job",
                job_id,
                heartbeat.is_alive,
                heartbeat.is_renewal_in_flight,
                heartbeat.clean_shutdown,
            )
            return None

        # If ownership was confirmed lost during scanning, do NOT call complete_job or fail_job
        if heartbeat.lost_ownership:
            logger.warning(
                "Job %s lease ownership confirmed lost on worker %s; discarding scan results without updating job",
                job_id,
                self.worker_id,
            )
            return None

        # If heartbeat status is uncertain (repeated transient renewal failures and expired lease),
        # do not commit stale findings for safety
        if heartbeat.is_lease_uncertain(finished_time):
            logger.warning(
                "Job %s lease status is uncertain on worker %s due to renewal errors; discarding scan results for safety",
                job_id,
                self.worker_id,
            )
            return None

        # Phase 3: Route scanner outcome through existing lifecycle functions in a fresh session
        with session_scope(self.session_factory) as session:
            return self._handle_scan_result(
                session=session,
                job_id=job_id,
                scan_result=scan_result,
                current_time=finished_time,
                files_summary=pr_files_summary,
            )

    def _build_pr_scan_input(
        self,
        pr_payload: GitHubPRScanJobPayload,
        *,
        cancel_event: threading.Event,
    ) -> tuple[ScanJobPayload | None, list[dict[str, Any]], ScanExecutionResult | None]:
        """Fetch bounded PR changed files from GitHub outside database transactions."""
        files_summary: list[dict[str, Any]] = []
        scanned_files: list[ScannedFile] = []
        seen_casefold: set[str] = set()
        total_bytes = 0
        fetched_supported_count = 0

        try:
            client = (
                self._github_client_factory()
                if self._github_client_factory is not None
                else GitHubAppClient.from_settings(get_settings())
            )
            with client:
                changed_files = client.list_pull_request_files(
                    pr_payload.installation_id,
                    pr_payload.full_name,
                    pr_payload.pr_number,
                )

                if cancel_event.is_set() or self._stop_event.is_set():
                    return (
                        None,
                        files_summary,
                        ScanExecutionResult(
                            status=ScanStatus.FAILED,
                            error_code="SCAN_CANCELED",
                            error_message="Pull request scan aborted due to cancellation or worker shutdown",
                            retryable=False,
                        ),
                    )

                # Deterministic ordering while skipping removed files
                candidates: list[str] = []
                for entry in changed_files:
                    if entry.status == "removed":
                        continue
                    try:
                        normalized = normalize_and_validate_path(entry.filename)
                    except (ValueError, TypeError):
                        sanitized_bad_path = "".join(
                            ch if ord(ch) >= 32 and ch != "\x7f" else "_" for ch in entry.filename
                        )[:200]
                        files_summary.append(
                            {
                                "path": sanitized_bad_path,
                                "byte_size": 0,
                                "scanned": False,
                                "skip_reason": "invalid_path",
                            }
                        )
                        continue
                    cf = normalized.casefold()
                    if cf in seen_casefold:
                        continue
                    seen_casefold.add(cf)
                    candidates.append(normalized)

                for path in sorted(candidates):
                    if cancel_event.is_set() or self._stop_event.is_set():
                        return (
                            None,
                            files_summary,
                            ScanExecutionResult(
                                status=ScanStatus.FAILED,
                                error_code="SCAN_CANCELED",
                                error_message="Pull request scan aborted due to cancellation or worker shutdown",
                                retryable=False,
                            ),
                        )

                    if not is_extension_supported(path):
                        files_summary.append(
                            {
                                "path": path,
                                "byte_size": 0,
                                "scanned": False,
                                "skip_reason": "unsupported_extension",
                            }
                        )
                        continue

                    if fetched_supported_count >= MAX_FILES_COUNT or total_bytes >= MAX_TOTAL_BYTES:
                        files_summary.append(
                            {
                                "path": path,
                                "byte_size": 0,
                                "scanned": False,
                                "skip_reason": "batch_limit_exceeded",
                            }
                        )
                        continue

                    fetched_supported_count += 1
                    file_data = client.get_file_content(
                        pr_payload.installation_id,
                        pr_payload.full_name,
                        path,
                        pr_payload.head_sha,
                        max_bytes=MAX_FILE_BYTES,
                    )
                    if file_data.skip_reason is not None or file_data.content is None:
                        files_summary.append(
                            {
                                "path": path,
                                "byte_size": file_data.size,
                                "scanned": False,
                                "skip_reason": file_data.skip_reason or "unreadable_file",
                            }
                        )
                        continue

                    raw_bytes = file_data.content
                    if total_bytes + len(raw_bytes) > MAX_TOTAL_BYTES:
                        files_summary.append(
                            {
                                "path": path,
                                "byte_size": len(raw_bytes),
                                "scanned": False,
                                "skip_reason": "batch_limit_exceeded",
                            }
                        )
                        continue

                    if b"\x00" in raw_bytes:
                        files_summary.append(
                            {
                                "path": path,
                                "byte_size": len(raw_bytes),
                                "scanned": False,
                                "skip_reason": "binary_or_nul",
                            }
                        )
                        continue

                    try:
                        text_content = raw_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        files_summary.append(
                            {
                                "path": path,
                                "byte_size": len(raw_bytes),
                                "scanned": False,
                                "skip_reason": "binary_or_non_utf8",
                            }
                        )
                        continue

                    if is_minified_or_generated(text_content):
                        files_summary.append(
                            {
                                "path": path,
                                "byte_size": len(raw_bytes),
                                "scanned": False,
                                "skip_reason": "minified_or_generated",
                            }
                        )
                        continue

                    total_bytes += len(raw_bytes)
                    files_summary.append(
                        {
                            "path": path,
                            "byte_size": len(raw_bytes),
                            "scanned": True,
                            "skip_reason": None,
                        }
                    )
                    scanned_files.append(
                        ScannedFile(
                            path=path,
                            content=text_content,
                            scanned=True,
                            skip_reason=None,
                        )
                    )
        except GitHubRateLimitError as exc:
            safe_delay = (
                exc.retry_after_sec
                if exc.retry_after_sec is not None and exc.retry_after_sec > 0
                else None
            )
            return (
                None,
                files_summary,
                ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code=exc.error_code,
                    error_message=sanitize_failure_message(str(exc)),
                    retryable=True,
                    retry_delay_sec=safe_delay,
                ),
            )
        except GitHubClientError as exc:
            return (
                None,
                files_summary,
                ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code=exc.error_code,
                    error_message=sanitize_failure_message(str(exc)),
                    retryable=exc.retryable,
                ),
            )

        if not scanned_files:
            return (
                None,
                files_summary,
                ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    findings=[],
                    counts={
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                    },
                    components={
                        "github_fetch": {
                            "status": "skipped_empty",
                            "files_examined": len(files_summary),
                        }
                    },
                ),
            )

        return (
            ScanJobPayload(files=scanned_files, run_ai=pr_payload.run_ai),
            files_summary,
            None,
        )

    def _finalize_canceled_scan_job(
        self,
        *,
        session: Session,
        job_id: uuid.UUID,
        scan_status: str,
        current_time: datetime,
    ) -> Job:
        """Release a claimed job whose scan was canceled/superseded without overwriting scan state."""
        stmt = (
            update(Job)
            .where(
                Job.id == job_id,
                Job.status == "running",
                Job.locked_by == self.worker_id,
                Job.locked_until >= current_time,
            )
            .values(
                status="failed",
                locked_by=None,
                locked_until=None,
                payload=None,
                last_error=sanitize_failure_message(
                    f"Aborted job because scan status is '{scan_status}'"
                ),
                updated_at=current_time,
            )
            .returning(Job)
            .execution_options(synchronize_session="fetch")
        )
        finalized = session.scalars(stmt).first()
        if finalized is None:
            raise JobInvalidStateError(
                f"Job '{job_id}' could not be finalized after scan cancellation due to concurrent state change"
            )
        session.commit()
        return finalized

    def _handle_scan_result(
        self,
        *,
        session: Session,
        job_id: uuid.UUID,
        scan_result: ScanExecutionResult,
        current_time: datetime,
        files_summary: list[dict[str, Any]] | None = None,
    ) -> Job:
        """Route the structured scanner execution result to job and scan state."""
        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            existing_job = session.scalar(select(Job).where(Job.id == job_id).with_for_update())
            locked_scan = (
                session.scalar(
                    select(Scan).where(Scan.id == existing_job.scan_id).with_for_update()
                )
                if existing_job is not None and existing_job.scan_id is not None
                else None
            )
        else:
            existing_job = session.get(Job, job_id)
            locked_scan = (
                session.get(Scan, existing_job.scan_id)
                if existing_job is not None and existing_job.scan_id is not None
                else None
            )

        if locked_scan is not None and locked_scan.status in ("canceled", "superseded"):
            logger.info(
                "Job %s discarding scanner results because scan %s is '%s'",
                job_id,
                locked_scan.id,
                locked_scan.status,
            )
            return self._finalize_canceled_scan_job(
                session=session,
                job_id=job_id,
                scan_status=locked_scan.status,
                current_time=current_time,
            )

        if scan_result.status in (ScanStatus.SUCCEEDED, ScanStatus.PARTIAL):
            scan_terminal_status = (
                "succeeded" if scan_result.status == ScanStatus.SUCCEEDED else "partial"
            )
            try:
                # 1. Fetch Job to extract associated Scan and Project IDs
                job = session.get(Job, job_id)
                if job is None:
                    raise JobNotFoundError(f"Job '{job_id}' does not exist")
                if job.scan is None:
                    raise JobInvalidStateError(f"Job '{job_id}' has no associated scan")

                # 2. Persist findings prior to job completion if findings are present
                persisted_counts: dict[str, int] | None = None
                if scan_result.findings:
                    persistence_result = persist_scan_findings(
                        session=session,
                        project_id=job.scan.project_id,
                        scan_id=job.scan.id,
                        findings=scan_result.findings,
                        now=current_time,
                        auto_commit=False,
                    )
                    persisted_counts = persistence_result.counts

                # 3. Transition job and scan state in the same transaction
                completed_job = complete_job(
                    session,
                    job_id=job_id,
                    worker_id=self.worker_id,
                    scan_status=scan_terminal_status,
                    now=current_time,
                    null_payload=True,
                    auto_commit=False,
                )

                if completed_job.scan is not None:
                    if files_summary is not None:
                        completed_job.scan.files_summary = files_summary
                    if scan_result.components is not None:
                        completed_job.scan.components = scan_result.components

                    # Reconcile counts:
                    # - If findings were persisted, use severity counts (merged with non-severity keys from scan_result.counts)
                    # - Else if scan_result.counts was provided (e.g. by mock engines or zero findings), preserve it
                    # - Else default to standard 5-level severity breakdown
                    if persisted_counts is not None:
                        merged_counts = dict(scan_result.counts or {})
                        merged_counts.update(persisted_counts)
                        completed_job.scan.counts = merged_counts
                    elif scan_result.counts is not None:
                        completed_job.scan.counts = scan_result.counts
                    else:
                        completed_job.scan.counts = {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                            "info": 0,
                        }

                    if scan_result.status == ScanStatus.PARTIAL:
                        if scan_result.error_code is not None:
                            completed_job.scan.error_code = scan_result.error_code
                        if scan_result.error_message is not None:
                            completed_job.scan.error_message = sanitize_failure_message(
                                scan_result.error_message
                            )

                # 4. Atomically commit finding rows, scan counts, and completion status
                session.commit()
                if scan_result.status == ScanStatus.SUCCEEDED:
                    logger.info("Job %s completed successfully", job_id)
                else:
                    logger.warning("Job %s completed with partial results", job_id)
                return completed_job

            except (JobOwnershipError, JobInvalidStateError, JobNotFoundError):
                session.rollback()
                raise
            except Exception as exc:  # noqa: BLE001 - catch unexpected finding persistence or completion errors
                session.rollback()
                sanitized_exc = sanitize_failure_message(str(exc))
                logger.error(
                    "Job %s failed during finding persistence or completion: %s",
                    job_id,
                    sanitized_exc,
                )
                with session_scope(self.session_factory) as fail_session:
                    check_job = fail_session.get(Job, job_id)
                    if (
                        check_job is not None
                        and check_job.scan is not None
                        and check_job.scan.status in ("canceled", "superseded")
                    ):
                        return self._finalize_canceled_scan_job(
                            session=fail_session,
                            job_id=job_id,
                            scan_status=check_job.scan.status,
                            current_time=current_time,
                        )
                    return fail_job(
                        fail_session,
                        job_id=job_id,
                        worker_id=self.worker_id,
                        error_message=f"Finding persistence failed: {sanitized_exc}",
                        error_code="FINDING_PERSISTENCE_ERROR",
                        retryable=False,
                        now=current_time,
                        auto_commit=True,
                    )

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
