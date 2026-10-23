"""Application-layer service for transactional scan-job creation and query.

Implements Blueprint Section 7 (Workflow A: Manual code analysis), Section 8.1
(Database models and constraints), Section 9.3 (Scans API contracts), and Threat
Mitigations T8 (Path safety) & T9 (Size limits and minified-file checks).
"""

from __future__ import annotations

import uuid
from pathlib import PurePosixPath
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import Job, Project, Scan, User
from app.domain.paths import normalize_and_validate_path
from app.schemas.scan import ManualFileInput

# Size and quantity boundaries (Workflow A)
MAX_FILES_COUNT: int = 20
MAX_FILE_BYTES: int = 200 * 1024  # 200 KB = 204,800 bytes
MAX_TOTAL_BYTES: int = 1024 * 1024  # 1 MB = 1,048,576 bytes
MAX_LINE_LENGTH: int = 5000  # Lines > 5000 chars are skipped as minified/generated

# Supported extension sets (Workflow A)
SEMGREP_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
)
SECRET_ONLY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".env",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".properties",
        ".sh",
        ".txt",
    }
)
ALL_SUPPORTED_EXTENSIONS: frozenset[str] = SEMGREP_EXTENSIONS | SECRET_ONLY_EXTENSIONS


class ScanServiceError(Exception):
    """Base exception for scan service operations."""


class ScanValidationError(ScanServiceError):
    """Raised when scan request validation fails (maps to HTTP 422)."""


class ScanPayloadTooLargeError(ScanServiceError):
    """Raised when file or batch size exceeds maximum allowed limits (maps to HTTP 413)."""


class ProjectNotFoundError(ScanServiceError):
    """Raised when referenced project does not exist (maps to HTTP 404)."""


class UserNotFoundError(ScanServiceError):
    """Raised when referenced user does not exist (maps to HTTP 404)."""


class ScanConflictError(ScanServiceError):
    """Raised when a uniqueness conflict occurs, e.g. duplicate trigger_key (maps to HTTP 409)."""


class ScanNotFoundError(ScanServiceError):
    """Raised when requested scan cannot be found (maps to HTTP 404)."""


def is_extension_supported(path: str) -> bool:
    """Check whether a relative file path has a supported extension for scanning.

    Supports Semgrep languages (.py, .js, .ts, etc.), secret scanning extensions
    (.json, .yaml, .toml, .txt, etc.), and dotfiles such as '.env' and '.env.*'.
    """
    p = PurePosixPath(path)
    name_lower = p.name.lower()
    suffix_lower = p.suffix.lower()

    return (
        suffix_lower in ALL_SUPPORTED_EXTENSIONS
        or name_lower == ".env"
        or name_lower.startswith(".env.")
    )


def is_minified_or_generated(content: str) -> bool:
    """Check if content has any single line exceeding the 5,000 character limit."""
    for line in content.splitlines():
        if len(line) > MAX_LINE_LENGTH:
            return True
    return False


def validate_manual_scan_files(
    files: list[ManualFileInput],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate and classify manual scan files according to Workflow A rules.

    Args:
        files: List of file objects containing 'path' and 'content'.

    Returns:
        Tuple of (files_summary, payload_files):
        - files_summary: List of metadata dicts for Scan.files_summary (path, byte_size, scanned, skip_reason).
        - payload_files: List of dicts for Job.payload (path, content, scanned, skip_reason).

    Raises:
        ScanValidationError: If file count, path safety, case-folded uniqueness, or NUL bytes are violated.
        ScanPayloadTooLargeError: If individual file > 200 KB or total payload > 1 MB.
    """
    if len(files) == 0:
        raise ScanValidationError("At least one file must be provided for manual analysis")

    if len(files) > MAX_FILES_COUNT:
        raise ScanValidationError(
            f"Cannot submit more than {MAX_FILES_COUNT} files in a single batch (got {len(files)})"
        )

    total_bytes = 0
    seen_casefold_paths: set[str] = set()
    files_summary: list[dict[str, Any]] = []
    payload_files: list[dict[str, Any]] = []

    for file_input in files:
        # 1. Reject NUL bytes in content
        if "\x00" in file_input.content:
            raise ScanValidationError(
                f"File content for '{file_input.path}' contains invalid NUL bytes"
            )

        # 2. Check individual file byte size
        encoded_bytes = file_input.content.encode("utf-8")
        byte_size = len(encoded_bytes)
        if byte_size > MAX_FILE_BYTES:
            raise ScanPayloadTooLargeError(
                f"File '{file_input.path}' exceeds maximum allowed size of 200 KB ({byte_size} bytes)"
            )
        total_bytes += byte_size

        # 3. Path normalization & safety checks
        try:
            normalized_path = normalize_and_validate_path(file_input.path)
        except (ValueError, TypeError) as exc:
            raise ScanValidationError(f"Invalid file path '{file_input.path}': {exc}") from exc

        # 4. Enforce case-folded path uniqueness within the batch
        casefold_path = normalized_path.casefold()
        if casefold_path in seen_casefold_paths:
            raise ScanValidationError(
                f"Duplicate file path '{file_input.path}' after case-folding normalization"
            )
        seen_casefold_paths.add(casefold_path)

        # 5. Extension allowlist and minification classification
        scanned: bool
        skip_reason: str | None

        if not is_extension_supported(normalized_path):
            scanned = False
            skip_reason = "unsupported_extension"
        elif is_minified_or_generated(file_input.content):
            scanned = False
            skip_reason = "minified_or_generated"
        else:
            scanned = True
            skip_reason = None

        summary_entry: dict[str, Any] = {
            "path": normalized_path,
            "byte_size": byte_size,
            "scanned": scanned,
            "skip_reason": skip_reason,
        }
        files_summary.append(summary_entry)

        payload_entry: dict[str, Any] = {
            "path": normalized_path,
            "content": file_input.content,
            "scanned": scanned,
            "skip_reason": skip_reason,
        }
        payload_files.append(payload_entry)

    # 6. Check total batch size limit
    if total_bytes > MAX_TOTAL_BYTES:
        raise ScanPayloadTooLargeError(
            f"Total payload size exceeds maximum limit of 1 MB ({total_bytes} bytes)"
        )

    return files_summary, payload_files


def _is_trigger_key_conflict(exc: IntegrityError) -> bool:
    """Determine whether an IntegrityError specifically stems from uq_scans_project_trigger."""
    err_msg = str(exc.orig if hasattr(exc, "orig") else exc).lower()
    if "uq_scans_project_trigger" in err_msg:
        return True
    return "unique" in err_msg and "trigger_key" in err_msg


def _is_foreign_key_violation(exc: IntegrityError) -> bool:
    """Determine whether an IntegrityError stems from a foreign key constraint failure."""
    err_msg = str(exc.orig if hasattr(exc, "orig") else exc).lower()
    return "foreign key" in err_msg or "foreignkey" in err_msg


def create_scan_and_job(
    session: Session,
    *,
    project_id: uuid.UUID,
    files_summary: list[dict[str, Any]],
    payload_files: list[dict[str, Any]],
    run_ai: bool = True,
    trigger: str = "manual",
    trigger_key: str | None = None,
    created_by_user_id: uuid.UUID | None = None,
    auto_commit: bool = False,
) -> tuple[Scan, Job]:
    """Atomically stage and flush a Scan and its associated persistent Job.

    When auto_commit=False (the default for route handlers managed by get_db_session
    or session_scope), stages both entities and flushes them to the session. If flush
    fails (e.g. uniqueness or foreign key conflict), this function rolls back the failed
    flush so the session returns to a safe, clean state. The outer caller owns final
    transaction commit or outer rollback.
    When auto_commit=True, this function commits the transaction immediately.

    Args:
        session: Active SQLAlchemy database session.
        project_id: UUID of the target project.
        files_summary: Metadata summary of files for Scan.files_summary.
        payload_files: Content payload to store in Job.payload.
        run_ai: Whether AI review is enabled.
        trigger: Trigger category ('manual', 'pull_request', 'rerun').
        trigger_key: Unique trigger key. If None, a new UUID-based key is generated.
        created_by_user_id: Optional UUID of user who initiated the scan.
        auto_commit: If True, commits the transaction before returning.

    Returns:
        Tuple of (scan, job) newly created instances.

    Raises:
        ProjectNotFoundError: If project_id does not exist.
        UserNotFoundError: If created_by_user_id is supplied but does not exist.
        ScanConflictError: If (project_id, trigger_key) violates unique constraint.
        ScanServiceError: If database integrity or unexpected error occurs.
    """
    # 1. Validate project existence
    project = session.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(f"Project with ID '{project_id}' does not exist")

    # 2. Validate user existence if provided
    if created_by_user_id is not None:
        user = session.get(User, created_by_user_id)
        if user is None:
            raise UserNotFoundError(f"User with ID '{created_by_user_id}' does not exist")

    # 3. Determine unique trigger key
    effective_trigger_key = trigger_key or f"{trigger}-{uuid.uuid4()}"

    # 4. Instantiate Scan and Job entities
    scan = Scan(
        project_id=project_id,
        created_by_user_id=created_by_user_id,
        trigger=trigger,
        trigger_key=effective_trigger_key,
        status="queued",
        report_status="not_applicable",
        files_summary=files_summary,
    )

    job = Job(
        scan=scan,
        type="scan",
        status="queued",
        attempts=0,
        max_attempts=3,
        payload={
            "files": payload_files,
            "run_ai": run_ai,
        },
    )
    # 5. Atomically stage both entities and flush
    try:
        session.add(scan)
        session.add(job)
        session.flush()
        if auto_commit:
            session.commit()
    except IntegrityError as exc:
        session.rollback()
        if _is_trigger_key_conflict(exc):
            raise ScanConflictError(
                f"A scan with trigger key '{effective_trigger_key}' already exists for project '{project_id}'"
            ) from exc
        if _is_foreign_key_violation(exc):
            raise ScanValidationError(
                "Foreign key constraint violation: referenced project or user does not exist"
            ) from exc
        raise ScanServiceError("Database integrity error creating scan and job") from exc
    except Exception as exc:
        session.rollback()
        raise ScanServiceError("Unexpected database error creating scan and job") from exc

    return scan, job


def create_manual_scan(
    session: Session,
    *,
    project_id: uuid.UUID,
    files: list[ManualFileInput],
    run_ai: bool = True,
    trigger_key: str | None = None,
    created_by_user_id: uuid.UUID | None = None,
    auto_commit: bool = False,
) -> tuple[Scan, Job]:
    """Validate files and create a manual scan with an enqueued background job.

    Enforces all Workflow A validation rules and guarantees single-transaction
    persistence of the Scan and Job rows. Never invokes scanners directly.
    """
    files_summary, payload_files = validate_manual_scan_files(files)
    return create_scan_and_job(
        session=session,
        project_id=project_id,
        files_summary=files_summary,
        payload_files=payload_files,
        run_ai=run_ai,
        trigger="manual",
        trigger_key=trigger_key,
        created_by_user_id=created_by_user_id,
        auto_commit=auto_commit,
    )


def get_scan(session: Session, scan_id: uuid.UUID) -> Scan | None:
    """Retrieve an ORM Scan instance by its primary key ID."""
    return session.get(Scan, scan_id)
