"""Application-layer service for persistent finding identity, deduplication, and lifecycle transitions.

Implements:
- Blueprint Section 7 (Workflow C: Finding review & lifecycle persistence)
- Blueprint Section 8.1 (findings, scan_findings, and finding_status_history models)
- Blueprint Section 10.5 (Canonical Finding Schema preservation)
- Blueprint Section 10.6 (Deterministic v1 fingerprint identity & deduplication across scans)
- Threat Mitigations T3 (Zero-secret disclosure & redaction) & T13 (Worker concurrency)
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models.finding import Finding, FindingStatusHistory
from app.db.models.scan import Scan, ScanFinding
from app.domain.findings import CanonicalFinding
from app.services.job_service import _normalize_datetime, sanitize_failure_message

logger = logging.getLogger("sentinel.services.finding")


class FindingServiceError(Exception):
    """Base exception for finding service operations."""


class ScanNotFoundError(FindingServiceError):
    """Raised when the specified scan does not exist."""


class ProjectMismatchError(FindingServiceError):
    """Raised when a scan does not belong to the supplied project ID."""


class FindingPersistenceError(FindingServiceError):
    """Raised when a database or integrity error occurs during finding persistence."""


@dataclass(frozen=True)
class PersistedFindingsResult:
    """Outcome summary for a persisted scan finding batch."""

    findings: list[Finding]
    scan_findings: list[ScanFinding]
    counts: dict[str, int]
    new_count: int
    recurring_count: int
    reopened_count: int


def _empty_severity_counts() -> dict[str, int]:
    """Initialize standard 5-level severity count breakdown matching Blueprint Section 9.3."""
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def persist_scan_findings(
    session: Session,
    *,
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    findings: Sequence[CanonicalFinding | dict[str, Any]] | None,
    now: datetime | None = None,
    auto_commit: bool = False,
) -> PersistedFindingsResult:
    """Atomically ingest and link canonical findings to a scan within a project.

    Deduplication & Lifecycle Rules (Blueprint Section 7 Workflow C & Section 10.6):
    1. Scan Verification: Ensures the target scan exists and belongs to project_id.
    2. Identity Deduplication: Canonical findings are identified by (project_id, fingerprint).
       Duplicate fingerprints within the same batch are deduplicated, keeping the first occurrence.
    3. New Findings: Persisted with status='open', first_seen_scan_id=scan_id, last_seen_scan_id=scan_id.
    4. Recurring Findings:
       - If status in ('accepted', 'dismissed', 'false_positive'): user decision is strictly preserved.
       - If status == 'fixed': automatically reopened to 'open' with actor_type='system' and an
         audit record appended to finding_status_history.
       - If status == 'open': remains 'open' with no redundant audit log entries.
       - last_seen_scan_id and last_seen_at are refreshed to current scan metadata.
    5. Per-Scan Observations: A ScanFinding row is inserted for every finding in this scan,
       capturing observation evidence (lines, snippet, severity, confidence, verification_status,
       remediation, references, and sanitized raw metadata).
    6. Concurrency Safety: Employs row locks where supported and savepoint-wrapped inserts to
       safely handle concurrent scans attempting to insert identical fingerprints.
    7. Severity Breakdown: Computes aggregate severity breakdown and updates scan.counts.

    Args:
        session: Active SQLAlchemy database session.
        project_id: UUID of the project owning the scan.
        scan_id: UUID of the current scan run.
        findings: Sequence of CanonicalFinding models or compatible dictionaries.
        now: Reference timestamp for state transitions. Defaults to utc_now().
        auto_commit: If True, commits the transaction before returning. Default False.

    Returns:
        PersistedFindingsResult containing the updated Finding and ScanFinding entities,
        severity count breakdown, and transition counts.

    Raises:
        ScanNotFoundError: If scan_id does not exist in the database.
        ProjectMismatchError: If scan_id does not belong to project_id.
        FindingPersistenceError: If an unhandled database error occurs.
    """
    if not isinstance(project_id, uuid.UUID):
        raise TypeError(f"project_id must be a UUID, got {type(project_id).__name__}")
    if not isinstance(scan_id, uuid.UUID):
        raise TypeError(f"scan_id must be a UUID, got {type(scan_id).__name__}")

    current_time = _normalize_datetime(now) or utc_now()

    # 1. Validate scan existence and project association
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError(f"Scan with ID '{scan_id}' not found")
    if scan.project_id != project_id:
        raise ProjectMismatchError(
            f"Scan '{scan_id}' belongs to project '{scan.project_id}', not '{project_id}'"
        )

    # 2. Parse, normalize, and batch-deduplicate incoming canonical findings
    canonical_items: list[CanonicalFinding] = []
    if findings:
        for idx, item in enumerate(findings):
            if isinstance(item, CanonicalFinding):
                canonical_items.append(item)
            elif isinstance(item, dict):
                try:
                    canonical_items.append(CanonicalFinding.model_validate(item))
                except Exception as err:
                    raise ValueError(
                        f"Invalid canonical finding payload at index {idx}: {err}"
                    ) from err
            else:
                raise TypeError(
                    f"Finding at index {idx} must be a CanonicalFinding or dict, got {type(item).__name__}"
                )

    # In-batch deduplication: unique constraint uq_scan_findings_scan_finding forbids duplicate
    # (scan_id, finding_id) in the same scan run.
    unique_canonical: list[CanonicalFinding] = []
    seen_fps: set[str] = set()
    for item in canonical_items:
        if item.fingerprint in seen_fps:
            logger.warning(
                "Duplicate finding fingerprint '%s' in scan %s; deduplicating",
                item.fingerprint,
                scan_id,
            )
            continue
        seen_fps.add(item.fingerprint)
        unique_canonical.append(item)

    # Fast path: scan completed with zero findings
    if not unique_canonical:
        counts = _empty_severity_counts()
        if scan.counts is None:
            scan.counts = counts
        if auto_commit:
            session.commit()
        else:
            session.flush()
        return PersistedFindingsResult(
            findings=[],
            scan_findings=[],
            counts=counts,
            new_count=0,
            recurring_count=0,
            reopened_count=0,
        )

    fingerprints = [f.fingerprint for f in unique_canonical]

    try:
        # 3. Query existing persistent findings for this project with row locks on PostgreSQL
        stmt = select(Finding).where(
            Finding.project_id == project_id,
            Finding.fingerprint.in_(fingerprints),
        )
        bind = session.get_bind()
        if bind is not None and getattr(bind.dialect, "name", "") == "postgresql":
            stmt = stmt.with_for_update()

        existing_findings_map: dict[str, Finding] = {
            f.fingerprint: f for f in session.scalars(stmt).all()
        }

        persisted_findings: list[Finding] = []
        created_scan_findings: list[ScanFinding] = []
        new_count = 0
        recurring_count = 0
        reopened_count = 0

        # 4. Upsert persistent findings and prepare scan observations
        for canonical in unique_canonical:
            finding: Finding
            fp = canonical.fingerprint

            if fp in existing_findings_map:
                finding = existing_findings_map[fp]
                recurring_count += 1

                # Refresh last seen metadata
                finding.last_seen_scan_id = scan_id
                finding.last_seen_at = current_time

                # Check for recurring 'fixed' finding: auto-reopen to 'open' with system audit trail
                if finding.status == "fixed":
                    finding.status = "open"
                    finding.status_reason = "Reopened by system: finding re-observed in scan"
                    finding.status_updated_at = current_time
                    finding.status_updated_by = None
                    reopened_count += 1

                    history = FindingStatusHistory(
                        id=uuid.uuid4(),
                        finding_id=finding.id,
                        from_status="fixed",
                        to_status="open",
                        actor_type="system",
                        actor_user_id=None,
                        reason="Reopened by system: finding re-observed in scan",
                        scan_id=scan_id,
                        created_at=current_time,
                    )
                    session.add(history)
                # Note: 'accepted', 'dismissed', 'false_positive' statuses are strictly preserved.
                # No audit history row is appended when status does not change.
            else:
                # Novel finding: create new persistent identity
                new_finding = Finding(
                    id=uuid.uuid4(),
                    project_id=project_id,
                    fingerprint=fp,
                    rule_id=canonical.rule_id,
                    source=canonical.source.value
                    if hasattr(canonical.source, "value")
                    else str(canonical.source),
                    category=canonical.category.value
                    if hasattr(canonical.category, "value")
                    else str(canonical.category),
                    title=canonical.title,
                    file_path=canonical.file_path,
                    status="open",
                    status_reason=None,
                    status_updated_at=None,
                    status_updated_by=None,
                    first_seen_scan_id=scan_id,
                    last_seen_scan_id=scan_id,
                    first_seen_at=current_time,
                    last_seen_at=current_time,
                    created_at=current_time,
                )

                # Concurrency-safe insert: use SAVEPOINT (begin_nested) to safely recover if
                # a concurrent scan already inserted the same (project_id, fingerprint).
                try:
                    with session.begin_nested():
                        session.add(new_finding)
                        session.flush()
                    finding = new_finding
                    new_count += 1
                except IntegrityError:
                    # Savepoint rolled back cleanly. Fetch the concurrently inserted finding:
                    reselect_stmt = select(Finding).where(
                        Finding.project_id == project_id,
                        Finding.fingerprint == fp,
                    )
                    if bind is not None and getattr(bind.dialect, "name", "") == "postgresql":
                        reselect_stmt = reselect_stmt.with_for_update()
                    finding = session.scalars(reselect_stmt).one()
                    recurring_count += 1

                    finding.last_seen_scan_id = scan_id
                    finding.last_seen_at = current_time
                    if finding.status == "fixed":
                        finding.status = "open"
                        finding.status_reason = "Reopened by system: finding re-observed in scan"
                        finding.status_updated_at = current_time
                        finding.status_updated_by = None
                        reopened_count += 1

                        history = FindingStatusHistory(
                            id=uuid.uuid4(),
                            finding_id=finding.id,
                            from_status="fixed",
                            to_status="open",
                            actor_type="system",
                            actor_user_id=None,
                            reason="Reopened by system: finding re-observed in scan",
                            scan_id=scan_id,
                            created_at=current_time,
                        )
                        session.add(history)

            persisted_findings.append(finding)

            # 5. Create per-scan finding observation (ScanFinding)
            references_data: list[dict[str, Any]] | None = (
                [ref.model_dump() for ref in canonical.references] if canonical.references else None
            )
            sources_data: list[dict[str, Any]] | None = (
                [src.model_dump() for src in canonical.sources] if canonical.sources else None
            )
            ai_data: dict[str, Any] | None = (
                canonical.ai_assessment.model_dump(exclude_none=True)
                if canonical.ai_assessment
                else None
            )

            scan_finding = ScanFinding(
                id=uuid.uuid4(),
                scan_id=scan_id,
                finding_id=finding.id,
                severity=canonical.severity.value
                if hasattr(canonical.severity, "value")
                else str(canonical.severity),
                confidence=canonical.confidence.value
                if hasattr(canonical.confidence, "value")
                else str(canonical.confidence),
                verification_status=canonical.verification_status.value
                if hasattr(canonical.verification_status, "value")
                else str(canonical.verification_status),
                start_line=canonical.start_line,
                end_line=canonical.end_line,
                snippet=canonical.snippet,
                snippet_start_line=canonical.snippet_start_line or canonical.start_line,
                in_diff=canonical.in_diff,
                description=canonical.description,
                remediation=canonical.remediation,
                references=references_data,
                sources=sources_data,
                ai_assessment=ai_data,
                raw=canonical.raw,
                created_at=current_time,
            )
            session.add(scan_finding)
            created_scan_findings.append(scan_finding)

        # 6. Compute observation counts by severity
        counts = _empty_severity_counts()
        for sf in created_scan_findings:
            if sf.severity in counts:
                counts[sf.severity] += 1
            else:
                counts[sf.severity] = 1

        # Synchronize scan.counts
        existing_counts = dict(scan.counts or {})
        existing_counts.update(counts)
        scan.counts = existing_counts

        # 7. Finalize persistence in session
        session.flush()
        if auto_commit:
            session.commit()

        logger.info(
            "Persisted %d scan findings for scan %s (new: %d, recurring: %d, reopened: %d)",
            len(created_scan_findings),
            scan_id,
            new_count,
            recurring_count,
            reopened_count,
        )

        return PersistedFindingsResult(
            findings=persisted_findings,
            scan_findings=created_scan_findings,
            counts=counts,
            new_count=new_count,
            recurring_count=recurring_count,
            reopened_count=reopened_count,
        )

    except (ScanNotFoundError, ProjectMismatchError, ValueError, TypeError):
        raise
    except SQLAlchemyError as exc:
        if auto_commit:
            session.rollback()
        sanitized = sanitize_failure_message(str(exc))
        raise FindingPersistenceError(
            f"Database error persisting scan findings: {sanitized}"
        ) from exc
    except Exception as exc:
        if auto_commit:
            session.rollback()
        sanitized = sanitize_failure_message(str(exc))
        raise FindingPersistenceError(
            f"Unexpected error persisting scan findings: {sanitized}"
        ) from exc


def get_finding(session: Session, finding_id: uuid.UUID) -> Finding | None:
    """Retrieve an ORM Finding instance by its unique primary key ID."""
    return session.get(Finding, finding_id)


def list_scan_findings(session: Session, scan_id: uuid.UUID) -> list[ScanFinding]:
    """Retrieve all observation instances linked to a specific scan run."""
    stmt = (
        select(ScanFinding)
        .where(ScanFinding.scan_id == scan_id)
        .order_by(ScanFinding.start_line.asc(), ScanFinding.id.asc())
    )
    return list(session.scalars(stmt).all())
