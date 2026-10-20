"""SQLAlchemy models for Scans, Background Jobs, and Scan Findings.

Blueprint Section 8.1:
- scans: one analysis run
- jobs: PostgreSQL queue mechanics claimed with FOR UPDATE SKIP LOCKED
- scan_findings: observation of a canonical finding in a particular scan run
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.observability import AIReview
    from app.db.models.project import Project


class Scan(Base, UUIDPrimaryKeyMixin):
    """An analysis run for a manual batch or pull request (Section 8.1)."""

    __tablename__ = "scans"
    __table_args__ = (
        sa.UniqueConstraint("project_id", "trigger_key", name="uq_scans_project_trigger"),
        sa.CheckConstraint(
            "trigger IN ('manual', 'pull_request', 'rerun')",
            name="ck_scans_trigger",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'partial', 'failed', "
            "'canceled', 'superseded', 'skipped')",
            name="ck_scans_status",
        ),
        sa.CheckConstraint(
            "report_status IN ('not_applicable', 'pending', 'published', 'failed')",
            name="ck_scans_report_status",
        ),
        sa.CheckConstraint(
            "head_sha IS NULL OR length(head_sha) = 40",
            name="ck_scans_head_sha_length",
        ),
        sa.Index("ix_scans_project_created", "project_id", "created_at"),
        sa.Index("ix_scans_project_pr_sha", "project_id", "pr_number", "head_sha"),
        sa.Index(
            "ix_scans_active_status",
            "status",
            postgresql_where=sa.text("status IN ('queued', 'running')"),
        ),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    trigger: Mapped[str] = mapped_column(sa.Text, nullable=False)
    trigger_key: Mapped[str] = mapped_column(sa.Text, nullable=False)
    pr_number: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    head_sha: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    base_sha: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    pr_title: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default="queued", server_default="queued"
    )
    error_code: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    components: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    files_summary: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONType, nullable=True)
    counts: Mapped[dict[str, int] | None] = mapped_column(JSONType, nullable=True)
    report_status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default="not_applicable", server_default="not_applicable"
    )
    report_error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    rerun_of: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    queued_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )
    started_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    duration_ms: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )

    # Relationships
    project: Mapped[Project] = relationship(back_populates="scans")
    job: Mapped[Job | None] = relationship(
        back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    scan_findings: Mapped[list[ScanFinding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    ai_review: Mapped[AIReview | None] = relationship(
        back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )


class Job(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """PostgreSQL queue mechanics claimed with FOR UPDATE SKIP LOCKED (Section 8.1 & 7)."""

    __tablename__ = "jobs"
    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'dead')",
            name="ck_jobs_status",
        ),
        sa.Index("ix_jobs_status_run_after", "status", "run_after"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    type: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default="scan", server_default="scan"
    )
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default="queued", server_default="queued"
    )
    attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    max_attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=3, server_default="3"
    )
    run_after: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )
    locked_by: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    payload: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSONType, nullable=True)
    last_error: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="job")


class ScanFinding(Base, UUIDPrimaryKeyMixin):
    """Observation of a finding in one specific scan (Section 8.1 & 10.5)."""

    __tablename__ = "scan_findings"
    __table_args__ = (
        sa.UniqueConstraint("scan_id", "finding_id", name="uq_scan_findings_scan_finding"),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_scan_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_scan_findings_confidence",
        ),
        sa.CheckConstraint(
            "verification_status IN ('scanner_detected', 'ai_corroborated', "
            "'ai_grounded', 'ai_unverified')",
            name="ck_scan_findings_verification_status",
        ),
        sa.Index("ix_scan_findings_scan_severity", "scan_id", "severity"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(sa.Text, nullable=False)
    confidence: Mapped[str] = mapped_column(sa.Text, nullable=False)
    verification_status: Mapped[str] = mapped_column(sa.Text, nullable=False)
    start_line: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    snippet: Mapped[str] = mapped_column(sa.Text, nullable=False)
    snippet_start_line: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    in_diff: Mapped[bool | None] = mapped_column(sa.Boolean, nullable=True)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    remediation: Mapped[str] = mapped_column(sa.Text, nullable=False)
    references: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONType, nullable=True)
    sources: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONType, nullable=True)
    ai_assessment: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="scan_findings")
    finding: Mapped[Finding] = relationship(back_populates="scan_findings")
