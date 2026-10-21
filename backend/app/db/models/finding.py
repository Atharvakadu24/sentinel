"""SQLAlchemy models for Persistent Findings and Finding Status History.

Blueprint Section 8.1:
- findings: persistent identity of an issue within a project across scans
- finding_status_history: append-only audit trail of finding lifecycle transitions
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, ORMExecuteState, Session, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.db.models.project import Project
    from app.db.models.scan import Scan, ScanFinding
    from app.db.models.user import User


class Finding(Base, UUIDPrimaryKeyMixin):
    """Persistent security finding identity across scans within a project (Section 8.1 & 10.6)."""

    __tablename__ = "findings"
    __table_args__ = (
        sa.UniqueConstraint("project_id", "fingerprint", name="uq_findings_project_fingerprint"),
        sa.CheckConstraint(
            "source IN ('semgrep', 'gitleaks', 'ai')",
            name="ck_findings_source",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'fixed', 'accepted', 'dismissed', 'false_positive')",
            name="ck_findings_status",
        ),
        sa.Index("ix_findings_project_status", "project_id", "status"),
        sa.Index("ix_findings_project_last_seen", "project_id", "last_seen_at"),
        sa.Index("ix_findings_project_file_path", "project_id", "file_path"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(sa.CHAR(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(sa.Text, nullable=False)
    source: Mapped[str] = mapped_column(sa.Text, nullable=False)
    category: Mapped[str] = mapped_column(sa.Text, nullable=False)
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    file_path: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default="open", server_default="open"
    )
    status_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    status_updated_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    status_updated_by: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )

    # Relationships
    project: Mapped[Project] = relationship(back_populates="findings")
    first_seen_scan: Mapped[Scan | None] = relationship(foreign_keys=[first_seen_scan_id])
    last_seen_scan: Mapped[Scan | None] = relationship(foreign_keys=[last_seen_scan_id])
    status_updated_by_user: Mapped[User | None] = relationship(
        foreign_keys=[status_updated_by]
    )
    scan_findings: Mapped[list[ScanFinding]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True
    )
    status_history: Mapped[list[FindingStatusHistory]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True
    )


class FindingStatusHistory(Base, UUIDPrimaryKeyMixin):
    """Append-only audit trail of status changes (Section 8.1 & Workflow C)."""

    __tablename__ = "finding_status_history"
    __table_args__ = (
        sa.CheckConstraint(
            "actor_type IN ('user', 'system')",
            name="ck_finding_status_history_actor_type",
        ),
        sa.Index("ix_finding_status_history_created", "finding_id", "created_at"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    from_status: Mapped[str] = mapped_column(sa.Text, nullable=False)
    to_status: Mapped[str] = mapped_column(sa.Text, nullable=False)
    actor_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )

    # Relationships
    finding: Mapped[Finding] = relationship(back_populates="status_history")
    actor_user: Mapped[User | None] = relationship()
    scan: Mapped[Scan | None] = relationship()


@sa.event.listens_for(FindingStatusHistory, "before_update")
def _prevent_finding_status_history_update(
    mapper: sa.orm.Mapper[FindingStatusHistory],
    connection: sa.Connection,
    target: FindingStatusHistory,
) -> None:
    """Enforce Blueprint Section 8.1 append-only audit invariant against updates."""
    raise sa.exc.InvalidRequestError(
        "FindingStatusHistory is an append-only audit log and cannot be updated."
    )


@sa.event.listens_for(FindingStatusHistory, "before_delete")
def _prevent_finding_status_history_delete(
    mapper: sa.orm.Mapper[FindingStatusHistory],
    connection: sa.Connection,
    target: FindingStatusHistory,
) -> None:
    """Enforce Blueprint Section 8.1 append-only audit invariant against direct deletes."""
    raise sa.exc.InvalidRequestError(
        "FindingStatusHistory is an append-only audit log and cannot be deleted directly."
    )


@sa.event.listens_for(Session, "do_orm_execute")
def _prevent_finding_status_history_bulk_dml(
    orm_execute_state: ORMExecuteState,
) -> None:
    """Enforce Blueprint Section 8.1 append-only audit invariant against bulk ORM DML."""
    if orm_execute_state.is_update or orm_execute_state.is_delete:
        entity = orm_execute_state.bind_mapper
        if entity is not None and issubclass(entity.class_, FindingStatusHistory):
            action = "updated" if orm_execute_state.is_update else "deleted"
            raise sa.exc.InvalidRequestError(
                f"FindingStatusHistory is an append-only audit log and cannot be {action} via bulk DML."
            )
