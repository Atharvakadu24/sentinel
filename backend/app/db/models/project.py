"""SQLAlchemy models for GitHub installations and projects.

Blueprint Section 8.1:
- github_installations: link between a user and a GitHub App installation
- projects: the unit of ownership, tenant boundary, and scanning
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.scan import Scan
    from app.db.models.user import User


class GitHubInstallation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Link between a Sentinel user and a GitHub App installation (Section 8.1)."""

    __tablename__ = "github_installations"
    __table_args__ = (
        sa.CheckConstraint(
            "account_type IN ('User', 'Organization')",
            name="ck_github_installations_account_type",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'deleted')",
            name="ck_github_installations_status",
        ),
    )

    installation_id: Mapped[int] = mapped_column(sa.BigInteger, unique=True, nullable=False)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    account_login: Mapped[str] = mapped_column(sa.Text, nullable=False)
    account_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default="active", server_default="active"
    )
    permissions: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)

    # Relationships
    owner_user: Mapped[User] = relationship(back_populates="installations")
    projects: Mapped[list[Project]] = relationship(back_populates="installation")


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The unit of ownership, tenant isolation, and scanning (Section 8.1 & Threat T4)."""

    __tablename__ = "projects"
    __table_args__ = (
        sa.CheckConstraint(
            "kind IN ('github', 'manual')",
            name="ck_projects_kind",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'access_lost', 'archived')",
            name="ck_projects_status",
        ),
        sa.CheckConstraint(
            "kind <> 'github' OR (installation_id IS NOT NULL AND github_repo_id IS NOT NULL)",
            name="ck_projects_github_fields",
        ),
        sa.Index("ix_projects_owner_created", "owner_user_id", "created_at"),
        sa.Index(
            "uq_projects_installation_repo",
            "installation_id",
            "github_repo_id",
            unique=True,
            postgresql_where=sa.text("kind = 'github'"),
        ),
    )

    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(sa.Text, nullable=False)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    installation_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("github_installations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    github_repo_id: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    full_name: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    default_branch: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default="active", server_default="active"
    )
    settings: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    # Relationships
    owner_user: Mapped[User] = relationship(back_populates="projects")
    installation: Mapped[GitHubInstallation | None] = relationship(back_populates="projects")
    scans: Mapped[list[Scan]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
