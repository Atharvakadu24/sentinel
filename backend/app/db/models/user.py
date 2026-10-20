"""SQLAlchemy models for User identity and session management.

Blueprint Section 8.1:
- users: identity from GitHub OAuth
- user_sessions: server-side sessions with hashed tokens
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.db.models.project import GitHubInstallation, Project


class User(Base, UUIDPrimaryKeyMixin):
    """User account authenticated via GitHub (Section 8.1)."""

    __tablename__ = "users"

    github_user_id: Mapped[int] = mapped_column(sa.BigInteger, unique=True, nullable=False)
    github_login: Mapped[str] = mapped_column(sa.Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    # Relationships
    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    installations: Mapped[list[GitHubInstallation]] = relationship(
        back_populates="owner_user", cascade="all, delete-orphan"
    )
    projects: Mapped[list[Project]] = relationship(
        back_populates="owner_user", cascade="all, delete-orphan"
    )


class UserSession(Base, UUIDPrimaryKeyMixin):
    """Server-side user session (Section 8.1 & Threat T17).

    The raw token exists exclusively in the client-side HttpOnly cookie.
    Only the SHA-256 byte digest is persisted in token_hash.
    """

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[bytes] = mapped_column(sa.LargeBinary(32), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    # Relationships
    user: Mapped[User] = relationship(back_populates="sessions")
