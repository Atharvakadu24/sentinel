"""GitHub App installation OAuth/setup state tracking model."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin, utc_now


class GitHubInstallState(UUIDPrimaryKeyMixin, Base):
    """Single-use expiring CSRF/state nonce for GitHub App installation callbacks."""

    __tablename__ = "github_install_states"

    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    state_hash: Mapped[str] = mapped_column(sa.Text(), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )

    __table_args__ = (
        sa.Index("ix_github_install_states_user_id", "user_id"),
        sa.Index("ix_github_install_states_expires_at", "expires_at"),
    )
