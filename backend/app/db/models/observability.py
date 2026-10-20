"""SQLAlchemy models for Webhook Events and AI Review Metrics.

Blueprint Section 8.1:
- webhook_events: delivery idempotency and diagnostics (30-day retention)
- ai_reviews: cost tracking, user quotas, and validation metrics per scan
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.db.models.scan import Scan
    from app.db.models.user import User


class WebhookEvent(Base, UUIDPrimaryKeyMixin):
    """Webhook delivery idempotency and diagnostics record (Section 8.1 & Threat T5)."""

    __tablename__ = "webhook_events"
    __table_args__ = (
        sa.CheckConstraint(
            "outcome IN ('accepted', 'ignored_event', 'ignored_draft', 'no_project', 'error')",
            name="ck_webhook_events_outcome",
        ),
    )

    delivery_id: Mapped[str] = mapped_column(sa.Text, unique=True, nullable=False)
    event_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    action: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    github_installation_id: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    github_repo_id: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    pr_number: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    head_sha: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    outcome: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    received_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )

    # Relationships
    scan: Mapped[Scan | None] = relationship()


class AIReview(Base, UUIDPrimaryKeyMixin):
    """Cost tracking, quota accounting, and validation metrics per scan (Section 8.1 & 11)."""

    __tablename__ = "ai_reviews"
    __table_args__ = (
        sa.Index("ix_ai_reviews_owner_created", "owner_user_id", "created_at"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("scans.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(sa.Text, nullable=False)
    model: Mapped[str] = mapped_column(sa.Text, nullable=False)
    prompt_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    calls: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    retries: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    input_tokens: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    output_tokens: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    latency_ms: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    est_cost_usd: Mapped[Decimal | None] = mapped_column(
        sa.Numeric(10, 6), nullable=True
    )
    claims_total: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    claims_valid: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    claims_rejected: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    schema_failures: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    rejections: Mapped[dict[str, int] | None] = mapped_column(JSONType, nullable=True)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False)
    error_code: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="ai_review")
    owner_user: Mapped[User] = relationship()
