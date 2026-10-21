"""SQLAlchemy 2.0 DeclarativeBase, shared mixins, and dialect-portable column types.

Implements Blueprint Section 8 conventions:
- UUID primary keys (gen_random_uuid() / uuid.uuid4)
- UTC timestamptz columns
- Dialect-portable JSONB for PostgreSQL with fallback for testing
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, ClassVar

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Portable JSON type: native JSONB on PostgreSQL, JSON on SQLite/others
JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


class Base(DeclarativeBase):
    """Base declarative class for all Sentinel SQLAlchemy models."""

    type_annotation_map: ClassVar[dict[Any, Any]] = {
        dict: JSONType,
        list: JSONType,
        dict[str, Any]: JSONType,
        list[Any]: JSONType,
        dict[str, int]: JSONType,
        list[dict[str, Any]]: JSONType,
    }


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class UUIDPrimaryKeyMixin:
    """Standardized UUID primary key mixin (Blueprint Section 8)."""

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=sa.text("gen_random_uuid()"),
    )


class TimestampMixin:
    """Standardized creation and update audit timestamps in UTC."""

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=sa.func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        server_default=sa.func.now(),
    )
