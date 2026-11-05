"""Application service layer for Project management and queries.

Implements Blueprint Section 8.1 (Projects model contracts) and Section 12
(Threat Mitigation T4: Tenant Isolation).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.project import Project
from app.schemas.project import ProjectKind, ProjectStatus


def list_projects(
    session: Session,
    *,
    user_id: uuid.UUID,
    kind: Sequence[str | ProjectKind] | str | ProjectKind | None = None,
    status: Sequence[str | ProjectStatus] | str | ProjectStatus | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[Project], int]:
    """Retrieve paginated projects owned by user_id with deterministic ordering.

    Implements:
    - Enforced tenant isolation: Project.owner_user_id == user_id.
    - Soft-delete exclusion: Project.deleted_at must be None.
    - Filters: kind, status (supporting single or multi-value sequence).
    - Stable, deterministic ordering: created_at DESC, id DESC.
    - Zero N+1 queries.
    """
    conditions: list[Any] = [
        Project.owner_user_id == user_id,
        Project.deleted_at.is_(None),
    ]

    if kind is not None:
        if isinstance(kind, (list, tuple, set)):
            kind_vals = [k.value if hasattr(k, "value") else str(k) for k in kind]
            conditions.append(Project.kind.in_(kind_vals))
        else:
            kind_val = kind.value if hasattr(kind, "value") else str(kind)
            conditions.append(Project.kind == kind_val)

    if status is not None:
        if isinstance(status, (list, tuple, set)):
            status_vals = [s.value if hasattr(s, "value") else str(s) for s in status]
            conditions.append(Project.status.in_(status_vals))
        else:
            status_val = status.value if hasattr(status, "value") else str(status)
            conditions.append(Project.status == status_val)

    count_stmt = select(sa.func.count(Project.id)).select_from(Project).where(*conditions)
    total = session.scalar(count_stmt) or 0

    stmt = (
        select(Project)
        .where(*conditions)
        .order_by(Project.created_at.desc(), Project.id.desc())
        .offset(offset)
        .limit(limit)
    )
    items = list(session.scalars(stmt).all())
    return items, total
