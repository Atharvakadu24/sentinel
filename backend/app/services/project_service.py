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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models.project import Project
from app.db.models.user import User
from app.schemas.project import ProjectKind, ProjectStatus


class ProjectServiceError(Exception):
    """Base exception for all project service operations."""


class ProjectConflictError(ProjectServiceError):
    """Raised when an active project with the same name already exists for the owner (409 Conflict)."""


class ProjectValidationError(ProjectServiceError):
    """Raised when project inputs violate business constraints (422 Unprocessable Content)."""


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


def _is_project_name_conflict(exc: IntegrityError) -> bool:
    """Determine whether an IntegrityError specifically stems from project name uniqueness."""
    err_msg = str(exc.orig if hasattr(exc, "orig") else exc).lower()
    if "uq_projects_owner_name" in err_msg or "uq_projects_name" in err_msg:
        return True
    is_unique = "unique" in err_msg or "duplicate" in err_msg
    if "uq_projects_installation_repo" in err_msg or "installation_id" in err_msg:
        return False
    return is_unique and (
        "projects.name" in err_msg or ("name" in err_msg and "projects" in err_msg)
    )


def _is_project_check_violation(exc: IntegrityError) -> bool:
    """Determine whether an IntegrityError stems from a known project check constraint."""
    err_msg = str(exc.orig if hasattr(exc, "orig") else exc).lower()
    known_checks = (
        "ck_projects_kind",
        "ck_projects_status",
        "ck_projects_github_fields",
    )
    if any(check in err_msg for check in known_checks):
        return True
    return "check" in err_msg and any(col in err_msg for col in ("kind", "status", "github_fields"))


def _is_foreign_key_violation(exc: IntegrityError) -> bool:
    """Determine whether an IntegrityError stems from a foreign key constraint failure."""
    err_msg = str(exc.orig if hasattr(exc, "orig") else exc).lower()
    return "foreign key" in err_msg or "foreignkey" in err_msg


def create_manual_project(
    session: Session,
    *,
    user_id: uuid.UUID,
    name: str,
    default_branch: str | None = "main",
    settings: dict[str, Any] | None = None,
    auto_commit: bool = False,
) -> Project:
    """Create a new manual project for the authenticated user.

    Enforces:
    - Tenant isolation: owner_user_id is derived exclusively from authenticated user_id.
    - Project kind: strictly 'manual', with GitHub fields explicitly None.
    - Concurrency safety: for PostgreSQL, serializes concurrent project creations
      for the same tenant using a row-level lock on the User record.
    - Duplicate conflict: case-insensitively rejects duplicate active names within
      the same tenant (raises ProjectConflictError).
    - Soft-delete reuse: allows reuse of project names after prior records are soft-deleted.
    - Cross-tenant independence: allows identical names across different users.
    - Database integrity: handles IntegrityError with rollback and domain error mapping.
    """
    cleaned_name = name.strip()
    if not cleaned_name:
        raise ProjectValidationError("Project name cannot be empty or whitespace only.")

    cleaned_branch = (default_branch or "main").strip()
    if not cleaned_branch:
        cleaned_branch = "main"

    # 1. On PostgreSQL, serialize same-tenant project creation using a row-level lock on User
    user_stmt = select(User.id).where(User.id == user_id)
    bind = session.get_bind()
    if bind is not None and getattr(bind.dialect, "name", "") == "postgresql":
        user_stmt = user_stmt.with_for_update()
    session.scalar(user_stmt)

    # 2. Case-insensitive duplicate check for active (non-soft-deleted) projects of this owner
    dup_stmt = select(Project.id).where(
        Project.owner_user_id == user_id,
        Project.deleted_at.is_(None),
        sa.func.lower(Project.name) == sa.func.lower(cleaned_name),
    )
    if session.scalar(dup_stmt) is not None:
        raise ProjectConflictError(
            f"An active project with the name '{cleaned_name}' already exists."
        )

    # 3. Instantiate and persist manual project
    project = Project(
        id=uuid.uuid4(),
        owner_user_id=user_id,
        kind="manual",
        name=cleaned_name,
        installation_id=None,
        github_repo_id=None,
        full_name=None,
        default_branch=cleaned_branch,
        status="active",
        settings=settings,
    )

    try:
        session.add(project)
        session.flush()
        if auto_commit:
            session.commit()
            session.refresh(project)
    except IntegrityError as exc:
        session.rollback()
        if _is_project_name_conflict(exc):
            raise ProjectConflictError(
                f"An active project with the name '{cleaned_name}' already exists."
            ) from exc
        if _is_project_check_violation(exc):
            raise ProjectValidationError(
                "Project data violates database integrity constraints."
            ) from exc
        if _is_foreign_key_violation(exc):
            raise ProjectValidationError("Referenced user does not exist.") from exc
        raise ProjectServiceError("Database integrity error creating project.") from exc
    except Exception as exc:
        session.rollback()
        raise ProjectServiceError("Unexpected error creating project.") from exc

    return project


def update_project(
    session: Session,
    *,
    project: Project,
    name: str | None = None,
    default_branch: str | None = None,
    settings: dict[str, Any] | None = None,
    fields_set: set[str] | None = None,
    auto_commit: bool = False,
) -> Project:
    """Update supported fields of an existing project.

    Enforces:
    - Supported field updates: name, default_branch, settings.
    - Tenant-scoped, case-insensitive duplicate name conflict: if name is updated,
      verifies that no other active project owned by the same user shares the name.
    - Preserves protected fields: id, owner_user_id, kind, status, installation_id,
      github_repo_id, full_name, deleted_at are never altered.
    - Concurrency safety: serializes same-tenant mutations on PostgreSQL using row locks.
    - Safe IntegrityError handling with rollback and domain error mapping.
    """
    effective_fields = fields_set if fields_set is not None else set()
    changed = False

    # 1. Update project name if provided in fields_set
    if "name" in effective_fields and name is not None:
        cleaned_name = name.strip()
        if not cleaned_name:
            raise ProjectValidationError("Project name cannot be empty or whitespace only.")

        # On PostgreSQL, serialize same-tenant mutations using a row-level lock on User
        user_stmt = select(User.id).where(User.id == project.owner_user_id)
        bind = session.get_bind()
        if bind is not None and getattr(bind.dialect, "name", "") == "postgresql":
            user_stmt = user_stmt.with_for_update()
        session.scalar(user_stmt)

        # Check for case-insensitive name conflict against other active projects of this owner
        dup_stmt = select(Project.id).where(
            Project.owner_user_id == project.owner_user_id,
            Project.id != project.id,
            Project.deleted_at.is_(None),
            sa.func.lower(Project.name) == sa.func.lower(cleaned_name),
        )
        if session.scalar(dup_stmt) is not None:
            raise ProjectConflictError(
                f"An active project with the name '{cleaned_name}' already exists."
            )

        if project.name != cleaned_name:
            project.name = cleaned_name
            changed = True

    # 2. Update default_branch if provided in fields_set
    if "default_branch" in effective_fields and default_branch is not None:
        cleaned_branch = default_branch.strip()
        if not cleaned_branch:
            raise ProjectValidationError("Default branch cannot be empty or whitespace only.")
        if project.default_branch != cleaned_branch:
            project.default_branch = cleaned_branch
            changed = True

    # 3. Update settings if provided in fields_set (explicit None clears settings)
    if "settings" in effective_fields and project.settings != settings:
        project.settings = settings
        changed = True

    if changed:
        project.updated_at = utc_now()

    try:
        session.flush()
        if auto_commit:
            session.commit()
            session.refresh(project)
    except IntegrityError as exc:
        session.rollback()
        if _is_project_name_conflict(exc):
            raise ProjectConflictError(
                f"An active project with the name '{project.name}' already exists."
            ) from exc
        if _is_project_check_violation(exc):
            raise ProjectValidationError(
                "Project data violates database integrity constraints."
            ) from exc
        if _is_foreign_key_violation(exc):
            raise ProjectValidationError("Referenced user does not exist.") from exc
        raise ProjectServiceError("Database integrity error updating project.") from exc
    except Exception as exc:
        session.rollback()
        raise ProjectServiceError("Unexpected error updating project.") from exc

    return project
