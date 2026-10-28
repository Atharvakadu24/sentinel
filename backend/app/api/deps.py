"""Common FastAPI dependencies for authentication, database session, and tenant authorization.

Implements Blueprint Section 8.1, Section 9, and Threat Mitigation T4 (Tenant Isolation).
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.base import utc_now
from app.db.models.finding import Finding
from app.db.models.project import Project
from app.db.models.user import User, UserSession
from app.db.session import get_db_session

DbSession = Annotated[Session, Depends(get_db_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def get_current_user(
    session: DbSession,
    settings: AppSettings,
    sentinel_session: Annotated[str | None, Cookie()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """Resolve authenticated User from session cookie or Bearer token.

    Blueprint Section 4 & Section 12 (Threat T17):
    - Server-side user session verified by SHA-256 token digest.
    - Fails closed with 401 Unauthorized if missing, expired, revoked, or user is soft-deleted.
    """
    token: str | None = None

    if sentinel_session:
        token = sentinel_session
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    if token:
        token_hash = hashlib.sha256(token.encode("utf-8")).digest()
        now = utc_now()
        stmt = (
            select(UserSession)
            .join(User, UserSession.user_id == User.id)
            .where(
                UserSession.token_hash == token_hash,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
                User.deleted_at.is_(None),
            )
        )
        user_session = session.scalars(stmt).first()
        if (
            user_session is not None
            and user_session.user is not None
            and user_session.user.deleted_at is None
        ):
            user_session.last_used_at = now
            return user_session.user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )


CurrentUser = Annotated[User, Depends(get_current_user)]


def verify_project_access(
    project_id: uuid.UUID,
    user: CurrentUser,
    session: DbSession,
) -> Project:
    """Verify that project exists and belongs to the authenticated user.

    Threat Mitigation T4 (Tenant Isolation):
    Fails closed with 404 Not Found if project does not exist or belongs
    to another tenant (preventing resource enumeration).
    """
    stmt = select(Project).where(
        Project.id == project_id,
        Project.deleted_at.is_(None),
    )
    project = session.scalars(stmt).first()
    if project is None or project.owner_user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID '{project_id}' not found",
        )
    return project


def verify_finding_access(
    finding_id: uuid.UUID,
    user: CurrentUser,
    session: DbSession,
) -> Finding:
    """Verify that finding exists and its project belongs to the authenticated user.

    Threat Mitigation T4 (Tenant Isolation):
    Fails closed with 404 Not Found if finding does not exist or its project
    belongs to another tenant (preventing resource enumeration).
    """
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found",
        )

    stmt = select(Project).where(
        Project.id == finding.project_id,
        Project.deleted_at.is_(None),
    )
    project = session.scalars(stmt).first()
    if project is None or project.owner_user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found",
        )

    return finding
