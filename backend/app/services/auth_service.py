"""Application service layer for authentication and session management.

Implements Blueprint Section 8.1 (user_sessions model contracts) and Section 12
(Threat Mitigation T17: Session Security).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models.user import UserSession


class AuthServiceError(Exception):
    """Base exception for all authentication and session service operations."""


def revoke_session(
    session: Session,
    *,
    user_session: UserSession,
    auto_commit: bool = False,
) -> UserSession:
    """Revoke an active user session immediately.

    Enforces:
    - Sets revoked_at to current UTC timestamp.
    - Scoped revocation: applies strictly to user_session; does not revoke other
      sessions belonging to the same user.
    - Preserves session record: does not physically delete from database.
    - Transactional persistence: flushes within caller's transaction with safe rollback.
    """
    user_session.revoked_at = utc_now()

    try:
        session.flush()
        if auto_commit:
            session.commit()
            session.refresh(user_session)
    except Exception as exc:
        session.rollback()
        raise AuthServiceError("Unexpected error revoking user session.") from exc

    return user_session

