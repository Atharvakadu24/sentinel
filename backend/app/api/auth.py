"""API routes for user identity and authentication session management.

Implements Blueprint Section 8.1 (users and user_sessions contracts) and Section 12
(Threat Mitigation T17: Session Security).
- GET /me: Retrieve safe user profile for the authenticated caller (200 OK)
- POST /logout: Revoke current session and invalidate session cookie (204 No Content)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status

from app.api.deps import AppSettings, CurrentSession, CurrentUser, DbSession
from app.schemas.user import UserResponse
from app.services.auth_service import AuthServiceError, revoke_session

router = APIRouter(tags=["auth"])


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user",
    description="Retrieve the authenticated user's profile and tenant identity.",
)
def get_current_user_endpoint(
    user: CurrentUser,
) -> UserResponse:
    """Retrieve safe profile for the authenticated caller."""
    return UserResponse.from_orm_model(user)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="User logout",
    description="Revoke the authenticated session and clear the session cookie.",
)
def logout_endpoint(
    current_session: CurrentSession,
    session: DbSession,
    settings: AppSettings,
    response: Response,
) -> Response:
    """Revoke the current user session and clear client-side session cookie."""
    try:
        revoke_session(session, user_session=current_session)
    except AuthServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while logging out.",
        ) from exc

    response.status_code = status.HTTP_204_NO_CONTENT
    response.delete_cookie(
        key="sentinel_session",
        path="/",
        httponly=True,
        samesite="lax",
        secure=(settings.APP_ENV == "production"),
    )
    return response
