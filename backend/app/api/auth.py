"""API routes for user identity, GitHub OAuth login, and session management.

Implements Blueprint Section 8.1 (users and user_sessions contracts) and Section 12
(Threat Mitigation T17: Session Security):
- GET /auth/github/login: Issue single-use state + CSRF tx cookie and GitHub OAuth URL
- GET /auth/github/callback: Validate state/tx/OAuth code, resolve User, issue UserSession cookie
- GET /me: Retrieve safe user profile for the authenticated caller (200 OK)
- POST /logout: Revoke current session and invalidate session cookie (204 No Content)
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated, NoReturn

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Query,
    Response,
    status,
)
from fastapi.responses import JSONResponse, RedirectResponse

from app.api.deps import AppSettings, CurrentSession, CurrentUser, DbSession
from app.schemas.user import GitHubAuthSessionResponse, GitHubAuthUrlResponse, UserResponse
from app.services.auth_service import (
    OAUTH_TX_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    AuthAuthorizationError,
    AuthConfigurationError,
    AuthConflictError,
    AuthServiceError,
    AuthStateError,
    AuthUpstreamError,
    AuthValidationError,
    complete_github_login_callback,
    initiate_github_login,
    revoke_session,
)
from app.services.github_client import GitHubConfigurationError, GitHubOAuthClient

router = APIRouter(tags=["auth"])


def get_github_oauth_client(
    settings: AppSettings,
) -> Generator[GitHubOAuthClient, None, None]:
    """FastAPI dependency yielding a configured GitHubOAuthClient or failing closed with 503."""
    try:
        client = GitHubOAuthClient.from_oauth_settings(settings)
    except GitHubConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    try:
        yield client
    finally:
        client.close()


GitHubOAuthClientDep = Annotated[GitHubOAuthClient, Depends(get_github_oauth_client)]


def _raise_upstream_http(exc: AuthUpstreamError) -> NoReturn:
    headers: dict[str, str] | None = None
    if exc.retry_after_sec is not None:
        headers = {"Retry-After": str(exc.retry_after_sec)}
    raise HTTPException(
        status_code=exc.status_code,
        detail=str(exc),
        headers=headers,
    ) from exc


def _set_no_store_headers(resp: Response) -> None:
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"


@router.get(
    "/auth/github/login",
    response_model=GitHubAuthUrlResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate GitHub OAuth login",
    description="Creates a single-use expiring OAuth login state and transaction cookie and returns or redirects to the GitHub OAuth authorize URL.",
)
def initiate_github_login_endpoint(
    session: DbSession,
    settings: AppSettings,
    next: Annotated[
        str | None,
        Query(
            max_length=512,
            description="Optional safe relative Sentinel path to redirect after login.",
        ),
    ] = None,
    redirect: Annotated[
        bool,
        Query(description="If true, responds with HTTP 302 redirect to GitHub instead of JSON."),
    ] = False,
) -> Response:
    """Create purpose-bound OAuth login state + tx cookie and return/redirect to GitHub."""
    try:
        initiation = initiate_github_login(
            session,
            settings=settings,
            next_path=next,
        )
    except AuthConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except AuthValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # Commit login state before emitting redirect or JSON response
    session.commit()

    resp: Response
    if redirect:
        resp = RedirectResponse(url=initiation.authorize_url, status_code=status.HTTP_302_FOUND)
    else:
        payload = GitHubAuthUrlResponse(
            authorize_url=initiation.authorize_url,
            expires_at=initiation.expires_at,
        )
        resp = JSONResponse(
            content=payload.model_dump(mode="json"),
            status_code=status.HTTP_200_OK,
        )

    resp.set_cookie(
        key=OAUTH_TX_COOKIE_NAME,
        value=initiation.raw_tx_nonce,
        max_age=settings.GITHUB_STATE_TTL_SEC,
        expires=initiation.expires_at,
        path="/",
        httponly=True,
        samesite="lax",
        secure=(settings.APP_ENV == "production"),
    )
    _set_no_store_headers(resp)
    return resp


@router.get(
    "/auth/github/callback",
    response_model=GitHubAuthSessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Complete GitHub OAuth login callback",
    description="Validates single-use login state and transaction cookie, verifies GitHub identity via OAuth, and issues a Sentinel UserSession cookie.",
)
def github_auth_callback_endpoint(
    state: Annotated[
        str, Query(min_length=1, max_length=256, description="OAuth login CSRF state token.")
    ],
    session: DbSession,
    settings: AppSettings,
    oauth_client: GitHubOAuthClientDep,
    code: Annotated[
        str | None,
        Query(min_length=1, max_length=512, description="GitHub OAuth authorization code."),
    ] = None,
    error: Annotated[
        str | None,
        Query(max_length=128, description="GitHub OAuth authorization error code."),
    ] = None,
    sentinel_oauth_tx: Annotated[str | None, Cookie()] = None,
    sentinel_session: Annotated[str | None, Cookie()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    """Complete OAuth code exchange, bind verified GitHub identity, and issue session cookie."""
    existing_session_token: str | None = None
    if sentinel_session:
        existing_session_token = sentinel_session
    elif authorization and authorization.lower().startswith("bearer "):
        existing_session_token = authorization[7:].strip()

    try:
        login_result = complete_github_login_callback(
            session,
            settings=settings,
            oauth_client=oauth_client,
            state=state,
            tx_nonce=sentinel_oauth_tx,
            code=code,
            oauth_error=error,
            existing_session_token=existing_session_token,
        )
    except AuthConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except (AuthStateError, AuthAuthorizationError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except AuthConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except AuthUpstreamError as exc:
        _raise_upstream_http(exc)
    except AuthServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete GitHub authentication.",
        ) from exc

    session.commit()
    session.refresh(login_result.user)

    resp: Response
    if login_result.next_path is not None:
        resp = RedirectResponse(url=login_result.next_path, status_code=status.HTTP_302_FOUND)
    else:
        payload = GitHubAuthSessionResponse(
            user=UserResponse.from_orm_model(login_result.user),
            expires_at=login_result.expires_at,
        )
        resp = JSONResponse(
            content=payload.model_dump(mode="json"),
            status_code=status.HTTP_200_OK,
        )

    secure_cookie = settings.APP_ENV == "production"
    resp.delete_cookie(
        key=OAUTH_TX_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=secure_cookie,
    )
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=login_result.raw_session_token,
        max_age=settings.SESSION_TTL_SEC,
        expires=login_result.expires_at,
        path="/",
        httponly=True,
        samesite="lax",
        secure=secure_cookie,
    )
    _set_no_store_headers(resp)
    return resp


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
    _set_no_store_headers(response)
    return response
