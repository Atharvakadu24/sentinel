"""API routes for GitHub App onboarding, installations, and repository connection."""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.api.deps import AppSettings, CurrentUser, DbSession
from app.schemas.github import (
    GitHubInstallationListResponse,
    GitHubInstallationResponse,
    GitHubInstallUrlResponse,
    GitHubRepoConnectRequest,
    GitHubRepositoryListResponse,
)
from app.schemas.project import ProjectDetailResponse
from app.services.github_client import GitHubAppClient, GitHubConfigurationError
from app.services.github_service import (
    GitHubAuthorizationError,
    GitHubInstallationConflictError,
    GitHubInstallationNotFoundError,
    GitHubIntegrationError,
    GitHubNotConfiguredError,
    GitHubRepoNotFoundError,
    GitHubStateError,
    GitHubUpstreamError,
    complete_github_installation_callback,
    connect_github_repository,
    initiate_github_installation,
    list_installation_repositories,
    list_user_installations,
)

router = APIRouter(prefix="/integrations/github", tags=["github"])


def get_github_client(settings: AppSettings) -> Generator[GitHubAppClient, None, None]:
    """FastAPI dependency yielding a configured GitHubAppClient or failing closed with 503."""
    try:
        client = GitHubAppClient.from_settings(settings)
    except GitHubConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    try:
        yield client
    finally:
        client.close()


GitHubClientDep = Annotated[GitHubAppClient, Depends(get_github_client)]


def _raise_upstream_http(exc: GitHubUpstreamError) -> NoReturn:
    headers: dict[str, str] | None = None
    if exc.retry_after_sec is not None:
        headers = {"Retry-After": str(exc.retry_after_sec)}
    raise HTTPException(
        status_code=exc.status_code,
        detail=str(exc),
        headers=headers,
    ) from exc


@router.get(
    "/install",
    response_model=GitHubInstallUrlResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate GitHub App installation",
    description="Creates a single-use expiring CSRF state bound to the authenticated user and returns the GitHub App installation URL.",
)
def initiate_github_install_endpoint(
    session: DbSession,
    user: CurrentUser,
    settings: AppSettings,
    redirect: Annotated[
        bool,
        Query(description="If true, responds with HTTP 302 redirect to GitHub instead of JSON."),
    ] = False,
) -> Response:
    """Create CSRF install state and return or redirect to GitHub App installation URL."""
    try:
        install_url, expires_at = initiate_github_installation(
            session,
            settings=settings,
            user_id=user.id,
        )
    except GitHubNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    if redirect:
        # Commit state explicitly before sending redirect response
        session.commit()
        return RedirectResponse(url=install_url, status_code=status.HTTP_302_FOUND)

    payload = GitHubInstallUrlResponse(install_url=install_url, expires_at=expires_at)
    return JSONResponse(content=payload.model_dump(mode="json"), status_code=status.HTTP_200_OK)


@router.get(
    "/callback",
    response_model=GitHubInstallationResponse,
    status_code=status.HTTP_200_OK,
    summary="Complete GitHub App installation callback",
    description="Validates single-use CSRF state and binds the verified GitHub installation to the authenticated user.",
)
def github_install_callback_endpoint(
    state: Annotated[str, Query(min_length=1, max_length=256, description="CSRF state token.")],
    session: DbSession,
    user: CurrentUser,
    settings: AppSettings,
    github_client: GitHubClientDep,
    installation_id: Annotated[
        int | None,
        Query(ge=1, description="GitHub installation ID."),
    ] = None,
    code: Annotated[
        str | None,
        Query(min_length=1, max_length=512, description="GitHub OAuth authorization code."),
    ] = None,
    error: Annotated[
        str | None,
        Query(max_length=128, description="GitHub OAuth authorization error code."),
    ] = None,
    setup_action: Annotated[
        str,
        Query(description="GitHub setup action ('install' or 'update')."),
    ] = "install",
) -> GitHubInstallationResponse:
    """Validate installation callback state, OAuth authorization, and persist ownership."""
    try:
        installation = complete_github_installation_callback(
            session,
            settings=settings,
            github_client=github_client,
            user_id=user.id,
            state=state,
            installation_id=installation_id,
            code=code,
            oauth_error=error,
            setup_action=setup_action,
        )
    except GitHubNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except (GitHubStateError, GitHubAuthorizationError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except GitHubInstallationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except GitHubInstallationConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except GitHubUpstreamError as exc:
        _raise_upstream_http(exc)
    except GitHubIntegrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete GitHub installation.",
        ) from exc

    return GitHubInstallationResponse.from_orm_model(installation)


@router.get(
    "/installations",
    response_model=GitHubInstallationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List connected GitHub installations",
    description="Lists GitHub App installations owned by the authenticated user.",
)
def list_installations_endpoint(
    session: DbSession,
    user: CurrentUser,
) -> GitHubInstallationListResponse:
    """Return owned non-deleted GitHub installations."""
    installations = list_user_installations(session, user_id=user.id)
    return GitHubInstallationListResponse(
        items=[GitHubInstallationResponse.from_orm_model(inst) for inst in installations],
        total=len(installations),
    )


@router.get(
    "/installations/{installation_id}/repositories",
    response_model=GitHubRepositoryListResponse,
    status_code=status.HTTP_200_OK,
    summary="List repositories accessible to an installation",
    description="Fetches paginated GitHub repositories for an owned active installation and marks those already connected to Sentinel projects.",
)
def list_installation_repositories_endpoint(
    installation_id: Annotated[int, Path(ge=1)],
    session: DbSession,
    user: CurrentUser,
    github_client: GitHubClientDep,
) -> GitHubRepositoryListResponse:
    """List repositories accessible through an owned installation."""
    try:
        repos = list_installation_repositories(
            session,
            github_client=github_client,
            installation_id=installation_id,
            user_id=user.id,
        )
    except GitHubInstallationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except GitHubInstallationConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except GitHubUpstreamError as exc:
        _raise_upstream_http(exc)

    return GitHubRepositoryListResponse(
        installation_id=installation_id,
        items=repos,
        total=len(repos),
    )


@router.post(
    "/installations/{installation_id}/repositories/connect",
    response_model=ProjectDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Connect GitHub repository to Sentinel project",
    description="Verifies installation ownership and repository access via GitHub API, then creates or reactivates a synced GitHub Project.",
)
def connect_repository_endpoint(
    installation_id: Annotated[int, Path(ge=1)],
    body: GitHubRepoConnectRequest,
    session: DbSession,
    user: CurrentUser,
    github_client: GitHubClientDep,
) -> ProjectDetailResponse:
    """Connect a GitHub repository under an owned active installation into Sentinel."""
    try:
        project = connect_github_repository(
            session,
            github_client=github_client,
            installation_id=installation_id,
            user_id=user.id,
            github_repo_id=body.github_repo_id,
            name=body.name,
        )
    except (GitHubInstallationNotFoundError, GitHubRepoNotFoundError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except GitHubInstallationConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except GitHubUpstreamError as exc:
        _raise_upstream_http(exc)
    except GitHubIntegrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect GitHub repository.",
        ) from exc

    return ProjectDetailResponse.from_orm_model(project)
