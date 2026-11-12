"""Application service for GitHub App installation onboarding and repository syncing."""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import quote

import sqlalchemy as sa
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.base import utc_now
from app.db.models import GitHubInstallation, GitHubInstallState, Project, User
from app.schemas.github import GitHubRepositoryItem
from app.services.github_client import (
    GitHubAppClient,
    GitHubAuthenticationError,
    GitHubClientError,
    GitHubInstallationInfo,
    GitHubNotFoundError,
    GitHubOAuthError,
    GitHubPermissionError,
    GitHubRateLimitError,
    GitHubRepositoryInfo,
    redact_github_secrets,
)
from app.services.job_service import _normalize_datetime

logger = logging.getLogger("sentinel.services.github")


class GitHubIntegrationError(Exception):
    """Base error for GitHub App onboarding and repository sync workflows."""


class GitHubNotConfiguredError(GitHubIntegrationError):
    """Raised when required GitHub App configuration settings are missing."""


class GitHubStateError(GitHubIntegrationError):
    """Raised when OAuth/install state is invalid, expired, replayed, or owned by another user."""


class GitHubAuthorizationError(GitHubIntegrationError):
    """Raised when GitHub OAuth authorization or installation access verification fails."""


class GitHubInstallationNotFoundError(GitHubIntegrationError):
    """Raised when the requested GitHub installation does not exist for the user."""


class GitHubInstallationConflictError(GitHubIntegrationError):
    """Raised on tenant ownership conflicts, suspended installations, or duplicate connections."""


class GitHubRepoNotFoundError(GitHubIntegrationError):
    """Raised when the requested GitHub repository is not accessible under the installation."""


class GitHubUpstreamError(GitHubIntegrationError):
    """Raised when calling the upstream GitHub API fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 502,
        retry_after_sec: int | None = None,
    ) -> None:
        super().__init__(redact_github_secrets(message))
        self.status_code = status_code
        self.retry_after_sec = retry_after_sec


def _hash_state(raw_state: str) -> str:
    return hashlib.sha256(raw_state.encode("utf-8")).hexdigest()


def _lock_user_for_project_write(session: Session, user_id: uuid.UUID) -> None:
    bind = session.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        session.execute(
            select(User.id).where(User.id == user_id).with_for_update()
        ).scalar_one_or_none()


def _is_unique_violation(exc: IntegrityError) -> bool:
    msg = str(exc.orig).lower() if exc.orig else str(exc).lower()
    return "unique" in msg or "duplicate key" in msg


def _map_client_error(exc: GitHubClientError, default_context: str) -> GitHubUpstreamError:
    if isinstance(exc, GitHubRateLimitError):
        return GitHubUpstreamError(
            "GitHub API rate limit exceeded; please retry shortly",
            status_code=429,
            retry_after_sec=exc.retry_after_sec,
        )
    if isinstance(exc, GitHubNotFoundError):
        return GitHubUpstreamError(
            f"{default_context}: resource not found on GitHub", status_code=404
        )
    return GitHubUpstreamError(
        f"{default_context}: {exc}",
        status_code=502,
    )


def initiate_github_installation(
    session: Session,
    *,
    settings: Settings,
    user_id: uuid.UUID,
    now: datetime | None = None,
    auto_commit: bool = False,
) -> tuple[str, datetime]:
    """Generate a single-use expiring CSRF state and return GitHub App install URL."""
    install_base_url = settings.get_github_install_base_url()
    if not settings.is_github_app_configured() or not install_base_url:
        raise GitHubNotConfiguredError(
            "GitHub App installation requires GITHUB_APP_ID, private key, and GITHUB_APP_SLUG"
        )

    current_time = _normalize_datetime(now) or utc_now()
    expires_at = current_time + timedelta(seconds=settings.GITHUB_STATE_TTL_SEC)
    raw_state = secrets.token_urlsafe(32)
    state_hash = _hash_state(raw_state)

    # Best-effort cleanup of stale expired states for hygiene
    stale_cutoff = current_time - timedelta(days=1)
    session.execute(
        sa.delete(GitHubInstallState).where(GitHubInstallState.expires_at < stale_cutoff)
    )

    state_row = GitHubInstallState(
        user_id=user_id,
        state_hash=state_hash,
        expires_at=expires_at,
        created_at=current_time,
    )
    session.add(state_row)
    session.flush()
    if auto_commit:
        session.commit()

    install_url = f"{install_base_url}?state={quote(raw_state, safe='')}"
    return install_url, expires_at


def _consume_install_state(
    session: Session,
    *,
    user_id: uuid.UUID,
    raw_state: str,
    current_time: datetime,
) -> None:
    """Atomically mark state token used if valid, unconsumed, unexpired, and owned by user."""
    cleaned_state = raw_state.strip()
    if not cleaned_state or len(cleaned_state) > 256:
        raise GitHubStateError("Invalid or missing GitHub installation state")

    state_hash = _hash_state(cleaned_state)
    stmt = (
        update(GitHubInstallState)
        .where(
            GitHubInstallState.state_hash == state_hash,
            GitHubInstallState.user_id == user_id,
            GitHubInstallState.used_at.is_(None),
            GitHubInstallState.expires_at > current_time,
        )
        .values(used_at=current_time)
        .returning(GitHubInstallState.id)
    )
    consumed_id = session.execute(stmt).scalar_one_or_none()
    if consumed_id is None:
        raise GitHubStateError("Invalid, expired, or already used installation state")

    # Persist single-use consumption immediately so downstream upstream failures never permit replay
    session.commit()


def _has_required_installation_permissions(permissions: dict[str, str]) -> bool:
    return permissions.get("contents") in ("read", "write") and permissions.get(
        "pull_requests"
    ) in ("read", "write")


def _verify_oauth_installation_access(
    *,
    info: GitHubInstallationInfo,
    accessible: list[GitHubInstallationInfo],
) -> None:
    matched = next((entry for entry in accessible if entry.id == info.id), None)
    if matched is None:
        raise GitHubAuthorizationError(
            "Authenticated GitHub user is not authorized to access this installation"
        )
    if matched.status != "active":
        raise GitHubAuthorizationError("GitHub App installation is suspended")
    if matched.account_type != info.account_type:
        raise GitHubAuthorizationError("GitHub installation account type mismatch")
    if matched.account_login.casefold() != info.account_login.casefold():
        raise GitHubAuthorizationError("GitHub installation account identity mismatch")
    if (
        info.account_id is None
        or matched.account_id is None
        or matched.account_id != info.account_id
    ):
        raise GitHubAuthorizationError("GitHub installation numeric account ID mismatch")


def complete_github_installation_callback(
    session: Session,
    *,
    settings: Settings,
    github_client: GitHubAppClient,
    user_id: uuid.UUID,
    state: str,
    installation_id: int | None = None,
    code: str | None = None,
    oauth_error: str | None = None,
    setup_action: str = "install",
    now: datetime | None = None,
    auto_commit: bool = False,
) -> GitHubInstallation:
    """Verify CSRF state, GitHub App/OAuth installation ownership, and bind to user_id."""
    current_time = _normalize_datetime(now) or utc_now()
    _consume_install_state(
        session,
        user_id=user_id,
        raw_state=state,
        current_time=current_time,
    )

    if setup_action not in ("install", "update"):
        raise GitHubStateError(f"Unsupported GitHub installation setup_action: '{setup_action}'")

    if oauth_error is not None and oauth_error.strip():
        if oauth_error.strip().lower() == "access_denied":
            raise GitHubAuthorizationError("GitHub OAuth authorization was denied by the user")
        raise GitHubAuthorizationError("GitHub OAuth authorization failed")

    if installation_id is None or isinstance(installation_id, bool) or installation_id <= 0:
        raise GitHubStateError("Invalid or missing GitHub installation_id")

    sentinel_user = session.get(User, user_id)
    if sentinel_user is None or sentinel_user.deleted_at is not None:
        raise GitHubStateError("Authenticated Sentinel user is not active")

    try:
        info = github_client.get_installation(installation_id)
    except GitHubNotFoundError as exc:
        raise GitHubInstallationNotFoundError(
            "GitHub App installation does not exist on GitHub"
        ) from exc
    except GitHubClientError as exc:
        raise _map_client_error(exc, "Failed to verify GitHub installation") from exc

    if info.id != installation_id:
        raise GitHubInstallationNotFoundError("GitHub installation ID mismatch from upstream API")

    if info.status != "active":
        raise GitHubAuthorizationError("GitHub App installation is suspended")

    if not _has_required_installation_permissions(info.permissions):
        raise GitHubAuthorizationError(
            "GitHub App installation lacks required contents and pull_requests permissions"
        )

    cleaned_code = code.strip() if isinstance(code, str) and code.strip() else None
    if info.account_type == "Organization":
        if not settings.is_github_oauth_configured():
            raise GitHubNotConfiguredError(
                "GitHub user OAuth (GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET) is required to verify organization installation ownership"
            )
        if cleaned_code is None:
            raise GitHubAuthorizationError(
                "GitHub OAuth authorization code is required to verify organization installation access"
            )
    elif cleaned_code is not None and not settings.is_github_oauth_configured():
        raise GitHubNotConfiguredError(
            "GitHub OAuth client credentials are not configured to exchange authorization code"
        )

    if cleaned_code is not None:
        user_access_token = ""
        try:
            try:
                user_access_token = github_client.exchange_oauth_code(cleaned_code)
                oauth_user = github_client.get_oauth_user(user_access_token)
                accessible = github_client.list_user_installations(user_access_token)
            except (GitHubOAuthError, GitHubAuthenticationError, GitHubPermissionError) as exc:
                raise GitHubAuthorizationError(str(exc)) from exc
            except GitHubClientError as exc:
                raise _map_client_error(exc, "Failed to verify GitHub OAuth authorization") from exc
        finally:
            user_access_token = ""

        if (
            oauth_user.id != sentinel_user.github_user_id
            or oauth_user.login.casefold() != sentinel_user.github_login.casefold()
        ):
            raise GitHubInstallationConflictError(
                "Authenticated GitHub OAuth user does not match the Sentinel account"
            )

        _verify_oauth_installation_access(info=info, accessible=accessible)

    if info.account_type == "User" and (
        (info.account_id is not None and info.account_id != sentinel_user.github_user_id)
        or info.account_login.casefold() != sentinel_user.github_login.casefold()
    ):
        raise GitHubInstallationConflictError(
            "Personal GitHub installation account does not match the authenticated Sentinel user"
        )

    existing = session.scalar(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == info.id)
    )
    if existing is not None:
        if existing.owner_user_id != user_id:
            raise GitHubInstallationConflictError(
                "This GitHub installation is already connected to another Sentinel account"
            )
        existing.account_login = info.account_login
        existing.account_type = info.account_type
        existing.status = info.status
        existing.permissions = info.permissions
        existing.updated_at = current_time
        installation = existing
    else:
        installation = GitHubInstallation(
            installation_id=info.id,
            owner_user_id=user_id,
            account_login=info.account_login,
            account_type=info.account_type,
            status=info.status,
            permissions=info.permissions,
            created_at=current_time,
            updated_at=current_time,
        )
        session.add(installation)

    try:
        session.flush()
        if auto_commit:
            session.commit()
            session.refresh(installation)
    except IntegrityError as exc:
        session.rollback()
        if _is_unique_violation(exc):
            raise GitHubInstallationConflictError(
                "This GitHub installation is already connected to another Sentinel account"
            ) from exc
        raise GitHubIntegrationError("Database error recording GitHub installation") from exc

    return installation


def list_user_installations(
    session: Session,
    *,
    user_id: uuid.UUID,
    include_deleted: bool = False,
) -> list[GitHubInstallation]:
    """List GitHub App installations owned by the authenticated user."""
    conditions = [GitHubInstallation.owner_user_id == user_id]
    if not include_deleted:
        conditions.append(GitHubInstallation.status != "deleted")
    stmt = (
        select(GitHubInstallation)
        .where(*conditions)
        .order_by(GitHubInstallation.created_at.desc(), GitHubInstallation.installation_id.asc())
    )
    return list(session.scalars(stmt).all())


def _get_owned_active_installation(
    session: Session,
    *,
    installation_id: int,
    user_id: uuid.UUID,
) -> GitHubInstallation:
    installation = session.scalar(
        select(GitHubInstallation).where(
            GitHubInstallation.installation_id == installation_id,
            GitHubInstallation.owner_user_id == user_id,
        )
    )
    if installation is None or installation.status == "deleted":
        raise GitHubInstallationNotFoundError("GitHub installation not found")
    if installation.status != "active":
        raise GitHubInstallationConflictError(
            f"GitHub installation is currently '{installation.status}'"
        )
    return installation


def list_installation_repositories(
    session: Session,
    *,
    github_client: GitHubAppClient,
    installation_id: int,
    user_id: uuid.UUID,
) -> list[GitHubRepositoryItem]:
    """List accessible GitHub repositories for an owned installation with link status."""
    inst = _get_owned_active_installation(session, installation_id=installation_id, user_id=user_id)

    try:
        remote_repos = github_client.list_installation_repositories(installation_id)
    except GitHubClientError as exc:
        raise _map_client_error(exc, "Failed to list repositories for GitHub installation") from exc

    linked_rows = session.execute(
        select(Project.github_repo_id, Project.id).where(
            Project.owner_user_id == user_id,
            Project.installation_id == inst.id,
            Project.kind == "github",
            Project.deleted_at.is_(None),
            Project.status == "active",
        )
    ).all()
    linked_map: dict[int, uuid.UUID] = {
        repo_id: proj_id for repo_id, proj_id in linked_rows if repo_id is not None
    }

    items: list[GitHubRepositoryItem] = []
    for repo in remote_repos:
        linked_project_id = linked_map.get(repo.id)
        items.append(
            GitHubRepositoryItem(
                id=repo.id,
                name=repo.name,
                full_name=repo.full_name,
                default_branch=repo.default_branch,
                private=repo.private,
                archived=repo.archived,
                html_url=repo.html_url,
                connected=linked_project_id is not None,
                project_id=linked_project_id,
            )
        )
    return items


def connect_github_repository(
    session: Session,
    *,
    github_client: GitHubAppClient,
    installation_id: int,
    user_id: uuid.UUID,
    github_repo_id: int,
    name: str | None = None,
    now: datetime | None = None,
    auto_commit: bool = False,
) -> Project:
    """Connect an installation-accessible GitHub repository to a Sentinel Project."""
    inst = _get_owned_active_installation(session, installation_id=installation_id, user_id=user_id)

    try:
        remote_repos = github_client.list_installation_repositories(installation_id)
    except GitHubClientError as exc:
        raise _map_client_error(exc, "Failed to verify GitHub repository access") from exc

    target_repo: GitHubRepositoryInfo | None = next(
        (r for r in remote_repos if r.id == github_repo_id), None
    )
    if target_repo is None:
        raise GitHubRepoNotFoundError(
            "Repository is not accessible under the specified GitHub installation"
        )

    effective_name = (name.strip() if name is not None else target_repo.name)[:100]
    current_time = _normalize_datetime(now) or utc_now()

    _lock_user_for_project_write(session, user_id)

    existing_repo_proj = session.scalar(
        select(Project).where(
            Project.installation_id == inst.id,
            Project.github_repo_id == target_repo.id,
            Project.kind == "github",
        )
    )

    if existing_repo_proj is not None:
        if existing_repo_proj.owner_user_id != user_id:
            raise GitHubInstallationConflictError(
                "This GitHub repository is already connected to another Sentinel account"
            )
        if existing_repo_proj.deleted_at is None and existing_repo_proj.status == "active":
            raise GitHubInstallationConflictError(
                f"Repository '{target_repo.full_name}' is already connected"
            )

        name_conflict = session.scalar(
            select(Project.id).where(
                Project.id != existing_repo_proj.id,
                Project.owner_user_id == user_id,
                Project.deleted_at.is_(None),
                sa.func.lower(Project.name) == sa.func.lower(effective_name),
            )
        )
        if name_conflict is not None:
            raise GitHubInstallationConflictError(
                f"An active project named '{effective_name}' already exists; provide a custom name"
            )

        existing_repo_proj.name = effective_name
        existing_repo_proj.full_name = target_repo.full_name
        existing_repo_proj.default_branch = target_repo.default_branch
        existing_repo_proj.status = "active"
        existing_repo_proj.deleted_at = None
        existing_repo_proj.updated_at = current_time
        project = existing_repo_proj
    else:
        name_conflict = session.scalar(
            select(Project.id).where(
                Project.owner_user_id == user_id,
                Project.deleted_at.is_(None),
                sa.func.lower(Project.name) == sa.func.lower(effective_name),
            )
        )
        if name_conflict is not None:
            raise GitHubInstallationConflictError(
                f"An active project named '{effective_name}' already exists; provide a custom name"
            )

        project = Project(
            owner_user_id=user_id,
            name=effective_name,
            kind="github",
            installation_id=inst.id,
            github_repo_id=target_repo.id,
            full_name=target_repo.full_name,
            default_branch=target_repo.default_branch,
            status="active",
            created_at=current_time,
            updated_at=current_time,
        )
        session.add(project)

    try:
        session.flush()
        if auto_commit:
            session.commit()
            session.refresh(project)
    except IntegrityError as exc:
        session.rollback()
        if _is_unique_violation(exc):
            raise GitHubInstallationConflictError(
                f"Repository '{target_repo.full_name}' or project name '{effective_name}' conflicts with an existing project"
            ) from exc
        raise GitHubIntegrationError("Database error connecting GitHub repository") from exc

    return project
