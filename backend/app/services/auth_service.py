"""Application service layer for authentication and session management.

Implements Blueprint Section 8.1 (users and user_sessions model contracts) and Section 12
(Threat Mitigation T17: Session Security), including GitHub OAuth login state issuance,
Login CSRF nonce verification, single-use atomic state consumption, identity resolution,
and server-side UserSession lifecycle management.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import unquote, urlencode, urlsplit

import sqlalchemy as sa
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings
from app.db.base import utc_now
from app.db.models.user import AuthLoginState, User, UserSession
from app.services.github_client import (
    GitHubAuthenticationError,
    GitHubClientError,
    GitHubConfigurationError,
    GitHubNotFoundError,
    GitHubOAuthClient,
    GitHubOAuthError,
    GitHubOAuthUser,
    GitHubPermissionError,
    GitHubRateLimitError,
    redact_github_secrets,
)
from app.services.job_service import _normalize_datetime

logger = logging.getLogger("sentinel.services.auth")

GITHUB_OAUTH_LOGIN_PURPOSE = "github_oauth_login"
OAUTH_TX_COOKIE_NAME = "sentinel_oauth_tx"
SESSION_COOKIE_NAME = "sentinel_session"


class AuthServiceError(Exception):
    """Base exception for all authentication and session service operations."""


class AuthConfigurationError(AuthServiceError):
    """Raised when required GitHub OAuth authentication settings are missing or invalid."""


class AuthValidationError(AuthServiceError):
    """Raised when login initiation input (e.g. next redirect path) fails validation."""


class AuthStateError(AuthServiceError):
    """Raised when OAuth login state or transaction cookie is missing, invalid, expired, or replayed."""


class AuthAuthorizationError(AuthServiceError):
    """Raised when GitHub OAuth authorization fails or target Sentinel account is deactivated."""


class AuthConflictError(AuthServiceError):
    """Raised when an active session already belongs to a different GitHub account."""


class AuthUpstreamError(AuthServiceError):
    """Raised when upstream GitHub OAuth/API calls fail transiently or via rate limits."""

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


@dataclass(frozen=True, slots=True)
class GitHubLoginInitiation:
    """Result of initiating GitHub OAuth login."""

    authorize_url: str
    raw_tx_nonce: str
    expires_at: datetime


@dataclass(slots=True)
class GitHubLoginResult:
    """Result of completing GitHub OAuth login callback."""

    user: User
    raw_session_token: str
    expires_at: datetime
    next_path: str | None = None


def _hash_state_hex(raw_state: str) -> str:
    return hashlib.sha256(raw_state.encode("utf-8")).hexdigest()


def _hash_token_digest(raw_value: str) -> bytes:
    return hashlib.sha256(raw_value.encode("utf-8")).digest()


def _is_unique_violation(exc: IntegrityError) -> bool:
    msg = str(exc.orig).lower() if exc.orig else str(exc).lower()
    return "unique" in msg or "duplicate key" in msg


def _map_github_client_error(exc: GitHubClientError, default_context: str) -> AuthUpstreamError:
    if isinstance(exc, GitHubRateLimitError):
        return AuthUpstreamError(
            "GitHub API rate limit exceeded; please retry shortly",
            status_code=429,
            retry_after_sec=exc.retry_after_sec,
        )
    if isinstance(exc, GitHubNotFoundError):
        return AuthUpstreamError(
            f"{default_context}: resource not found on GitHub",
            status_code=502,
        )
    return AuthUpstreamError(
        f"{default_context}: {exc}",
        status_code=502,
    )


def validate_safe_next_path(next_path: str | None) -> str | None:
    """Validate that optional post-login redirect target is a strictly relative Sentinel path."""
    if next_path is None or next_path == "":
        return None
    if len(next_path) > 512:
        raise AuthValidationError("Redirect path 'next' exceeds maximum allowed length")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in next_path):
        raise AuthValidationError(
            "Redirect path 'next' must not contain whitespace or control characters"
        )
    if "\\" in next_path or "@" in next_path:
        raise AuthValidationError("Redirect path 'next' contains disallowed characters")

    decoded = unquote(next_path)
    if (
        "\\" in decoded
        or "@" in decoded
        or decoded.startswith("//")
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch in ("\r", "\n", "\t") for ch in decoded)
    ):
        raise AuthValidationError("Redirect path 'next' must be a safe relative path")

    parsed = urlsplit(next_path)
    if parsed.scheme or parsed.netloc:
        raise AuthValidationError("Redirect path 'next' must not include a scheme or host")
    if not next_path.startswith("/") or next_path.startswith(("//", "/\\")):
        raise AuthValidationError("Redirect path 'next' must start with a single '/'")

    return next_path


def initiate_github_login(
    session: Session,
    *,
    settings: Settings,
    now: datetime | None = None,
    next_path: str | None = None,
    auto_commit: bool = False,
) -> GitHubLoginInitiation:
    """Create a single-use login OAuth state bound to a transaction cookie nonce."""
    if not settings.is_github_oauth_configured() or not settings.GITHUB_CLIENT_ID:
        raise AuthConfigurationError(
            "GitHub OAuth login requires GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET"
        )

    validated_next = validate_safe_next_path(next_path)
    current_time = _normalize_datetime(now) or utc_now()
    expires_at = current_time + timedelta(seconds=settings.GITHUB_STATE_TTL_SEC)
    raw_state = secrets.token_urlsafe(32)
    raw_tx_nonce = secrets.token_urlsafe(32)

    # Best-effort cleanup of stale expired login states
    stale_cutoff = current_time - timedelta(days=1)
    session.execute(sa.delete(AuthLoginState).where(AuthLoginState.expires_at < stale_cutoff))

    redirect_uri = settings.GITHUB_AUTH_CALLBACK_URL
    state_row = AuthLoginState(
        state_hash=_hash_state_hex(raw_state),
        tx_nonce_hash=_hash_token_digest(raw_tx_nonce),
        purpose=GITHUB_OAUTH_LOGIN_PURPOSE,
        redirect_uri=redirect_uri,
        next_path=validated_next,
        expires_at=expires_at,
        created_at=current_time,
    )
    session.add(state_row)
    session.flush()
    if auto_commit:
        session.commit()

    params: dict[str, str] = {
        "client_id": settings.GITHUB_CLIENT_ID.strip(),
        "state": raw_state,
    }
    if redirect_uri:
        params["redirect_uri"] = redirect_uri

    authorize_url = (
        f"{settings.GITHUB_OAUTH_BASE_URL.rstrip('/')}/login/oauth/authorize?{urlencode(params)}"
    )
    return GitHubLoginInitiation(
        authorize_url=authorize_url,
        raw_tx_nonce=raw_tx_nonce,
        expires_at=expires_at,
    )


def _consume_login_state(
    session: Session,
    *,
    raw_state: str,
    current_time: datetime,
) -> tuple[bytes, str | None, str | None]:
    """Atomically consume valid, unexpired login state token before downstream verification."""
    cleaned_state = raw_state.strip()
    if not cleaned_state or len(cleaned_state) > 256:
        raise AuthStateError("Invalid or missing GitHub OAuth login state")

    stmt = (
        update(AuthLoginState)
        .where(
            AuthLoginState.state_hash == _hash_state_hex(cleaned_state),
            AuthLoginState.purpose == GITHUB_OAUTH_LOGIN_PURPOSE,
            AuthLoginState.used_at.is_(None),
            AuthLoginState.expires_at > current_time,
        )
        .values(used_at=current_time)
        .returning(
            AuthLoginState.tx_nonce_hash,
            AuthLoginState.redirect_uri,
            AuthLoginState.next_path,
        )
    )
    consumed = session.execute(stmt).first()
    if consumed is None:
        raise AuthStateError("Invalid, expired, or already used OAuth login state")

    # Commit single-use consumption immediately so subsequent failures never permit replay
    session.commit()
    return bytes(consumed.tx_nonce_hash), consumed.redirect_uri, consumed.next_path


def _find_active_session(
    session: Session,
    *,
    raw_token: str | None,
    current_time: datetime,
) -> UserSession | None:
    if not raw_token:
        return None
    cleaned = raw_token.strip()
    if not cleaned:
        return None

    stmt = (
        select(UserSession)
        .join(User, UserSession.user_id == User.id)
        .options(selectinload(UserSession.user))
        .where(
            UserSession.token_hash == _hash_token_digest(cleaned),
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > current_time,
            User.deleted_at.is_(None),
        )
    )
    return session.scalars(stmt).first()


def _upsert_user_from_oauth(
    session: Session,
    *,
    oauth_user: GitHubOAuthUser,
    current_time: datetime,
) -> User:
    def _apply_profile_updates(target: User) -> User:
        if target.deleted_at is not None:
            raise AuthAuthorizationError("Sentinel user account is deactivated")
        target.github_login = oauth_user.login
        if oauth_user.name is not None:
            target.display_name = oauth_user.name
        if oauth_user.avatar_url is not None:
            target.avatar_url = oauth_user.avatar_url
        target.last_login_at = current_time
        return target

    stmt = select(User).where(User.github_user_id == oauth_user.id)
    bind = session.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        stmt = stmt.with_for_update()

    existing = session.scalars(stmt).first()
    if existing is not None:
        return _apply_profile_updates(existing)

    new_user = User(
        github_user_id=oauth_user.id,
        github_login=oauth_user.login,
        display_name=oauth_user.name,
        avatar_url=oauth_user.avatar_url,
        last_login_at=current_time,
    )
    try:
        with session.begin_nested():
            session.add(new_user)
            session.flush()
    except IntegrityError as exc:
        if not _is_unique_violation(exc):
            raise
        race_stmt = select(User).where(User.github_user_id == oauth_user.id)
        if bind is not None and bind.dialect.name == "postgresql":
            race_stmt = race_stmt.with_for_update()
        existing_after_race = session.scalars(race_stmt).first()
        if existing_after_race is None:
            raise
        return _apply_profile_updates(existing_after_race)

    return new_user


def complete_github_login_callback(
    session: Session,
    *,
    settings: Settings,
    oauth_client: GitHubOAuthClient,
    state: str,
    tx_nonce: str | None,
    code: str | None = None,
    oauth_error: str | None = None,
    existing_session_token: str | None = None,
    now: datetime | None = None,
    auto_commit: bool = False,
) -> GitHubLoginResult:
    """Validate OAuth login callback, resolve Sentinel User, and issue a fresh UserSession.

    Session rotation & multi-device policy:
    - Multi-device logins are supported: logging in from another browser/device issues a new
      independent UserSession without revoking sessions held on other devices.
    - Cross-account conflict: if the caller presents an active session belonging to a different
      GitHub user, fail closed with AuthConflictError (409) without modifying existing sessions.
    - Same-user caller rotation (session fixation defense): if the caller presents an active
      session for the same GitHub user, only that caller-presented session (which the browser
      cookie is about to replace) is revoked before minting a new session token.
    """
    if not settings.is_github_oauth_configured():
        raise AuthConfigurationError(
            "GitHub OAuth login requires GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET"
        )

    current_time = _normalize_datetime(now) or utc_now()
    expected_tx_hash, stored_redirect_uri, stored_next_path = _consume_login_state(
        session,
        raw_state=state,
        current_time=current_time,
    )

    cleaned_tx = tx_nonce.strip() if isinstance(tx_nonce, str) else ""
    if not cleaned_tx or len(cleaned_tx) > 256:
        raise AuthStateError("Missing or invalid OAuth transaction cookie")
    if not hmac.compare_digest(expected_tx_hash, _hash_token_digest(cleaned_tx)):
        raise AuthStateError("OAuth transaction cookie mismatch")

    if oauth_error is not None and oauth_error.strip():
        if oauth_error.strip().lower() == "access_denied":
            raise AuthAuthorizationError("GitHub OAuth login was denied by the user")
        raise AuthAuthorizationError("GitHub OAuth login authorization failed")

    cleaned_code = code.strip() if isinstance(code, str) and code.strip() else None
    if cleaned_code is None:
        raise AuthAuthorizationError("Missing GitHub OAuth authorization code")

    user_access_token = ""
    try:
        try:
            user_access_token = oauth_client.exchange_oauth_code(
                cleaned_code,
                redirect_uri=stored_redirect_uri,
            )
            oauth_user = oauth_client.get_oauth_user(user_access_token)
        except GitHubConfigurationError as exc:
            raise AuthConfigurationError(str(exc)) from exc
        except (GitHubOAuthError, GitHubAuthenticationError, GitHubPermissionError) as exc:
            raise AuthAuthorizationError(str(exc)) from exc
        except GitHubClientError as exc:
            raise _map_github_client_error(exc, "Failed to verify GitHub OAuth login") from exc
    finally:
        user_access_token = ""

    prior_session = _find_active_session(
        session,
        raw_token=existing_session_token,
        current_time=current_time,
    )
    if prior_session is not None:
        if prior_session.user.github_user_id != oauth_user.id:
            raise AuthConflictError(
                "An active session belongs to a different GitHub account; log out first"
            )
        prior_session.revoked_at = current_time

    user = _upsert_user_from_oauth(
        session,
        oauth_user=oauth_user,
        current_time=current_time,
    )

    raw_session_token = secrets.token_urlsafe(32)
    session_expires_at = current_time + timedelta(seconds=settings.SESSION_TTL_SEC)
    user_session = UserSession(
        user_id=user.id,
        token_hash=_hash_token_digest(raw_session_token),
        expires_at=session_expires_at,
        created_at=current_time,
    )
    session.add(user_session)
    session.flush()
    if auto_commit:
        session.commit()
        session.refresh(user)

    safe_next_path = validate_safe_next_path(stored_next_path)
    return GitHubLoginResult(
        user=user,
        raw_session_token=raw_session_token,
        expires_at=session_expires_at,
        next_path=safe_next_path,
    )


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
