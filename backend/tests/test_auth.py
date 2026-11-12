"""Integration and security tests for Current User and Authentication endpoints.

Validates:
- GET /me and GET /api/v1/me (safe user profile, tenant identity)
- POST /logout and POST /api/v1/logout (session revocation, cookie invalidation)
- Threat Mitigation T17 (Session Security)
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Generator
from datetime import timedelta
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.auth import get_github_oauth_client
from app.core.config import Settings, get_settings
from app.db.base import Base, utc_now
from app.db.models.user import AuthLoginState, User, UserSession
from app.db.session import get_db_session, session_scope
from app.main import app
from app.services.github_client import GitHubOAuthClient
from tests.test_github_client import _encode_rsa_pkcs8_pem, _generate_rsa_keypair


@pytest.fixture
def test_engine() -> Engine:
    """Isolated in-memory SQLite engine with foreign key constraints enabled."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session_factory(test_engine: Engine) -> sessionmaker[Session]:
    """Session factory for the isolated test database."""
    return sessionmaker(bind=test_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def db_session(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Isolated database session fixture."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_user(db_session: Session) -> User:
    """Create a persistent user in the test database."""
    user = User(
        github_user_id=1001,
        github_login="alice-dev",
        display_name="Alice Developer",
        avatar_url="https://avatars.githubusercontent.com/u/1001",
    )
    db_session.add(user)
    db_session.commit()
    return user


def create_test_session(
    db_session: Session,
    user: User,
    *,
    expires_in_days: int = 1,
    revoked: bool = False,
) -> tuple[str, UserSession]:
    """Helper to create a server-side session and return (raw_token, UserSession)."""
    raw_token = f"test-token-{uuid.uuid4().hex}-{user.id}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).digest()
    now = utc_now()
    user_session = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash,
        expires_at=now + timedelta(days=expires_in_days),
        revoked_at=now if revoked else None,
    )
    db_session.add(user_session)
    db_session.commit()
    return raw_token, user_session


@pytest.fixture
def client_factory(
    session_factory: sessionmaker[Session],
) -> Generator[Any, None, None]:
    """Factory fixture for TestClients with dependency override."""

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session

    def _create_client(**kwargs: Any) -> TestClient:
        return TestClient(app, **kwargs)

    yield _create_client
    app.dependency_overrides.clear()


@pytest.fixture
def unauthenticated_client(client_factory: Any) -> TestClient:
    """Unauthenticated TestClient."""
    return client_factory()


class TestCurrentUserEndpoint:
    """Integration and security tests for GET /me and GET /api/v1/me."""

    def test_get_me_success_bearer(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Valid Bearer-authenticated user retrieves their profile successfully."""
        raw_token, _ = create_test_session(db_session, sample_user)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.get("/api/v1/me")
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == str(sample_user.id)
        assert data["github_user_id"] == 1001
        assert data["github_login"] == "alice-dev"
        assert data["display_name"] == "Alice Developer"
        assert data["avatar_url"] == "https://avatars.githubusercontent.com/u/1001"
        assert "created_at" in data
        assert data["last_login_at"] is None

    def test_get_me_success_cookie(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Valid cookie-authenticated user retrieves their profile successfully."""
        raw_token, _ = create_test_session(db_session, sample_user)
        client = client_factory(cookies={"sentinel_session": raw_token})

        resp = client.get("/api/v1/me")
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == str(sample_user.id)
        assert data["github_login"] == "alice-dev"

    def test_get_me_root_and_v1_parity(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Both /me and /api/v1/me return identical profile responses."""
        raw_token, _ = create_test_session(db_session, sample_user)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp_root = client.get("/me")
        resp_v1 = client.get("/api/v1/me")

        assert resp_root.status_code == 200
        assert resp_v1.status_code == 200
        assert resp_root.json() == resp_v1.json()

    def test_get_me_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
    ) -> None:
        """Unauthenticated requests fail with HTTP 401."""
        resp = unauthenticated_client.get("/api/v1/me")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_get_me_invalid_token_returns_401(
        self,
        client_factory: Any,
    ) -> None:
        """An unknown or forged token fails with HTTP 401."""
        client = client_factory(headers={"Authorization": "Bearer forged-token-abc"})
        resp = client.get("/api/v1/me")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_get_me_expired_session_returns_401(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """An expired session fails with HTTP 401."""
        raw_token, _ = create_test_session(db_session, sample_user, expires_in_days=-1)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.get("/api/v1/me")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_get_me_revoked_session_returns_401(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """A revoked session fails with HTTP 401."""
        raw_token, _ = create_test_session(db_session, sample_user, revoked=True)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.get("/api/v1/me")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_get_me_soft_deleted_user_returns_401(
        self,
        client_factory: Any,
        db_session: Session,
    ) -> None:
        """A soft-deleted user cannot authenticate and returns HTTP 401."""
        deleted_user = User(
            github_user_id=9999,
            github_login="deleted-user",
            deleted_at=utc_now(),
        )
        db_session.add(deleted_user)
        db_session.commit()

        raw_token, _ = create_test_session(db_session, deleted_user)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.get("/api/v1/me")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_get_me_response_schema_isolation(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Response model exposes strictly the defined safe profile fields and no internals."""
        raw_token, _ = create_test_session(db_session, sample_user)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.get("/api/v1/me")
        assert resp.status_code == 200
        data = resp.json()

        allowed_keys = {
            "id",
            "github_user_id",
            "github_login",
            "display_name",
            "avatar_url",
            "created_at",
            "last_login_at",
        }
        assert set(data.keys()) == allowed_keys
        assert "token" not in data
        assert "token_hash" not in data
        assert "deleted_at" not in data
        assert "sessions" not in data


class TestLogoutEndpoint:
    """Integration and security tests for POST /logout and POST /api/v1/logout."""

    def test_logout_success_bearer(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Authenticated logout via Bearer token revokes the session in the database."""
        raw_token, session_record = create_test_session(db_session, sample_user)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.post("/api/v1/logout")
        assert resp.status_code == 204
        assert resp.content == b""
        assert resp.text == ""

        # Verify DB revocation
        db_session.expire_all()
        refreshed = db_session.get(UserSession, session_record.id)
        assert refreshed is not None
        assert refreshed.revoked_at is not None

    def test_logout_success_cookie_clears_cookie(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Authenticated logout via cookie clears the sentinel_session cookie."""
        raw_token, session_record = create_test_session(db_session, sample_user)
        client = client_factory(cookies={"sentinel_session": raw_token})

        resp = client.post("/api/v1/logout")
        assert resp.status_code == 204
        assert resp.content == b""

        # Verify Set-Cookie header invalidates sentinel_session
        set_cookie = resp.headers.get("set-cookie", "")
        assert "sentinel_session=" in set_cookie
        # Cookie expiration or max-age 0 indicates clearing
        assert "max-age=0" in set_cookie.lower() or "expires=" in set_cookie.lower()
        assert "path=/" in set_cookie.lower()
        assert "httponly" in set_cookie.lower()

        # Verify DB revocation
        db_session.expire_all()
        refreshed = db_session.get(UserSession, session_record.id)
        assert refreshed is not None
        assert refreshed.revoked_at is not None

    def test_logout_immediately_invalidates_credential(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """The revoked session credential fails on the very next authenticated request."""
        raw_token, _ = create_test_session(db_session, sample_user)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        # 1. Before logout: /me succeeds
        assert client.get("/api/v1/me").status_code == 200

        # 2. Perform logout
        logout_resp = client.post("/api/v1/logout")
        assert logout_resp.status_code == 204

        # 3. Immediately after logout: /me fails with 401
        assert client.get("/api/v1/me").status_code == 401

    def test_logout_scoped_to_current_session(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Logging out of one session does not revoke other active sessions of the same user."""
        token_1, session_1 = create_test_session(db_session, sample_user)
        token_2, session_2 = create_test_session(db_session, sample_user)

        client_1 = client_factory(headers={"Authorization": f"Bearer {token_1}"})
        client_2 = client_factory(headers={"Authorization": f"Bearer {token_2}"})

        # Logout session 1
        assert client_1.post("/api/v1/logout").status_code == 204

        # Session 1 is revoked
        assert client_1.get("/api/v1/me").status_code == 401

        # Session 2 is still valid
        assert client_2.get("/api/v1/me").status_code == 200

        db_session.expire_all()
        assert db_session.get(UserSession, session_1.id).revoked_at is not None
        assert db_session.get(UserSession, session_2.id).revoked_at is None

    def test_logout_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
    ) -> None:
        """Unauthenticated logout requests fail with HTTP 401."""
        resp = unauthenticated_client.post("/api/v1/logout")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_logout_already_revoked_session_returns_401(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Attempting to log out an already-revoked session fails with HTTP 401."""
        raw_token, _ = create_test_session(db_session, sample_user, revoked=True)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.post("/api/v1/logout")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_logout_expired_session_returns_401(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Attempting to log out an expired session fails with HTTP 401."""
        raw_token, _ = create_test_session(db_session, sample_user, expires_in_days=-1)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        resp = client.post("/api/v1/logout")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_logout_root_and_v1_parity(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Both /logout and /api/v1/logout routes behave identically."""
        token_root, sess_root = create_test_session(db_session, sample_user)
        token_v1, sess_v1 = create_test_session(db_session, sample_user)

        client_root = client_factory(headers={"Authorization": f"Bearer {token_root}"})
        client_v1 = client_factory(headers={"Authorization": f"Bearer {token_v1}"})

        r_root = client_root.post("/logout")
        r_v1 = client_v1.post("/api/v1/logout")

        assert r_root.status_code == 204
        assert r_v1.status_code == 204

        db_session.expire_all()
        assert db_session.get(UserSession, sess_root.id).revoked_at is not None
        assert db_session.get(UserSession, sess_v1.id).revoked_at is not None

    def test_logout_database_failure_mapped_to_500_and_rolled_back(
        self,
        client_factory: Any,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Database errors during session revocation map to HTTP 500 and roll back."""
        raw_token, session_record = create_test_session(db_session, sample_user)
        client = client_factory(headers={"Authorization": f"Bearer {raw_token}"})

        with patch.object(Session, "flush", side_effect=Exception("Simulated DB failure")):
            resp = client.post("/api/v1/logout")

        assert resp.status_code == 500
        assert resp.json()["detail"] == "An internal error occurred while logging out."

        # Verify rollback: session remains active (revoked_at is None)
        db_session.expire_all()
        refreshed = db_session.get(UserSession, session_record.id)
        assert refreshed is not None
        assert refreshed.revoked_at is None


def _make_oauth_settings(
    *,
    configured: bool = True,
    production: bool = False,
    callback_url: str | None = "https://sentinel.example.com/auth/github/callback",
    session_ttl_sec: int = 3600,
) -> Settings:
    if production:
        strong = SecretStr("abcdefghijklmnopqrstuvwxyz0123456789")
        pem = _encode_rsa_pkcs8_pem(_generate_rsa_keypair(2048))
        return Settings(
            APP_ENV="production",
            AI_DEBUG_LOG=False,
            SECRET_KEY=strong,
            SESSION_SECRET=strong,
            FINGERPRINT_KEY=strong,
            GITLEAKS_PATH=os.path.abspath("/usr/local/bin/gitleaks"),
            GITHUB_APP_ID=999001 if configured else None,
            GITHUB_WEBHOOK_SECRET=(
                SecretStr("webhook_prod_secret_with_sufficient_entropy_1234")
                if configured
                else None
            ),
            GITHUB_APP_PRIVATE_KEY=SecretStr(pem) if configured else None,
            GITHUB_APP_SLUG="sentinel-security-bot" if configured else None,
            GITHUB_CLIENT_ID="Iv1.sentinelprodclient" if configured else None,
            GITHUB_CLIENT_SECRET=(
                SecretStr("oauth_prod_secret_test_value_123456") if configured else None
            ),
            GITHUB_AUTH_CALLBACK_URL=callback_url if configured else None,
            SESSION_TTL_SEC=session_ttl_sec,
        )
    return Settings(
        APP_ENV="development",
        GITHUB_CLIENT_ID="Iv1.sentineltestclient" if configured else None,
        GITHUB_CLIENT_SECRET=(
            SecretStr("oauth_dev_secret_test_value_123456") if configured else None
        ),
        GITHUB_AUTH_CALLBACK_URL=callback_url if configured else None,
        GITHUB_STATE_TTL_SEC=300,
        SESSION_TTL_SEC=session_ttl_sec,
    )


def _extract_state_from_authorize_url(authorize_url: str) -> str:
    parsed = urlparse(authorize_url)
    return parse_qs(parsed.query)["state"][0]


class TestGitHubOAuthLoginFlow:
    """Comprehensive tests for GET /auth/github/login and GET /auth/github/callback."""

    def _setup_oauth_client(
        self,
        session_factory: sessionmaker[Session],
        settings: Settings,
        handler: Any,
        *,
        follow_redirects: bool = False,
        base_url: str = "http://testserver",
    ) -> Generator[TestClient, None, None]:
        def override_db() -> Generator[Session, None, None]:
            with session_scope(session_factory) as session:
                yield session

        def override_settings() -> Settings:
            return settings

        def override_oauth_client() -> Generator[GitHubOAuthClient, None, None]:
            client = GitHubOAuthClient.from_oauth_settings(
                settings,
                transport=httpx.MockTransport(handler),
                sleep_fn=lambda _s: None,
            )
            try:
                yield client
            finally:
                client.close()

        app.dependency_overrides[get_db_session] = override_db
        app.dependency_overrides[get_settings] = override_settings
        app.dependency_overrides[get_github_oauth_client] = override_oauth_client
        try:
            with TestClient(app, base_url=base_url, follow_redirects=follow_redirects) as client:
                yield client
        finally:
            app.dependency_overrides.clear()

    def test_first_time_login_issues_hashed_session_and_cookie_attributes(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
    ) -> None:
        tok_alice = "ghu" + "_" + "loginalice123456"
        seen_token_forms: list[str] = []

        def gh_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login/oauth/access_token":
                seen_token_forms.append(request.content.decode("utf-8"))
                return httpx.Response(200, json={"access_token": tok_alice, "token_type": "bearer"})
            if request.url.path == "/user":
                return httpx.Response(
                    200,
                    json={
                        "id": 9001,
                        "login": "alice-gh",
                        "name": "Alice OAuth",
                        "avatar_url": "https://avatars.githubusercontent.com/u/9001",
                    },
                )
            return httpx.Response(404)

        settings = _make_oauth_settings(configured=True, session_ttl_sec=7200)
        for client in self._setup_oauth_client(session_factory, settings, gh_handler):
            init_resp = client.get("/auth/github/login")
            assert init_resp.status_code == 200
            assert init_resp.headers.get("cache-control") == "no-store"
            auth_url = init_resp.json()["authorize_url"]
            raw_state = _extract_state_from_authorize_url(auth_url)
            tx_cookie = client.cookies.get("sentinel_oauth_tx")
            assert tx_cookie

            # State and tx nonce must be stored as SHA-256 digests only
            state_row = db_session.scalars(select(AuthLoginState)).one()
            assert state_row.purpose == "github_oauth_login"
            assert state_row.state_hash != raw_state
            assert state_row.state_hash == hashlib.sha256(raw_state.encode("utf-8")).hexdigest()
            assert state_row.tx_nonce_hash == hashlib.sha256(tx_cookie.encode("utf-8")).digest()
            assert state_row.used_at is None

            cb_resp = client.get(f"/auth/github/callback?code=auth-code-1&state={raw_state}")
            assert cb_resp.status_code == 200
            assert cb_resp.headers.get("cache-control") == "no-store"
            body = cb_resp.json()
            assert set(body.keys()) == {"user", "expires_at"}
            assert body["user"]["github_user_id"] == 9001
            assert body["user"]["github_login"] == "alice-gh"
            assert body["user"]["display_name"] == "Alice OAuth"
            assert "token" not in body

            # Inspect cookie attributes directly from Set-Cookie headers
            set_cookies = cb_resp.headers.get_list("set-cookie")
            session_header = next(h for h in set_cookies if h.startswith("sentinel_session="))
            assert "HttpOnly" in session_header
            assert "SameSite=lax" in session_header or "SameSite=Lax" in session_header
            assert "Path=/" in session_header
            assert "Max-Age=7200" in session_header

            # Verify DB session stores only SHA-256 hash
            raw_session_tok = client.cookies.get("sentinel_session")
            assert raw_session_tok
            assert not client.cookies.get("sentinel_oauth_tx")
            db_session.expire_all()
            sess_row = db_session.scalars(select(UserSession)).one()
            assert sess_row.token_hash == hashlib.sha256(raw_session_tok.encode("utf-8")).digest()
            assert sess_row.revoked_at is None

            # Authenticated /me & /api/v1/me work immediately
            me_resp = client.get("/api/v1/me")
            assert me_resp.status_code == 200
            assert me_resp.json()["github_user_id"] == 9001

            # Logout revokes DB session and clears access
            logout_resp = client.post("/logout")
            assert logout_resp.status_code == 204
            assert client.get("/me").status_code == 401

        assert (
            "redirect_uri=https%3A%2F%2Fsentinel.example.com%2Fauth%2Fgithub%2Fcallback"
            in seen_token_forms[0]
        )

    def test_existing_user_handle_rename_preserves_identity_and_updates_profile(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
    ) -> None:
        existing_user = User(
            github_user_id=4242,
            github_login="old-handle",
            display_name="Old Name",
            avatar_url="https://avatars.githubusercontent.com/u/4242?v=1",
        )
        db_session.add(existing_user)
        db_session.commit()
        original_id = existing_user.id

        tok = "ghu" + "_" + "renameuser123456"

        def gh_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login/oauth/access_token":
                return httpx.Response(200, json={"access_token": tok, "token_type": "bearer"})
            if request.url.path == "/user":
                return httpx.Response(
                    200,
                    json={
                        "id": 4242,
                        "login": "new-handle",
                        "name": "New Name",
                        "avatar_url": "https://avatars.githubusercontent.com/u/4242?v=2",
                    },
                )
            return httpx.Response(404)

        settings = _make_oauth_settings(configured=True)
        for client in self._setup_oauth_client(session_factory, settings, gh_handler):
            init_resp = client.get("/api/v1/auth/github/login")
            raw_state = _extract_state_from_authorize_url(init_resp.json()["authorize_url"])
            cb_resp = client.get(f"/api/v1/auth/github/callback?code=c1&state={raw_state}")
            assert cb_resp.status_code == 200
            data = cb_resp.json()
            assert data["user"]["id"] == str(original_id)
            assert data["user"]["github_user_id"] == 4242
            assert data["user"]["github_login"] == "new-handle"
            assert data["user"]["display_name"] == "New Name"

            db_session.expire_all()
            assert len(db_session.scalars(select(User)).all()) == 1

    def test_soft_deleted_user_rejected_fail_closed(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
    ) -> None:
        deleted_user = User(
            github_user_id=5555,
            github_login="deactivated-dev",
            deleted_at=utc_now(),
        )
        db_session.add(deleted_user)
        db_session.commit()

        tok = "ghu" + "_" + "deleteduser123456"

        def gh_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login/oauth/access_token":
                return httpx.Response(200, json={"access_token": tok, "token_type": "bearer"})
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 5555, "login": "deactivated-dev"})
            return httpx.Response(404)

        settings = _make_oauth_settings(configured=True)
        for client in self._setup_oauth_client(session_factory, settings, gh_handler):
            init_resp = client.get("/auth/github/login")
            raw_state = _extract_state_from_authorize_url(init_resp.json()["authorize_url"])
            cb_resp = client.get(f"/auth/github/callback?code=c-del&state={raw_state}")
            assert cb_resp.status_code == 403
            assert not client.cookies.get("sentinel_session")
            db_session.expire_all()
            assert db_session.scalars(select(UserSession)).all() == []

    def test_session_fixation_rotates_same_user_and_rejects_different_user_409(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
    ) -> None:
        alice = User(github_user_id=1010, github_login="alice")
        db_session.add(alice)
        db_session.commit()
        old_token, old_session = create_test_session(db_session, alice)

        tok_alice = "ghu" + "_" + "alicefixation123456"
        tok_bob = "ghu" + "_" + "bobsubstitution123456"

        def gh_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login/oauth/access_token":
                body = request.content.decode("utf-8")
                return httpx.Response(
                    200,
                    json={
                        "access_token": tok_bob if "code=bob-code" in body else tok_alice,
                        "token_type": "bearer",
                    },
                )
            if request.url.path == "/user":
                auth = request.headers.get("Authorization", "")
                if tok_bob in auth:
                    return httpx.Response(200, json={"id": 2020, "login": "bob"})
                return httpx.Response(200, json={"id": 1010, "login": "alice"})
            return httpx.Response(404)

        settings = _make_oauth_settings(configured=True)
        for client in self._setup_oauth_client(session_factory, settings, gh_handler):
            # 1. Existing session signed in as alice -> re-login as bob must return 409 Conflict
            client.cookies.set("sentinel_session", old_token, domain="testserver.local")
            init1 = client.get("/auth/github/login")
            st1 = _extract_state_from_authorize_url(init1.json()["authorize_url"])
            conflict = client.get(f"/auth/github/callback?code=bob-code&state={st1}")
            assert conflict.status_code == 409

            db_session.expire_all()
            assert db_session.get(UserSession, old_session.id).revoked_at is None

            # 2. Same user (alice) logging in while holding old_token -> rotates session
            init2 = client.get("/auth/github/login")
            st2 = _extract_state_from_authorize_url(init2.json()["authorize_url"])
            ok = client.get(f"/auth/github/callback?code=alice-code&state={st2}")
            assert ok.status_code == 200

            new_token = client.cookies.get("sentinel_session", domain="testserver.local")
            assert new_token
            assert new_token != old_token

            db_session.expire_all()
            assert db_session.get(UserSession, old_session.id).revoked_at is not None

            # Old session token no longer accepted (use a clean client without the new cookie)
            with TestClient(app) as clean_client:
                assert (
                    clean_client.get(
                        "/me", headers={"Authorization": f"Bearer {old_token}"}
                    ).status_code
                    == 401
                )
            assert client.get("/me").status_code == 200

    def test_csrf_tx_cookie_replay_expiry_and_error_handling(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
    ) -> None:
        tok = "ghu" + "_" + "csrfuser1234567890"

        def gh_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login/oauth/access_token":
                if "code=bad-code" in request.content.decode("utf-8"):
                    return httpx.Response(200, json={"error": "bad_verification_code"})
                if "code=boom-code" in request.content.decode("utf-8"):
                    return httpx.Response(502, text="bad gateway")
                return httpx.Response(200, json={"access_token": tok, "token_type": "bearer"})
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 3131, "login": "csrf-alice"})
            return httpx.Response(404)

        settings = _make_oauth_settings(configured=True)
        for client in self._setup_oauth_client(session_factory, settings, gh_handler):
            # Missing / wrong tx cookie fails 403 AND consumes state so later replay also fails 403
            init1 = client.get("/auth/github/login")
            st1 = _extract_state_from_authorize_url(init1.json()["authorize_url"])
            real_tx = client.cookies.get("sentinel_oauth_tx")
            assert real_tx

            client.cookies.delete("sentinel_oauth_tx")
            no_tx_resp = client.get(f"/auth/github/callback?code=good&state={st1}")
            assert no_tx_resp.status_code == 403

            client.cookies.set("sentinel_oauth_tx", real_tx, domain="testserver.local")
            replay_after_no_tx = client.get(f"/auth/github/callback?code=good&state={st1}")
            assert replay_after_no_tx.status_code == 403

            # Wrong tx cookie
            init2 = client.get("/auth/github/login")
            st2 = _extract_state_from_authorize_url(init2.json()["authorize_url"])
            client.cookies.set(
                "sentinel_oauth_tx",
                "attacker-forged-tx-nonce",
                domain="testserver.local",
            )
            bad_tx_resp = client.get(f"/auth/github/callback?code=good&state={st2}")
            assert bad_tx_resp.status_code == 403

            # User denied OAuth
            init3 = client.get("/auth/github/login")
            st3 = _extract_state_from_authorize_url(init3.json()["authorize_url"])
            denied = client.get(f"/auth/github/callback?state={st3}&error=access_denied")
            assert denied.status_code == 403
            assert client.get(f"/auth/github/callback?code=good&state={st3}").status_code == 403

            # Bad verification code -> 403 and no replay
            init4 = client.get("/auth/github/login")
            st4 = _extract_state_from_authorize_url(init4.json()["authorize_url"])
            bad_code = client.get(f"/auth/github/callback?code=bad-code&state={st4}")
            assert bad_code.status_code == 403

            # Upstream 5xx -> 502 and no replay
            init5 = client.get("/auth/github/login")
            st5 = _extract_state_from_authorize_url(init5.json()["authorize_url"])
            upstream_err = client.get(f"/auth/github/callback?code=boom-code&state={st5}")
            assert upstream_err.status_code == 502

            # Expired state row rejected
            init6 = client.get("/auth/github/login")
            st6 = _extract_state_from_authorize_url(init6.json()["authorize_url"])
            row = db_session.scalars(
                select(AuthLoginState).where(
                    AuthLoginState.state_hash == hashlib.sha256(st6.encode("utf-8")).hexdigest()
                )
            ).one()
            row.expires_at = utc_now() - timedelta(seconds=5)
            db_session.commit()
            assert client.get(f"/auth/github/callback?code=good&state={st6}").status_code == 403

            # Unknown state rejected
            assert (
                client.get(
                    "/auth/github/callback?code=good&state=completely-unknown-state"
                ).status_code
                == 403
            )

            # Successful login state cannot be replayed once consumed
            init7 = client.get("/auth/github/login")
            st7 = _extract_state_from_authorize_url(init7.json()["authorize_url"])
            ok = client.get(f"/auth/github/callback?code=good&state={st7}")
            assert ok.status_code == 200
            replay = client.get(f"/auth/github/callback?code=good&state={st7}")
            assert replay.status_code == 403

    def test_open_redirect_protection_and_safe_next_redirect_and_production_secure_cookie(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        tok = "ghu" + "_" + "redirectuser123456"

        def gh_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login/oauth/access_token":
                return httpx.Response(200, json={"access_token": tok, "token_type": "bearer"})
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 6161, "login": "redir-alice"})
            return httpx.Response(404)

        prod_settings = _make_oauth_settings(configured=True, production=True)
        for client in self._setup_oauth_client(
            session_factory,
            prod_settings,
            gh_handler,
            base_url="https://testserver",
        ):
            for unsafe_next in (
                "//evil.com",
                "https://evil.com/phish",
                "/\\evil.com",
                "/%5cevil.com",
                "/@evil.com",
                "relative-without-slash",
            ):
                bad = client.get("/auth/github/login", params={"next": unsafe_next})
                assert bad.status_code == 400, f"Expected 400 for {unsafe_next!r}"

            # redirect=true issues 302 to GitHub authorize URL with tx cookie (Secure in prod)
            safe_next = "/integrations/github/install?redirect=true"
            redir_init = client.get(
                "/auth/github/login",
                params={"next": safe_next, "redirect": "true"},
            )
            assert redir_init.status_code == 302
            raw_state = _extract_state_from_authorize_url(redir_init.headers["location"])
            tx_header = next(
                h
                for h in redir_init.headers.get_list("set-cookie")
                if h.startswith("sentinel_oauth_tx=")
            )
            assert "Secure" in tx_header
            assert "HttpOnly" in tx_header

            # Attacker ?next=https://evil.com on callback is ignored; DB-stored safe_next is used
            cb = client.get(
                f"/auth/github/callback?code=good&state={raw_state}&next=https://evil.com"
            )
            assert cb.status_code == 302
            assert cb.headers["location"] == safe_next
            sess_header = next(
                h for h in cb.headers.get_list("set-cookie") if h.startswith("sentinel_session=")
            )
            assert "Secure" in sess_header
            assert "HttpOnly" in sess_header

    def test_unconfigured_oauth_returns_503(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        settings = _make_oauth_settings(configured=False)

        def override_db() -> Generator[Session, None, None]:
            with session_scope(session_factory) as session:
                yield session

        app.dependency_overrides[get_db_session] = override_db
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            with TestClient(app) as client:
                assert client.get("/auth/github/login").status_code == 503
                assert client.get("/auth/github/callback?code=abc&state=xyz").status_code == 503
        finally:
            app.dependency_overrides.clear()

    def test_multi_device_login_preserves_other_active_sessions_and_expiry(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
    ) -> None:
        """Logging in from Device B preserves Device A's active session; expiry invalidates only expired session."""
        tok = "ghu" + "_" + "multidevice123456"

        def gh_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/login/oauth/access_token":
                return httpx.Response(200, json={"access_token": tok, "token_type": "bearer"})
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 7373, "login": "multi-alice"})
            return httpx.Response(404)

        settings = _make_oauth_settings(configured=True, callback_url=None)
        token_a = ""
        token_b = ""

        # Device A signs in
        for client_a in self._setup_oauth_client(session_factory, settings, gh_handler):
            init_a = client_a.get("/auth/github/login")
            st_a = _extract_state_from_authorize_url(init_a.json()["authorize_url"])
            assert "redirect_uri=" not in init_a.json()["authorize_url"]
            cb_a = client_a.get(f"/auth/github/callback?code=code-a&state={st_a}")
            assert cb_a.status_code == 200
            token_a = client_a.cookies.get("sentinel_session", domain="testserver.local") or ""
            assert token_a

        # Device B signs in separately (does NOT send Device A's cookie)
        for client_b in self._setup_oauth_client(session_factory, settings, gh_handler):
            init_b = client_b.get("/auth/github/login")
            st_b = _extract_state_from_authorize_url(init_b.json()["authorize_url"])
            cb_b = client_b.get(f"/auth/github/callback?code=code-b&state={st_b}")
            assert cb_b.status_code == 200
            token_b = client_b.cookies.get("sentinel_session", domain="testserver.local") or ""
            assert token_b
            assert token_b != token_a

            # Both Device A and Device B sessions remain active simultaneously
            db_session.expire_all()
            sessions = db_session.scalars(select(UserSession)).all()
            assert len(sessions) == 2
            assert all(s.revoked_at is None for s in sessions)

            # Logging out Device B revokes only Device B; Device A stays authenticated
            logout_b = client_b.post("/logout")
            assert logout_b.status_code == 204
            assert logout_b.headers.get("cache-control") == "no-store"
            assert (
                client_b.get("/me", headers={"Authorization": f"Bearer {token_b}"}).status_code
                == 401
            )
            assert (
                client_b.get("/me", headers={"Authorization": f"Bearer {token_a}"}).status_code
                == 200
            )

            # Expiring Device A's session invalidates it cleanly
            hash_a = hashlib.sha256(token_a.encode("utf-8")).digest()
            sess_a = db_session.scalars(
                select(UserSession).where(UserSession.token_hash == hash_a)
            ).one()
            sess_a.expires_at = utc_now() - timedelta(seconds=1)
            db_session.commit()
            assert (
                client_b.get("/me", headers={"Authorization": f"Bearer {token_a}"}).status_code
                == 401
            )
