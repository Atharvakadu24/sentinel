"""Integration and security tests for Current User and Authentication endpoints.

Validates:
- GET /me and GET /api/v1/me (safe user profile, tenant identity)
- POST /logout and POST /api/v1/logout (session revocation, cookie invalidation)
- Threat Mitigation T17 (Session Security)
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Generator
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models.user import User, UserSession
from app.db.session import get_db_session, session_scope
from app.main import app


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

