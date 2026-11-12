"""Integration and security tests for Sentinel GitHub App milestone."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import uuid
from collections.abc import Generator
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.auth import get_github_oauth_client
from app.api.github import get_github_client
from app.core.config import Settings, get_settings
from app.db.base import Base, utc_now
from app.db.models import (
    Finding,
    GitHubInstallation,
    GitHubInstallState,
    Job,
    Project,
    Scan,
    User,
    UserSession,
    WebhookEvent,
)
from app.db.session import get_db_session
from app.domain.findings import (
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
)
from app.main import app
from app.services.github_client import GitHubAppClient, GitHubOAuthClient
from app.worker.composite import CompositeScannerEngine
from app.worker.runner import JobWorker
from app.worker.scanner import (
    ScanExecutionResult,
    ScanJobPayload,
    ScannerInterface,
    ScanStatus,
)
from tests.test_github_client import _encode_rsa_pkcs8_pem, _generate_rsa_keypair


@pytest.fixture(scope="module")
def github_test_pem() -> str:
    return _encode_rsa_pkcs8_pem(_generate_rsa_keypair(2048))


@pytest.fixture
def test_engine() -> Engine:
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
    return sessionmaker(bind=test_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def db_session(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def tenant_a(db_session: Session) -> User:
    user = User(github_user_id=101, github_login="alice", display_name="Alice")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def tenant_b(db_session: Session) -> User:
    user = User(github_user_id=202, github_login="bob", display_name="Bob")
    db_session.add(user)
    db_session.commit()
    return user


def _auth_headers(db_session: Session, user: User) -> dict[str, str]:
    raw_token = f"session-{uuid.uuid4().hex}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).digest()
    now = utc_now()
    db_session.add(
        UserSession(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now + timedelta(days=1),
        )
    )
    db_session.commit()
    return {"Authorization": f"Bearer {raw_token}"}


def _sign_webhook(secret: str, raw_body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _make_settings(
    pem: str,
    *,
    configured: bool = True,
    oauth_configured: bool = False,
) -> Settings:
    if not configured:
        return Settings(
            GITHUB_APP_ID=None,
            GITHUB_WEBHOOK_SECRET=None,
            GITHUB_APP_PRIVATE_KEY=None,
            GITHUB_APP_PRIVATE_KEY_PATH=None,
            GITHUB_APP_SLUG=None,
            GITHUB_CLIENT_ID=None,
            GITHUB_CLIENT_SECRET=None,
        )
    return Settings(
        GITHUB_APP_ID=999001,
        GITHUB_WEBHOOK_SECRET=SecretStr("webhook_test_secret_with_sufficient_entropy_1234"),
        GITHUB_APP_PRIVATE_KEY=SecretStr(pem),
        GITHUB_APP_SLUG="sentinel-security-bot",
        GITHUB_STATE_TTL_SEC=300,
        GITHUB_CLIENT_ID="Iv1.sentineltestclient" if oauth_configured else None,
        GITHUB_CLIENT_SECRET=(
            SecretStr("oauth_client_secret_test_value_1234567890") if oauth_configured else None
        ),
    )


def _client_with_overrides(
    session_factory: sessionmaker[Session],
    settings: Settings,
    github_transport: httpx.MockTransport | None = None,
) -> Generator[TestClient, None, None]:
    def override_db() -> Generator[Session, None, None]:
        sess = session_factory()
        try:
            yield sess
            if sess.in_transaction():
                sess.commit()
        except BaseException:
            if sess.in_transaction():
                sess.rollback()
            raise
        finally:
            sess.close()

    def override_settings() -> Settings:
        return settings

    app.dependency_overrides[get_db_session] = override_db
    app.dependency_overrides[get_settings] = override_settings
    if github_transport is not None:

        def override_gh_client() -> Generator[GitHubAppClient, None, None]:
            client = GitHubAppClient.from_settings(
                settings,
                transport=github_transport,
                sleep_fn=lambda _s: None,
            )
            try:
                yield client
            finally:
                client.close()

        def override_gh_oauth_client() -> Generator[GitHubOAuthClient, None, None]:
            client = GitHubOAuthClient.from_oauth_settings(
                settings,
                transport=github_transport,
                sleep_fn=lambda _s: None,
            )
            try:
                yield client
            finally:
                client.close()

        app.dependency_overrides[get_github_client] = override_gh_client
        app.dependency_overrides[get_github_oauth_client] = override_gh_oauth_client

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. Config & Readiness Tests
# ---------------------------------------------------------------------------


def test_github_config_validation_and_secret_masking(github_test_pem: str) -> None:
    strong = SecretStr("abcdefghijklmnopqrstuvwxyz0123456789")
    abs_gitleaks = os.path.abspath("/usr/local/bin/gitleaks")
    # Unconfigured production still succeeds cleanly (degraded/unconfigured GitHub readiness)
    prod_unconfigured = Settings(
        APP_ENV="production",
        AI_DEBUG_LOG=False,
        SECRET_KEY=strong,
        SESSION_SECRET=strong,
        FINGERPRINT_KEY=strong,
        GITLEAKS_PATH=abs_gitleaks,
    )
    assert prod_unconfigured.is_github_configured() is False

    # Partial GitHub config in production fails closed
    with pytest.raises(ValidationError, match="private key"):
        Settings(
            APP_ENV="production",
            AI_DEBUG_LOG=False,
            SECRET_KEY=strong,
            SESSION_SECRET=strong,
            FINGERPRINT_KEY=strong,
            GITLEAKS_PATH=abs_gitleaks,
            GITHUB_APP_ID=12345,
        )

    with pytest.raises(ValidationError, match="GITHUB_WEBHOOK_SECRET"):
        Settings(
            APP_ENV="production",
            AI_DEBUG_LOG=False,
            SECRET_KEY=strong,
            SESSION_SECRET=strong,
            FINGERPRINT_KEY=strong,
            GITLEAKS_PATH=abs_gitleaks,
            GITHUB_WEBHOOK_SECRET=SecretStr("short_weak_secret"),
        )

    # Full valid production configuration succeeds and masks secrets
    prod_ok = Settings(
        APP_ENV="production",
        AI_DEBUG_LOG=False,
        SECRET_KEY=strong,
        SESSION_SECRET=strong,
        FINGERPRINT_KEY=strong,
        GITLEAKS_PATH=abs_gitleaks,
        GITHUB_APP_ID=12345,
        GITHUB_WEBHOOK_SECRET=strong,
        GITHUB_APP_PRIVATE_KEY=SecretStr(github_test_pem),
        GITHUB_APP_SLUG="sentinel-app",
    )
    assert prod_ok.is_github_configured() is True
    assert "abcdefghijklmnopqrstuvwxyz" not in repr(prod_ok)
    assert "BEGIN PRIVATE KEY" not in str(prod_ok)


def test_readiness_and_unconfigured_fail_closed(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    unconfigured = _make_settings(github_test_pem, configured=False)
    headers_a = _auth_headers(db_session, tenant_a)

    for client in _client_with_overrides(session_factory, unconfigured):
        resp = client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json() == {
            "status": "ready",
            "database": "ok",
            "github": {
                "status": "unconfigured",
                "configured": False,
                "app_configured": False,
                "webhook_configured": False,
            },
        }
        assert client.get("/api/v1/readyz").status_code == 200

        assert client.get("/integrations/github/install", headers=headers_a).status_code == 503
        assert (
            client.get(
                "/integrations/github/callback?installation_id=1&state=abc",
                headers=headers_a,
            ).status_code
            == 503
        )
        assert client.post("/webhooks/github", json={"zen": "ok"}).status_code == 503

    configured = _make_settings(github_test_pem, configured=True)
    for client in _client_with_overrides(session_factory, configured):
        resp = client.get("/api/v1/readyz")
        assert resp.status_code == 200
        assert resp.json()["github"] == {
            "status": "configured",
            "configured": True,
            "app_configured": True,
            "webhook_configured": True,
        }


# ---------------------------------------------------------------------------
# 2. Installation Onboarding, CSRF State, Replay & Tenant Isolation
# ---------------------------------------------------------------------------


def test_installation_csrf_replay_and_tenant_isolation(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    tenant_b: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem, configured=True, oauth_configured=True)
    headers_a = _auth_headers(db_session, tenant_a)
    headers_b = _auth_headers(db_session, tenant_b)

    inst_token = "ghs" + "_" + "instcallback0000000000"
    oauth_tok_a = "ghu" + "_" + "aliceoauth0000000000"
    oauth_tok_b = "ghu" + "_" + "boboauth000000000000"

    def gh_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            form = parse_qs(request.content.decode("utf-8"))
            code = form["code"][0]
            if code == "oauth-code-a":
                return httpx.Response(
                    200, json={"access_token": oauth_tok_a, "token_type": "bearer"}
                )
            if code == "oauth-code-b":
                return httpx.Response(
                    200, json={"access_token": oauth_tok_b, "token_type": "bearer"}
                )
            return httpx.Response(200, json={"error": "bad_verification_code"})
        if request.url.path == "/user":
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {oauth_tok_a}":
                return httpx.Response(200, json={"id": 101, "login": "alice"})
            if auth == f"Bearer {oauth_tok_b}":
                return httpx.Response(200, json={"id": 202, "login": "bob"})
            return httpx.Response(401, json={"message": "Bad credentials"})
        if request.url.path == "/user/installations":
            auth = request.headers.get("authorization", "")
            if auth in (f"Bearer {oauth_tok_a}", f"Bearer {oauth_tok_b}"):
                return httpx.Response(
                    200,
                    json={
                        "installations": [
                            {
                                "id": 555,
                                "account": {
                                    "id": 5001,
                                    "login": "acme-org",
                                    "type": "Organization",
                                },
                                "permissions": {"contents": "read", "pull_requests": "write"},
                                "suspended_at": None,
                            }
                        ]
                    },
                )
            return httpx.Response(401, json={"message": "Bad credentials"})
        if request.url.path == "/app/installations/555/access_tokens":
            return httpx.Response(201, json={"token": inst_token})
        if request.url.path == "/app/installations/555":
            return httpx.Response(
                200,
                json={
                    "id": 555,
                    "account": {"id": 5001, "login": "acme-org", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        if request.url.path == "/app/installations/9999":
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(404)

    for client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        # Must authenticate
        assert client.get("/integrations/github/install").status_code == 401

        # Tenant A initiates installation
        init_resp = client.get("/integrations/github/install", headers=headers_a)
        assert init_resp.status_code == 200
        body = init_resp.json()
        parsed = urlparse(body["install_url"])
        assert parsed.netloc == "github.com"
        assert parsed.path == "/apps/sentinel-security-bot/installations/new"
        raw_state = parse_qs(parsed.query)["state"][0]

        # Only state SHA-256 hash stored in DB, never raw state
        state_row = db_session.scalar(select(GitHubInstallState))
        assert state_row is not None
        assert state_row.state_hash != raw_state
        assert state_row.state_hash == hashlib.sha256(raw_state.encode()).hexdigest()

        # Optional HTTP 302 redirect flow also works
        redir_resp = client.get(
            "/integrations/github/install?redirect=true",
            headers=headers_a,
            follow_redirects=False,
        )
        assert redir_resp.status_code == 302
        redir_state = parse_qs(urlparse(redir_resp.headers["location"]).query)["state"][0]

        # Cross-tenant state redemption fails without consuming Tenant A's state
        wrong_user_resp = client.get(
            f"/integrations/github/callback?installation_id=555&state={raw_state}",
            headers=headers_b,
        )
        assert wrong_user_resp.status_code == 403

        # Tenant A invalid state rejected
        assert (
            client.get(
                "/integrations/github/callback?installation_id=555&state=forged_state",
                headers=headers_a,
            ).status_code
            == 403
        )

        # Single-use state is consumed even if GitHub installation lookup returns 404
        fail_upstream = client.get(
            f"/integrations/github/callback?installation_id=9999&state={redir_state}",
            headers=headers_a,
        )
        assert fail_upstream.status_code == 404
        # Replaying redir_state must fail with 403
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=555&state={redir_state}",
                headers=headers_a,
            ).status_code
            == 403
        )

        # Tenant A completes callback legitimately with unused raw_state + OAuth code
        cb_resp = client.get(
            f"/integrations/github/callback?installation_id=555&setup_action=install&state={raw_state}&code=oauth-code-a",
            headers=headers_a,
        )
        assert cb_resp.status_code == 200
        inst_data = cb_resp.json()
        assert inst_data["installation_id"] == 555
        assert inst_data["account_login"] == "acme-org"
        assert inst_data["account_type"] == "Organization"
        assert inst_data["status"] == "active"

        # Replaying raw_state again fails
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=555&state={raw_state}&code=oauth-code-a",
                headers=headers_a,
            ).status_code
            == 403
        )

        # Tenant B creates own state, attempts to hijack installation 555 -> 409 Conflict
        init_b = client.get("/integrations/github/install", headers=headers_b).json()
        state_b = parse_qs(urlparse(init_b["install_url"]).query)["state"][0]
        hijack_resp = client.get(
            f"/integrations/github/callback?installation_id=555&state={state_b}&code=oauth-code-b",
            headers=headers_b,
        )
        assert hijack_resp.status_code == 409

        # Expired state fails cleanly
        init_exp = client.get("/integrations/github/install", headers=headers_a).json()
        exp_state = parse_qs(urlparse(init_exp["install_url"]).query)["state"][0]
        exp_hash = hashlib.sha256(exp_state.encode()).hexdigest()
        exp_row = db_session.scalar(
            select(GitHubInstallState).where(GitHubInstallState.state_hash == exp_hash)
        )
        assert exp_row is not None
        exp_row.expires_at = utc_now() - timedelta(seconds=5)
        db_session.commit()
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=555&state={exp_state}",
                headers=headers_a,
            ).status_code
            == 403
        )


# ---------------------------------------------------------------------------
# 3. Repository Onboarding & Cross-Tenant Access Controls
# ---------------------------------------------------------------------------


def test_repository_listing_connect_and_reconnect(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    tenant_b: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem, configured=True)
    headers_a = _auth_headers(db_session, tenant_a)
    headers_b = _auth_headers(db_session, tenant_b)

    inst = GitHubInstallation(
        installation_id=700,
        owner_user_id=tenant_a.id,
        account_login="alice-org",
        account_type="Organization",
        status="active",
    )
    db_session.add(inst)
    db_session.commit()

    tok = "ghs" + "_" + "repolist0000000000000"

    def gh_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/700/access_tokens":
            return httpx.Response(201, json={"token": tok})
        if request.url.path == "/installation/repositories":
            return httpx.Response(
                200,
                json={
                    "repositories": [
                        {
                            "id": 9001,
                            "name": "payments-api",
                            "full_name": "alice-org/payments-api",
                            "default_branch": "main",
                            "private": True,
                            "html_url": "https://github.com/alice-org/payments-api",
                        }
                    ]
                },
            )
        return httpx.Response(404)

    for client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        # Installations listing isolated per tenant
        list_a = client.get("/integrations/github/installations", headers=headers_a)
        assert list_a.status_code == 200 and list_a.json()["total"] == 1
        list_b = client.get("/integrations/github/installations", headers=headers_b)
        assert list_b.status_code == 200 and list_b.json()["total"] == 0

        # Cross-tenant repo list & connect return 404
        assert (
            client.get(
                "/integrations/github/installations/700/repositories", headers=headers_b
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/integrations/github/installations/700/repositories/connect",
                headers=headers_b,
                json={"github_repo_id": 9001},
            ).status_code
            == 404
        )

        # Repo not shared with installation returns 404
        assert (
            client.post(
                "/integrations/github/installations/700/repositories/connect",
                headers=headers_a,
                json={"github_repo_id": 999999},
            ).status_code
            == 404
        )

        # Before connecting
        repos_before = client.get(
            "/integrations/github/installations/700/repositories", headers=headers_a
        ).json()
        assert repos_before["items"][0]["connected"] is False
        assert repos_before["items"][0]["project_id"] is None

        # Connect repository -> 201 Created
        conn_resp = client.post(
            "/integrations/github/installations/700/repositories/connect",
            headers=headers_a,
            json={"github_repo_id": 9001},
        )
        assert conn_resp.status_code == 201
        project_data = conn_resp.json()
        assert project_data["kind"] == "github"
        assert project_data["installation_id"] == str(inst.id)
        assert project_data["github_repo_id"] == 9001
        assert project_data["full_name"] == "alice-org/payments-api"
        assert project_data["default_branch"] == "main"

        # Duplicate connect -> 409 Conflict
        dup_resp = client.post(
            "/integrations/github/installations/700/repositories/connect",
            headers=headers_a,
            json={"github_repo_id": 9001},
        )
        assert dup_resp.status_code == 409

        # After connecting, list reflects connected status and project_id
        repos_after = client.get(
            "/integrations/github/installations/700/repositories", headers=headers_a
        ).json()
        assert repos_after["items"][0]["connected"] is True
        assert repos_after["items"][0]["project_id"] == project_data["id"]

        # Soft delete project then reconnect cleanly respects uq_projects_installation_repo
        del_resp = client.delete(f"/projects/{project_data['id']}", headers=headers_a)
        assert del_resp.status_code == 204
        reconn = client.post(
            "/integrations/github/installations/700/repositories/connect",
            headers=headers_a,
            json={"github_repo_id": 9001},
        )
        assert reconn.status_code == 201
        assert reconn.json()["id"] == project_data["id"]
        assert reconn.json()["status"] == "active"


# ---------------------------------------------------------------------------
# 4. Webhooks: HMAC Verification, Idempotency, Lifecycle & Async PR Worker
# ---------------------------------------------------------------------------


def test_webhook_hmac_idempotency_lifecycle_and_pr_worker_execution(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
    tmp_path: Path,
) -> None:
    settings = _make_settings(github_test_pem, configured=True)
    assert settings.GITHUB_WEBHOOK_SECRET is not None
    wh_secret = settings.GITHUB_WEBHOOK_SECRET.get_secret_value()

    inst_800 = GitHubInstallation(
        installation_id=800,
        owner_user_id=tenant_a.id,
        account_login="acme",
        account_type="Organization",
        status="active",
    )
    db_session.add(inst_800)
    db_session.flush()
    project = Project(
        owner_user_id=tenant_a.id,
        name="service-repo",
        kind="github",
        installation_id=inst_800.id,
        github_repo_id=4400,
        full_name="acme/service-repo",
        default_branch="main",
        status="active",
    )
    db_session.add(project)
    db_session.commit()

    sha_v1 = "1" * 40
    sha_v2 = "2" * 40
    base_sha = "0" * 40
    worker_tok = "ghs" + "_" + "workerfetch0000000000"

    for client in _client_with_overrides(session_factory, settings):
        # Invalid signature fails BEFORE JSON parsing
        bad_json_resp = client.post(
            "/webhooks/github",
            content=b"{not-valid-json",
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "del-bad-1",
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
            },
        )
        assert bad_json_resp.status_code == 401

        # Missing delivery/event headers rejected with 400 after valid signature
        ping_bytes = json.dumps({"zen": "Keep it logically awesome."}).encode("utf-8")
        missing_hdr = client.post(
            "/webhooks/github",
            content=ping_bytes,
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": _sign_webhook(wh_secret, ping_bytes),
            },
        )
        assert missing_hdr.status_code == 400

        # Valid ping
        ping_ok = client.post(
            "/webhooks/github",
            content=ping_bytes,
            headers={
                "X-GitHub-Event": "ping",
                "X-GitHub-Delivery": "del-ping-1",
                "X-Hub-Signature-256": _sign_webhook(wh_secret, ping_bytes),
            },
        )
        assert ping_ok.status_code == 200
        assert ping_ok.json()["outcome"] == "accepted"

        # Draft PR ignored
        draft_payload = json.dumps(
            {
                "action": "opened",
                "installation": {"id": 800},
                "repository": {"id": 4400, "full_name": "acme/service-repo"},
                "pull_request": {
                    "number": 12,
                    "draft": True,
                    "title": "WIP",
                    "head": {"sha": sha_v1},
                    "base": {"sha": base_sha},
                },
            }
        ).encode("utf-8")
        draft_resp = client.post(
            "/webhooks/github",
            content=draft_payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "del-draft-1",
                "X-Hub-Signature-256": _sign_webhook(wh_secret, draft_payload),
            },
        )
        assert draft_resp.status_code == 200
        assert draft_resp.json()["outcome"] == "ignored_draft"

        # Opened PR v1 enqueues scan + job
        pr1_payload = json.dumps(
            {
                "action": "opened",
                "installation": {"id": 800},
                "repository": {"id": 4400, "full_name": "acme/service-repo"},
                "pull_request": {
                    "number": 12,
                    "draft": False,
                    "title": "Fix auth flow",
                    "head": {"sha": sha_v1},
                    "base": {"sha": base_sha},
                },
            }
        ).encode("utf-8")
        pr1_resp = client.post(
            "/webhooks/github",
            content=pr1_payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "del-pr1-1",
                "X-Hub-Signature-256": _sign_webhook(wh_secret, pr1_payload),
            },
        )
        assert pr1_resp.status_code == 200
        pr1_data = pr1_resp.json()
        assert pr1_data["status"] == "processed"
        assert pr1_data["outcome"] == "accepted"
        scan1_id = uuid.UUID(pr1_data["scan_id"])

        # Duplicate delivery does NOT create second scan or job
        pr1_dup = client.post(
            "/webhooks/github",
            content=pr1_payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "del-pr1-1",
                "X-Hub-Signature-256": _sign_webhook(wh_secret, pr1_payload),
            },
        )
        assert pr1_dup.status_code == 200
        assert pr1_dup.json()["status"] == "duplicate"
        assert pr1_dup.json()["scan_id"] == str(scan1_id)

        # New commit synchronize (sha_v2) supersedes PR scan v1 cleanly
        pr2_payload = json.dumps(
            {
                "action": "synchronize",
                "installation": {"id": 800},
                "repository": {"id": 4400, "full_name": "acme/service-repo"},
                "pull_request": {
                    "number": 12,
                    "draft": False,
                    "title": "Fix auth flow",
                    "head": {"sha": sha_v2},
                    "base": {"sha": base_sha},
                },
            }
        ).encode("utf-8")
        pr2_resp = client.post(
            "/webhooks/github",
            content=pr2_payload,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "del-pr1-2",
                "X-Hub-Signature-256": _sign_webhook(wh_secret, pr2_payload),
            },
        )
        assert pr2_resp.status_code == 200
        scan2_id = uuid.UUID(pr2_resp.json()["scan_id"])

        # Lifecycle events: repository removed -> access_lost, added -> active
        rm_payload = json.dumps(
            {
                "action": "removed",
                "installation": {"id": 800},
                "repositories_removed": [{"id": 4400}],
            }
        ).encode("utf-8")
        assert (
            client.post(
                "/webhooks/github",
                content=rm_payload,
                headers={
                    "X-GitHub-Event": "installation_repositories",
                    "X-GitHub-Delivery": "del-rm-1",
                    "X-Hub-Signature-256": _sign_webhook(wh_secret, rm_payload),
                },
            ).status_code
            == 200
        )
        db_session.expire_all()
        assert db_session.get(Project, project.id).status == "access_lost"  # type: ignore[union-attr]

        add_payload = json.dumps(
            {
                "action": "added",
                "installation": {"id": 800},
                "repositories_added": [{"id": 4400, "full_name": "acme/service-repo"}],
            }
        ).encode("utf-8")
        assert (
            client.post(
                "/webhooks/github",
                content=add_payload,
                headers={
                    "X-GitHub-Event": "installation_repositories",
                    "X-GitHub-Delivery": "del-add-1",
                    "X-Hub-Signature-256": _sign_webhook(wh_secret, add_payload),
                },
            ).status_code
            == 200
        )
        db_session.expire_all()
        assert db_session.get(Project, project.id).status == "active"  # type: ignore[union-attr]

    # Verify scan1 superseded and scan2 queued
    db_session.expire_all()
    scan1 = db_session.get(Scan, scan1_id)
    scan2 = db_session.get(Scan, scan2_id)
    assert scan1 is not None and scan1.status == "superseded"
    assert scan2 is not None and scan2.status == "queued"

    # Worker executes scan2 asynchronously using injected GitHubAppClient + CompositeScannerEngine
    captured_payloads: list[ScanJobPayload] = []
    source_code = "import os\nos.system('id')\n"
    encoded_src = base64.b64encode(source_code.encode("utf-8")).decode("ascii")

    def gh_worker_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/800/access_tokens":
            return httpx.Response(201, json={"token": worker_tok})
        if request.url.path == "/repos/acme/service-repo/pulls/12/files":
            return httpx.Response(
                200,
                json=[
                    {
                        "filename": "deleted.py",
                        "status": "removed",
                        "additions": 0,
                        "deletions": 5,
                        "changes": 5,
                    },
                    {
                        "filename": "docs/readme.md",
                        "status": "modified",
                        "additions": 2,
                        "deletions": 0,
                        "changes": 2,
                    },
                    {
                        "filename": "app/auth.py",
                        "status": "modified",
                        "additions": 2,
                        "deletions": 0,
                        "changes": 2,
                    },
                ],
            )
        if request.url.path == "/repos/acme/service-repo/contents/app/auth.py":
            assert request.url.params.get("ref") == sha_v2
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "size": len(source_code),
                    "encoding": "base64",
                    "content": encoded_src,
                    "sha": "blob1",
                },
            )
        return httpx.Response(404)

    class _StubAdapter(ScannerInterface):
        def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
            captured_payloads.append(payload)
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                findings=[
                    CanonicalFinding(
                        source=FindingSource.SEMGREP,
                        rule_id="python.lang.security.audit.os-system",
                        category=FindingCategory.INJECTION,
                        title="Avoid os.system",
                        description="Using os.system executes a subshell and risks command injection.",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.HIGH,
                        verification_status=VerificationStatus.SCANNER_DETECTED,
                        file_path="app/auth.py",
                        start_line=2,
                        end_line=2,
                        snippet="os.system('id')",
                        remediation="Use subprocess.run without shell=True.",
                        fingerprint=hashlib.sha256(b"pr-fp-1").hexdigest(),
                    )
                ],
                components={"semgrep": {"status": "succeeded", "finding_count": 1}},
            )

    class _EmptyAdapter(ScannerInterface):
        def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                findings=[],
                components={"gitleaks": {"status": "succeeded", "finding_count": 0}},
            )

    composite = CompositeScannerEngine(
        semgrep=_StubAdapter(),
        gitleaks=_EmptyAdapter(),
        workspace_base_dir=tmp_path,
    )

    worker = JobWorker(
        session_factory=session_factory,
        worker_id="gh-pr-worker-1",
        scanner=composite,
        github_client_factory=lambda: GitHubAppClient.from_settings(
            settings,
            transport=httpx.MockTransport(gh_worker_handler),
            sleep_fn=lambda _s: None,
        ),
    )

    assert worker.run_once() is True
    assert len(captured_payloads) == 1
    assert [f.path for f in captured_payloads[0].files] == ["app/auth.py"]

    db_session.expire_all()
    completed_scan = db_session.get(Scan, scan2_id)
    assert completed_scan is not None
    assert completed_scan.status == "succeeded"
    assert completed_scan.counts == {
        "findings": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert isinstance(completed_scan.files_summary, list)
    assert {item["path"]: item["scanned"] for item in completed_scan.files_summary} == {
        "app/auth.py": True,
        "docs/readme.md": False,
    }

    persisted_findings = list(db_session.scalars(select(Finding)).all())
    assert len(persisted_findings) == 1
    assert persisted_findings[0].file_path == "app/auth.py"

    # Webhook events recorded
    events = list(db_session.scalars(select(WebhookEvent)).all())
    assert len(events) == 6


def test_worker_pr_scan_empty_files_and_rate_limit_retry(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem, configured=True)
    inst_801 = GitHubInstallation(
        installation_id=801,
        owner_user_id=tenant_a.id,
        account_login="acme-2",
        account_type="Organization",
        status="active",
    )
    db_session.add(inst_801)
    db_session.flush()
    project = Project(
        owner_user_id=tenant_a.id,
        name="docs-repo",
        kind="github",
        installation_id=inst_801.id,
        github_repo_id=4401,
        full_name="acme-2/docs-repo",
        default_branch="main",
        status="active",
    )
    db_session.add(project)
    db_session.commit()

    # 1. Docs-only PR completes cleanly with zero findings without invoking scanner
    scan_docs = Scan(
        project_id=project.id,
        trigger="pull_request",
        trigger_key="pr:1:sha:" + "a" * 40,
        pr_number=1,
        head_sha="a" * 40,
        status="queued",
        report_status="pending",
    )
    job_docs = Job(
        scan=scan_docs,
        type="github_pr_scan",
        status="queued",
        payload={
            "installation_id": 801,
            "github_repo_id": 4401,
            "full_name": "acme-2/docs-repo",
            "pr_number": 1,
            "head_sha": "a" * 40,
            "base_sha": None,
            "run_ai": True,
        },
    )
    db_session.add_all([scan_docs, job_docs])
    db_session.commit()

    tok = "ghs" + "_" + "docspr000000000000000"

    def docs_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/801/access_tokens":
            return httpx.Response(201, json={"token": tok})
        if request.url.path == "/repos/acme-2/docs-repo/pulls/1/files":
            return httpx.Response(
                200,
                json=[
                    {
                        "filename": "README.md",
                        "status": "modified",
                        "additions": 1,
                        "deletions": 0,
                        "changes": 1,
                    }
                ],
            )
        return httpx.Response(404)

    class _NeverCalledScanner(ScannerInterface):
        def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
            raise AssertionError("Scanner should not run on 0-scannable-file PR")

    worker = JobWorker(
        session_factory=session_factory,
        worker_id="gh-pr-worker-empty",
        scanner=_NeverCalledScanner(),
        github_client_factory=lambda: GitHubAppClient.from_settings(
            settings,
            transport=httpx.MockTransport(docs_handler),
            sleep_fn=lambda _s: None,
        ),
    )
    assert worker.run_once() is True
    db_session.expire_all()
    assert db_session.get(Scan, scan_docs.id).status == "succeeded"  # type: ignore[union-attr]

    # 2. Upstream rate limit (429 Retry-After: 45) requeues job with retryable error & secret redaction
    scan_rl = Scan(
        project_id=project.id,
        trigger="pull_request",
        trigger_key="pr:2:sha:" + "b" * 40,
        pr_number=2,
        head_sha="b" * 40,
        status="queued",
        report_status="pending",
    )
    job_rl = Job(
        scan=scan_rl,
        type="github_pr_scan",
        status="queued",
        payload={
            "installation_id": 801,
            "github_repo_id": 4401,
            "full_name": "acme-2/docs-repo",
            "pr_number": 2,
            "head_sha": "b" * 40,
            "base_sha": None,
            "run_ai": True,
        },
    )
    db_session.add_all([scan_rl, job_rl])
    db_session.commit()

    def rl_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/801/access_tokens":
            return httpx.Response(201, json={"token": tok})
        return httpx.Response(
            429,
            headers={"Retry-After": "45"},
            json={"message": f"Secondary rate limit for token {tok}"},
        )

    worker_rl = JobWorker(
        session_factory=session_factory,
        worker_id="gh-pr-worker-rl",
        scanner=_NeverCalledScanner(),
        github_client_factory=lambda: GitHubAppClient.from_settings(
            settings,
            transport=httpx.MockTransport(rl_handler),
            sleep_fn=lambda _s: None,
        ),
    )
    assert worker_rl.run_once() is True
    db_session.expire_all()
    updated_job = db_session.get(Job, job_rl.id)
    updated_scan = db_session.get(Scan, scan_rl.id)
    assert updated_job is not None and updated_job.status == "queued"
    assert updated_job.attempts == 1
    assert updated_job.last_error is not None
    assert tok not in updated_job.last_error
    assert updated_scan is not None and updated_scan.status == "queued"


# ---------------------------------------------------------------------------
# 6. Hardening & Security Regression Tests (Crypto/Config/Webhook/Worker)
# ---------------------------------------------------------------------------


def test_github_config_rejects_corrupt_key_and_readiness_reports_partial(
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    strong = SecretStr("abcdefghijklmnopqrstuvwxyz0123456789")
    abs_gitleaks = os.path.abspath("/usr/local/bin/gitleaks")

    with pytest.raises(ValidationError, match="GITHUB_APP_PRIVATE_KEY is invalid"):
        Settings(
            APP_ENV="development",
            GITHUB_APP_ID=12345,
            GITHUB_APP_PRIVATE_KEY=SecretStr("-----BEGIN PRIVATE KEY-----\nbad-der"),
        )

    corrupt_key_path = tmp_path / "corrupt.pem"
    corrupt_key_path.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----", encoding="utf-8"
    )

    with pytest.raises(ValidationError, match="private key is unusable"):
        Settings(
            APP_ENV="production",
            AI_DEBUG_LOG=False,
            SECRET_KEY=strong,
            SESSION_SECRET=strong,
            FINGERPRINT_KEY=strong,
            GITLEAKS_PATH=abs_gitleaks,
            GITHUB_APP_ID=12345,
            GITHUB_APP_SLUG="sentinel-bot",
            GITHUB_WEBHOOK_SECRET=SecretStr("webhook_test_secret_with_sufficient_entropy_1234"),
            GITHUB_APP_PRIVATE_KEY_PATH=str(corrupt_key_path),
        )

    partial_settings = Settings(
        GITHUB_APP_ID=12345,
        GITHUB_APP_PRIVATE_KEY_PATH=str(corrupt_key_path),
    )
    assert partial_settings.is_github_app_configured() is False
    assert partial_settings.has_partial_github_config() is True

    for client in _client_with_overrides(session_factory, partial_settings):
        ready = client.get("/readyz")
        assert ready.status_code == 200
        gh = ready.json()["github"]
        assert gh["status"] == "partial"
        assert gh["configured"] is False
        assert gh["app_configured"] is False
        assert gh["webhook_configured"] is False


def test_installation_callback_rejects_mismatched_user_installation_account(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    tenant_b: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem)
    headers_a = _auth_headers(db_session, tenant_a)
    headers_b = _auth_headers(db_session, tenant_b)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/777":
            # User installation belonging to Mallory (id=999), NOT Alice (id=101)
            return httpx.Response(
                200,
                json={
                    "id": 777,
                    "account": {"id": 999, "login": "mallory", "type": "User"},
                    "permissions": {"pull_requests": "read", "contents": "read"},
                    "repository_selection": "selected",
                },
            )
        if request.url.path == "/app/installations/778":
            return httpx.Response(
                200,
                json={
                    "id": 778,
                    "account": {"id": 202, "login": "bob", "type": "User"},
                    "permissions": {"pull_requests": "read", "contents": "read"},
                    "repository_selection": "selected",
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    for client in _client_with_overrides(session_factory, settings, github_transport=transport):
        init_a = client.get("/integrations/github/install", headers=headers_a)
        assert init_a.status_code == 200
        state_a = parse_qs(urlparse(init_a.json()["install_url"]).query)["state"][0]

        mismatch = client.get(
            f"/integrations/github/callback?installation_id=777&state={state_a}&setup_action=install",
            headers=headers_a,
        )
        assert mismatch.status_code == 409
        assert (
            db_session.scalar(
                select(GitHubInstallation).where(GitHubInstallation.installation_id == 777)
            )
            is None
        )

        init_b = client.get("/integrations/github/install", headers=headers_b)
        assert init_b.status_code == 200
        state_b = parse_qs(urlparse(init_b.json()["install_url"]).query)["state"][0]

        ok_b = client.get(
            f"/integrations/github/callback?installation_id=778&state={state_b}&setup_action=install",
            headers=headers_b,
        )
        assert ok_b.status_code == 200
        assert ok_b.json()["installation_id"] == 778


def test_webhook_streaming_size_limit_invalid_content_length_and_rollback(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.webhooks as webhooks_api
    from app.services import github_webhook_service

    settings = _make_settings(github_test_pem)
    secret = settings.GITHUB_WEBHOOK_SECRET.get_secret_value()  # type: ignore[union-attr]

    monkeypatch.setattr(webhooks_api, "MAX_WEBHOOK_BODY_BYTES", 1024)

    for client in _client_with_overrides(session_factory, settings):
        bad_len = client.post(
            "/webhooks/github",
            headers={"Content-Length": "-5", "X-GitHub-Event": "ping", "X-GitHub-Delivery": "d1"},
        )
        assert bad_len.status_code == 400

        non_num_len = client.post(
            "/webhooks/github",
            headers={
                "Content-Length": "not-a-number",
                "X-GitHub-Event": "ping",
                "X-GitHub-Delivery": "d2",
            },
        )
        assert non_num_len.status_code == 400

        def _chunk_stream() -> Any:
            yield b"{" + b'"pad":"'
            yield b"A" * 1200
            yield b'"}'

        chunked_too_big = client.post(
            "/webhooks/github",
            content=_chunk_stream(),
            headers={
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "d-chunked-big",
                "X-Hub-Signature-256": "sha256=" + ("0" * 64),
            },
        )
        assert chunked_too_big.status_code == 413

        # Malformed PR SHA (64 hex chars instead of 40) is rejected cleanly as outcome='error'
        bad_sha_body = json.dumps(
            {
                "action": "opened",
                "installation": {"id": 901},
                "repository": {"id": 9010, "full_name": "acme/repo"},
                "pull_request": {
                    "number": 1,
                    "draft": False,
                    "title": "Bad SHA",
                    "head": {"sha": "f" * 64},
                    "base": {"sha": "a" * 40},
                },
            }
        ).encode("utf-8")
        bad_sha_resp = client.post(
            "/webhooks/github",
            content=bad_sha_body,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "d-bad-sha-64",
                "X-Hub-Signature-256": _sign_webhook(secret, bad_sha_body),
            },
        )
        assert bad_sha_resp.status_code == 200
        assert bad_sha_resp.json()["outcome"] == "error"

    # Verify SAVEPOINT rollback when handler mutates DB then raises inside process_github_webhook
    inst = GitHubInstallation(
        installation_id=902,
        owner_user_id=tenant_a.id,
        account_login="acme-rb",
        account_type="Organization",
        status="active",
        permissions={"pull_requests": "read", "contents": "read"},
    )
    db_session.add(inst)
    db_session.flush()
    project = Project(
        owner_user_id=tenant_a.id,
        installation_id=inst.id,
        kind="github",
        github_repo_id=9020,
        name="app",
        full_name="acme-rb/app",
        status="active",
    )
    db_session.add(project)
    db_session.flush()
    existing_scan = Scan(
        project_id=project.id,
        trigger="pull_request",
        trigger_key="pr:5:sha:" + ("a" * 40),
        pr_number=5,
        head_sha="a" * 40,
        status="queued",
        report_status="pending",
    )
    db_session.add(existing_scan)
    db_session.commit()

    def _boom_create_pr_scan(session: Session, **kwargs: Any) -> Any:
        # Mutate prior scan inside handler SAVEPOINT, then raise before returning
        scan_row = session.get(Scan, existing_scan.id)
        assert scan_row is not None
        scan_row.status = "superseded"
        session.flush()
        leaked_tok = "ghs" + "_" + "boomSecretToken1234567"
        raise RuntimeError(f"Simulated crash using {leaked_tok}")

    monkeypatch.setattr(github_webhook_service, "create_github_pr_scan", _boom_create_pr_scan)
    res = github_webhook_service.process_github_webhook(
        db_session,
        delivery_id="d-savepoint-rollback",
        event_type="pull_request",
        payload={
            "action": "synchronize",
            "installation": {"id": 902},
            "repository": {"id": 9020, "full_name": "acme-rb/app"},
            "pull_request": {
                "number": 5,
                "draft": False,
                "title": "Rollback check",
                "head": {"sha": "b" * 40},
                "base": {"sha": "a" * 40},
            },
        },
        auto_commit=True,
    )
    assert res.outcome == "error"
    db_session.expire_all()
    preserved_scan = db_session.get(Scan, existing_scan.id)
    assert preserved_scan is not None and preserved_scan.status == "queued"
    ev = db_session.scalar(
        select(WebhookEvent).where(WebhookEvent.delivery_id == "d-savepoint-rollback")
    )
    assert ev is not None and ev.outcome == "error" and ev.scan_id is None


def test_worker_pr_scan_fails_when_project_or_installation_inactive_and_respects_supersession(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem)
    inst = GitHubInstallation(
        installation_id=950,
        owner_user_id=tenant_a.id,
        account_login="acme-worker",
        account_type="Organization",
        status="active",
        permissions={"pull_requests": "read", "contents": "read"},
    )
    db_session.add(inst)
    db_session.flush()
    project = Project(
        owner_user_id=tenant_a.id,
        installation_id=inst.id,
        kind="github",
        github_repo_id=9500,
        name="service",
        full_name="acme-worker/service",
        status="active",
    )
    db_session.add(project)
    db_session.commit()

    def _enqueue_pr(pr_num: int, sha_char: str) -> tuple[Scan, Job]:
        s = Scan(
            project_id=project.id,
            trigger="pull_request",
            trigger_key=f"pr:{pr_num}:sha:{sha_char * 40}",
            pr_number=pr_num,
            head_sha=sha_char * 40,
            status="queued",
            report_status="pending",
        )
        j = Job(
            scan=s,
            type="github_pr_scan",
            status="queued",
            payload={
                "installation_id": 950,
                "github_repo_id": 9500,
                "full_name": "acme-worker/service",
                "pr_number": pr_num,
                "head_sha": sha_char * 40,
                "base_sha": None,
                "run_ai": True,
            },
        )
        db_session.add_all([s, j])
        db_session.commit()
        return s, j

    class _NeverCalledScanner(ScannerInterface):
        def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
            raise AssertionError("Scanner should not run when project or installation is inactive")

    def _never_http(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"GitHub API should not be called: {request.url}")

    # 1. Project revoked (`access_lost`) before worker claims job
    scan_proj, job_proj = _enqueue_pr(1, "1")
    project.status = "access_lost"
    db_session.commit()

    worker_1 = JobWorker(
        session_factory=session_factory,
        worker_id="gh-guard-1",
        scanner=_NeverCalledScanner(),
        github_client_factory=lambda: GitHubAppClient.from_settings(
            settings,
            transport=httpx.MockTransport(_never_http),
            sleep_fn=lambda _s: None,
        ),
    )
    assert worker_1.run_once() is True
    db_session.expire_all()
    assert db_session.get(Job, job_proj.id).status == "failed"  # type: ignore[union-attr]
    assert db_session.get(Scan, scan_proj.id).error_code == "PROJECT_INACTIVE"  # type: ignore[union-attr]
    assert db_session.get(Scan, scan_proj.id).status == "failed"  # type: ignore[union-attr]

    # 2. Installation suspended while project active
    project.status = "active"
    inst.status = "suspended"
    db_session.commit()
    scan_inst, job_inst = _enqueue_pr(2, "2")

    assert worker_1.run_once() is True
    db_session.expire_all()
    assert db_session.get(Job, job_inst.id).status == "failed"  # type: ignore[union-attr]
    assert db_session.get(Scan, scan_inst.id).error_code == "INSTALLATION_INACTIVE"  # type: ignore[union-attr]
    assert db_session.get(Scan, scan_inst.id).status == "failed"  # type: ignore[union-attr]

    # 3. Concurrent supersession during execution discards findings & preserves 'superseded'
    inst.status = "active"
    db_session.commit()
    scan_sup, job_sup = _enqueue_pr(3, "3")
    tok = "ghs" + "_" + "supersede000000000000"

    def sup_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/950/access_tokens":
            return httpx.Response(201, json={"token": tok})
        if request.url.path == "/repos/acme-worker/service/pulls/3/files":
            return httpx.Response(
                200,
                json=[
                    {
                        "filename": "app.py",
                        "status": "added",
                        "additions": 2,
                        "deletions": 0,
                        "changes": 2,
                    }
                ],
            )
        if request.url.path == "/repos/acme-worker/service/contents/app.py":
            # Simulate concurrent webhook marking scan 'superseded' mid-scan
            with session_factory() as s_other:
                row = s_other.get(Scan, scan_sup.id)
                assert row is not None
                row.status = "superseded"
                s_other.commit()
            encoded = base64.b64encode(b"x = eval(input())\n").decode("ascii")
            return httpx.Response(
                200,
                json={"type": "file", "encoding": "base64", "size": 18, "content": encoded},
            )
        return httpx.Response(404)

    class _FindingScanner(ScannerInterface):
        def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                findings=[
                    CanonicalFinding(
                        fingerprint=hashlib.sha256(b"sup-fp-1").hexdigest(),
                        source=FindingSource.SEMGREP,
                        rule_id="python.lang.security.audit.eval-detected",
                        title="Avoid eval()",
                        description="Dangerous eval call",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.HIGH,
                        category=FindingCategory.INJECTION,
                        verification_status=VerificationStatus.SCANNER_DETECTED,
                        file_path="app.py",
                        start_line=1,
                        end_line=1,
                        snippet="x = eval(input())",
                        remediation="Avoid calling eval on untrusted input.",
                    )
                ],
                counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            )

    worker_sup = JobWorker(
        session_factory=session_factory,
        worker_id="gh-guard-sup",
        scanner=_FindingScanner(),
        github_client_factory=lambda: GitHubAppClient.from_settings(
            settings,
            transport=httpx.MockTransport(sup_handler),
            sleep_fn=lambda _s: None,
        ),
    )
    assert worker_sup.run_once() is True
    db_session.expire_all()
    final_scan = db_session.get(Scan, scan_sup.id)
    final_job = db_session.get(Job, job_sup.id)
    assert final_scan is not None and final_scan.status == "superseded"
    assert final_job is not None and final_job.status == "failed"
    assert db_session.scalars(select(Finding).where(Finding.project_id == project.id)).all() == []


# ---------------------------------------------------------------------------
# 6. Organization Installation OAuth Ownership & Edge-Case Matrix
# ---------------------------------------------------------------------------


def _issue_state(client, headers: dict[str, str]) -> str:
    resp = client.get("/integrations/github/install", headers=headers)
    assert resp.status_code == 200
    return parse_qs(urlparse(resp.json()["install_url"]).query)["state"][0]


def test_org_installation_oauth_success_and_no_secret_persistence(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem, configured=True, oauth_configured=True)
    headers_a = _auth_headers(db_session, tenant_a)
    oauth_tok = "ghu" + "_" + "orgmembervalid000000"
    oauth_code = "secret-oauth-code-901"

    def gh_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": oauth_tok, "token_type": "bearer"})
        if request.url.path == "/user":
            assert request.headers["authorization"] == f"Bearer {oauth_tok}"
            return httpx.Response(200, json={"id": 101, "login": "Alice"})
        if request.url.path == "/user/installations":
            return httpx.Response(
                200,
                json={
                    "installations": [
                        {
                            "id": 901,
                            "account": {
                                "id": 9001,
                                "login": "Org-Security",
                                "type": "Organization",
                            },
                            "permissions": {"contents": "read", "pull_requests": "write"},
                            "suspended_at": None,
                        }
                    ]
                },
            )
        if request.url.path == "/app/installations/901":
            return httpx.Response(
                200,
                json={
                    "id": 901,
                    "account": {"id": 9001, "login": "org-security", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        return httpx.Response(404)

    for client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        state = _issue_state(client, headers_a)
        resp = client.get(
            f"/integrations/github/callback?installation_id=901&setup_action=install&state={state}&code={oauth_code}",
            headers=headers_a,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["installation_id"] == 901
        assert body["account_type"] == "Organization"
        assert oauth_tok not in resp.text
        assert oauth_code not in resp.text

    db_session.expire_all()
    inst = db_session.scalar(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == 901)
    )
    assert inst is not None
    assert inst.owner_user_id == tenant_a.id
    assert inst.account_login == "org-security"


def test_org_installation_rejects_unauthorized_member_and_id_substitution(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem, configured=True, oauth_configured=True)
    headers_a = _auth_headers(db_session, tenant_a)
    oauth_tok = "ghu" + "_" + "unauthmember00000000"

    def gh_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": oauth_tok, "token_type": "bearer"})
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 101, "login": "alice"})
        if request.url.path == "/user/installations":
            # User only belongs to installation 700, NOT 888
            return httpx.Response(
                200,
                json={
                    "installations": [
                        {
                            "id": 700,
                            "account": {"id": 7000, "login": "alice-org", "type": "Organization"},
                            "permissions": {"contents": "read", "pull_requests": "read"},
                            "suspended_at": None,
                        }
                    ]
                },
            )
        if request.url.path == "/app/installations/888":
            return httpx.Response(
                200,
                json={
                    "id": 888,
                    "account": {"id": 8880, "login": "victim-org", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        return httpx.Response(404)

    for client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        # Attempt to link installation 888 (not in /user/installations) -> 403
        state_1 = _issue_state(client, headers_a)
        resp = client.get(
            f"/integrations/github/callback?installation_id=888&state={state_1}&code=valid-code",
            headers=headers_a,
        )
        assert resp.status_code == 403
        # State was consumed and cannot be replayed with legitimate installation 700
        replay = client.get(
            f"/integrations/github/callback?installation_id=700&state={state_1}&code=valid-code",
            headers=headers_a,
        )
        assert replay.status_code == 403

    assert (
        db_session.scalar(
            select(GitHubInstallation).where(GitHubInstallation.installation_id == 888)
        )
        is None
    )


def test_org_installation_account_identity_and_metadata_mismatches(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem, configured=True, oauth_configured=True)
    headers_a = _auth_headers(db_session, tenant_a)
    tok_bob = "ghu" + "_" + "boboauthattacker0000"
    tok_mismatch = "ghu" + "_" + "alicemismatchmeta000"

    def gh_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            code = parse_qs(request.content.decode("utf-8"))["code"][0]
            tok = tok_bob if code == "bob-code" else tok_mismatch
            return httpx.Response(200, json={"access_token": tok, "token_type": "bearer"})
        if request.url.path == "/user":
            if request.headers["authorization"] == f"Bearer {tok_bob}":
                return httpx.Response(200, json={"id": 202, "login": "bob"})
            return httpx.Response(200, json={"id": 101, "login": "alice"})
        if request.url.path == "/user/installations":
            if request.headers["authorization"] == f"Bearer {tok_bob}":
                return httpx.Response(
                    200,
                    json={
                        "installations": [
                            {
                                "id": 910,
                                "account": {"id": 9100, "login": "org-a", "type": "Organization"},
                                "permissions": {"contents": "read", "pull_requests": "write"},
                                "suspended_at": None,
                            }
                        ]
                    },
                )
            return httpx.Response(
                200,
                json={
                    "installations": [
                        {
                            "id": 910,
                            "account": {
                                "id": 9999,
                                "login": "different-org",
                                "type": "Organization",
                            },
                            "permissions": {"contents": "read", "pull_requests": "write"},
                            "suspended_at": None,
                        }
                    ]
                },
            )
        if request.url.path == "/app/installations/910":
            return httpx.Response(
                200,
                json={
                    "id": 910,
                    "account": {"id": 9100, "login": "org-a", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        return httpx.Response(404)

    for client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        # 1. Authenticated Sentinel user Alice presents Bob's OAuth code -> 409 Conflict
        st1 = _issue_state(client, headers_a)
        r1 = client.get(
            f"/integrations/github/callback?installation_id=910&state={st1}&code=bob-code",
            headers=headers_a,
        )
        assert r1.status_code == 409

        # 2. /user/installations account metadata disagrees with /app/installations/910 -> 403
        st2 = _issue_state(client, headers_a)
        r2 = client.get(
            f"/integrations/github/callback?installation_id=910&state={st2}&code=meta-code",
            headers=headers_a,
        )
        assert r2.status_code == 403

    assert (
        db_session.scalar(
            select(GitHubInstallation).where(GitHubInstallation.installation_id == 910)
        )
        is None
    )


def test_oauth_error_denial_expired_state_and_permission_failures(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    settings = _make_settings(github_test_pem, configured=True, oauth_configured=True)
    headers_a = _auth_headers(db_session, tenant_a)
    tok_alice = "ghu" + "_" + "alicelackperms00000"
    tok_revoked = "ghu" + "_" + "revokedalice0000000"
    exchange_calls = 0

    def gh_handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchange_calls
        if request.url.path == "/login/oauth/access_token":
            exchange_calls += 1
            code = parse_qs(request.content.decode("utf-8"))["code"][0]
            if code == "bad-code":
                return httpx.Response(200, json={"error": "bad_verification_code"})
            if code == "upstream-500":
                return httpx.Response(
                    500,
                    text="upstream failure client_secret=oauth_client_secret_test_value_1234567890",
                )
            if code == "revoked-code":
                return httpx.Response(
                    200, json={"access_token": tok_revoked, "token_type": "bearer"}
                )
            return httpx.Response(200, json={"access_token": tok_alice, "token_type": "bearer"})
        if request.url.path == "/user":
            if request.headers["authorization"] == f"Bearer {tok_revoked}":
                return httpx.Response(401, json={"message": "Bad credentials"})
            return httpx.Response(200, json={"id": 101, "login": "alice"})
        if request.url.path == "/user/installations":
            return httpx.Response(
                200,
                json={
                    "installations": [
                        {
                            "id": 920,
                            "account": {"id": 9200, "login": "lowperm-org", "type": "Organization"},
                            "permissions": {"metadata": "read"},
                            "suspended_at": None,
                        }
                    ]
                },
            )
        if request.url.path == "/app/installations/920":
            return httpx.Response(
                200,
                json={
                    "id": 920,
                    "account": {"id": 9200, "login": "validperm-org", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        if request.url.path == "/app/installations/921":
            return httpx.Response(
                200,
                json={
                    "id": 921,
                    "account": {"id": 9210, "login": "lowperm-org", "type": "Organization"},
                    "permissions": {"metadata": "read"},
                    "suspended_at": None,
                },
            )
        return httpx.Response(404)

    for client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        # 1. User cancels / denies OAuth -> 403, state consumed, no token exchange called
        st_deny = _issue_state(client, headers_a)
        deny_resp = client.get(
            f"/integrations/github/callback?installation_id=920&error=access_denied&state={st_deny}",
            headers=headers_a,
        )
        assert deny_resp.status_code == 403
        assert exchange_calls == 0
        # Replaying st_deny even with a code fails cleanly
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=920&state={st_deny}&code=good",
                headers=headers_a,
            ).status_code
            == 403
        )
        assert exchange_calls == 0

        # 2. Expired state prevents token exchange entirely -> 403
        st_exp = _issue_state(client, headers_a)
        exp_hash = hashlib.sha256(st_exp.encode()).hexdigest()
        exp_row = db_session.scalar(
            select(GitHubInstallState).where(GitHubInstallState.state_hash == exp_hash)
        )
        assert exp_row is not None
        exp_row.expires_at = utc_now() - timedelta(seconds=10)
        db_session.commit()
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=920&state={st_exp}&code=good",
                headers=headers_a,
            ).status_code
            == 403
        )
        assert exchange_calls == 0

        # 3. bad_verification_code -> 403
        st_bad = _issue_state(client, headers_a)
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=920&state={st_bad}&code=bad-code",
                headers=headers_a,
            ).status_code
            == 403
        )

        # 4. Upstream 500 during code exchange -> 502 and never leaks client_secret
        st_500 = _issue_state(client, headers_a)
        err_500 = client.get(
            f"/integrations/github/callback?installation_id=920&state={st_500}&code=upstream-500",
            headers=headers_a,
        )
        assert err_500.status_code == 502
        assert "oauth_client_secret_test_value_1234567890" not in err_500.text

        # 5. Revoked user token during /user check -> 403
        st_revoked = _issue_state(client, headers_a)
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=920&state={st_revoked}&code=revoked-code",
                headers=headers_a,
            ).status_code
            == 403
        )

        # 6. Missing required installation permissions -> 403
        st_perm = _issue_state(client, headers_a)
        perm_resp = client.get(
            f"/integrations/github/callback?installation_id=921&state={st_perm}&code=good",
            headers=headers_a,
        )
        assert perm_resp.status_code == 403
        assert "permission" in perm_resp.json()["detail"].lower()


def test_org_fails_closed_without_oauth_and_personal_remains_compatible(
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_a: User,
    github_test_pem: str,
) -> None:
    from pydantic import ValidationError

    # Partial OAuth configuration is rejected by Settings validation
    with pytest.raises(ValidationError, match="GITHUB_CLIENT_ID"):
        Settings(GITHUB_CLIENT_ID="Iv1.onlyidset")

    headers_a = _auth_headers(db_session, tenant_a)
    tok_alice = "ghu" + "_" + "personaluser00000000"

    def gh_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/930":
            return httpx.Response(
                200,
                json={
                    "id": 930,
                    "account": {"id": 9300, "login": "unconfigured-org", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        if request.url.path == "/app/installations/931":
            return httpx.Response(
                200,
                json={
                    "id": 931,
                    "account": {"id": 101, "login": "alice", "type": "User"},
                    "permissions": {"contents": "read", "pull_requests": "read"},
                    "suspended_at": None,
                },
            )
        if request.url.path == "/app/installations/932":
            return httpx.Response(
                200,
                json={
                    "id": 932,
                    "account": {"id": 202, "login": "bob", "type": "User"},
                    "permissions": {"contents": "read", "pull_requests": "read"},
                    "suspended_at": None,
                },
            )
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": tok_alice, "token_type": "bearer"})
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 101, "login": "alice"})
        if request.url.path == "/user/installations":
            return httpx.Response(
                200,
                json={
                    "installations": [
                        {
                            "id": 931,
                            "account": {"id": 101, "login": "alice", "type": "User"},
                            "permissions": {"contents": "read", "pull_requests": "read"},
                            "suspended_at": None,
                        }
                    ]
                },
            )
        return httpx.Response(404)

    # 1. Without OAuth configured: Org fails closed (503), User works without code
    no_oauth_settings = _make_settings(github_test_pem, configured=True, oauth_configured=False)
    for client in _client_with_overrides(
        session_factory, no_oauth_settings, httpx.MockTransport(gh_handler)
    ):
        st_org = _issue_state(client, headers_a)
        org_503 = client.get(
            f"/integrations/github/callback?installation_id=930&state={st_org}",
            headers=headers_a,
        )
        assert org_503.status_code == 503

        st_user = _issue_state(client, headers_a)
        user_ok = client.get(
            f"/integrations/github/callback?installation_id=931&state={st_user}",
            headers=headers_a,
        )
        assert user_ok.status_code == 200
        assert user_ok.json()["account_type"] == "User"

        # Mismatched personal User (bob) still rejected with 409
        st_bob = _issue_state(client, headers_a)
        bob_409 = client.get(
            f"/integrations/github/callback?installation_id=932&state={st_bob}",
            headers=headers_a,
        )
        assert bob_409.status_code == 409

    # 2. With OAuth configured: setup-URL-only Org callback without code -> 403,
    #    while User works both with and without code
    oauth_settings = _make_settings(github_test_pem, configured=True, oauth_configured=True)
    for client in _client_with_overrides(
        session_factory, oauth_settings, httpx.MockTransport(gh_handler)
    ):
        st_org_nocode = _issue_state(client, headers_a)
        org_403 = client.get(
            f"/integrations/github/callback?installation_id=930&state={st_org_nocode}",
            headers=headers_a,
        )
        assert org_403.status_code == 403

        st_user_with_code = _issue_state(client, headers_a)
        user_oauth_ok = client.get(
            f"/integrations/github/callback?installation_id=931&setup_action=update&state={st_user_with_code}&code=alice-code",
            headers=headers_a,
        )
        assert user_oauth_ok.status_code == 200
        assert user_oauth_ok.json()["installation_id"] == 931


def test_browser_cookie_login_to_org_installation_and_cross_state_isolation(
    github_test_pem: str,
    session_factory: sessionmaker[Session],
    db_session: Session,
    tenant_b: User,
) -> None:
    """Unauthenticated browser authenticates via GitHub OAuth cookie, links Org install, and stays tenant-isolated."""
    tok_alice = "ghu" + "_" + "browseralice123456"
    seen_redirect_uris: list[str] = []

    def gh_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            body = request.content.decode("utf-8")
            seen_redirect_uris.append(body)
            return httpx.Response(200, json={"access_token": tok_alice, "token_type": "bearer"})
        if request.url.path == "/user":
            return httpx.Response(
                200,
                json={
                    "id": 9101,
                    "login": "browser-alice",
                    "name": "Browser Alice",
                    "avatar_url": "https://avatars.githubusercontent.com/u/9101",
                },
            )
        if request.url.path == "/app/installations/950":
            return httpx.Response(
                200,
                json={
                    "id": 950,
                    "account": {"id": 8801, "login": "acme-browser-org", "type": "Organization"},
                    "permissions": {"contents": "read", "pull_requests": "write"},
                    "suspended_at": None,
                },
            )
        if request.url.path == "/user/installations":
            return httpx.Response(
                200,
                json={
                    "installations": [
                        {
                            "id": 950,
                            "account": {
                                "id": 8801,
                                "login": "acme-browser-org",
                                "type": "Organization",
                            },
                            "permissions": {"contents": "read", "pull_requests": "write"},
                            "suspended_at": None,
                        }
                    ]
                },
            )
        return httpx.Response(404)

    settings = Settings(
        GITHUB_APP_ID=999001,
        GITHUB_WEBHOOK_SECRET=SecretStr("webhook_test_secret_with_sufficient_entropy_1234"),
        GITHUB_APP_PRIVATE_KEY=SecretStr(github_test_pem),
        GITHUB_APP_SLUG="sentinel-security-bot",
        GITHUB_STATE_TTL_SEC=300,
        GITHUB_CLIENT_ID="Iv1.sentinelbrowserclient",
        GITHUB_CLIENT_SECRET=SecretStr("oauth_client_secret_test_value_1234567890"),
        GITHUB_AUTH_CALLBACK_URL="https://sentinel.example.com/auth/github/callback",
        GITHUB_APP_INSTALL_CALLBACK_URL="https://sentinel.example.com/integrations/github/callback",
    )
    headers_b = _auth_headers(db_session, tenant_b)

    for client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        # 1. Start completely unauthenticated browser login aiming for installation setup
        assert client.get("/me").status_code == 401
        login_init = client.get(
            "/auth/github/login",
            params={"next": "/integrations/github/install"},
        )
        assert login_init.status_code == 200
        login_state = parse_qs(urlparse(login_init.json()["authorize_url"]).query)["state"][0]

        # Login state cannot be used on the installation callback
        assert (
            client.get(
                f"/integrations/github/callback?installation_id=950&state={login_state}&code=c-org",
                headers=headers_b,
            ).status_code
            == 403
        )

        # 2. Complete OAuth login callback -> redirects to /integrations/github/install with SameSite=Lax session cookie
        login_cb = client.get(
            f"/auth/github/callback?code=c-login&state={login_state}",
            follow_redirects=False,
        )
        assert login_cb.status_code == 302
        assert login_cb.headers["location"] == "/integrations/github/install"

        # Cookie authenticates /me and /integrations/github/install
        me_resp = client.get("/me")
        assert me_resp.status_code == 200
        assert me_resp.json()["github_login"] == "browser-alice"

        install_init = client.get("/integrations/github/install")
        assert install_init.status_code == 200
        install_state = parse_qs(urlparse(install_init.json()["install_url"]).query)["state"][0]

        # Install state cannot be used on login callback
        assert (
            client.get(
                f"/auth/github/callback?code=c-login2&state={install_state}",
            ).status_code
            == 403
        )

        # 3. Complete GitHub App installation callback for Organization using session cookie
        install_cb = client.get(
            f"/integrations/github/callback?installation_id=950&setup_action=install&state={install_state}&code=c-org",
        )
        assert install_cb.status_code == 200
        assert install_cb.json()["installation_id"] == 950
        assert install_cb.json()["account_login"] == "acme-browser-org"

        # 4. Authenticated cookie user sees installation; Tenant B cannot see or claim it
        list_a = client.get("/integrations/github/installations")
        assert list_a.status_code == 200
        assert [i["installation_id"] for i in list_a.json()["items"]] == [950]

    for bob_client in _client_with_overrides(
        session_factory, settings, httpx.MockTransport(gh_handler)
    ):
        list_b = bob_client.get("/integrations/github/installations", headers=headers_b)
        assert list_b.status_code == 200
        assert list_b.json()["items"] == []

    assert (
        "redirect_uri=https%3A%2F%2Fsentinel.example.com%2Fauth%2Fgithub%2Fcallback"
        in seen_redirect_uris[0]
    )
    assert (
        "redirect_uri=https%3A%2F%2Fsentinel.example.com%2Fintegrations%2Fgithub%2Fcallback"
        in seen_redirect_uris[1]
    )
