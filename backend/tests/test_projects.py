"""Integration and security tests for Projects API endpoints.

Validates:
- Blueprint Section 8.1 (projects model constraints, tenant boundary, soft-delete)
- Blueprint Section 9 (API pagination conventions, response schemas)
- Blueprint Section 12 (Threat T4 Tenant Isolation)
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Generator
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import GitHubInstallation, Project, User, UserSession
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
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def other_user(db_session: Session) -> User:
    """Create second user for cross-tenant isolation testing."""
    user = User(
        github_user_id=2002,
        github_login="bob-attacker",
        display_name="Bob Attacker",
    )
    db_session.add(user)
    db_session.commit()
    return user


def create_authenticated_user_session(db_session: Session, user: User) -> str:
    """Helper to create a server-side session and return raw token for Bearer auth."""
    raw_token = f"test-token-{uuid.uuid4().hex}-{user.id}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).digest()
    user_session = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash,
        expires_at=utc_now() + timedelta(days=1),
    )
    db_session.add(user_session)
    db_session.commit()
    return raw_token


@pytest.fixture
def client(
    session_factory: sessionmaker[Session],
    db_session: Session,
    sample_user: User,
) -> Generator[TestClient, None, None]:
    """TestClient authenticated as sample_user via real UserSession token."""
    token = create_authenticated_user_session(db_session, sample_user)

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def other_client(
    session_factory: sessionmaker[Session],
    db_session: Session,
    other_user: User,
) -> Generator[TestClient, None, None]:
    """TestClient authenticated as other_user via real UserSession token."""
    token = create_authenticated_user_session(db_session, other_user)

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def unauthenticated_client(
    session_factory: sessionmaker[Session],
) -> Generator[TestClient, None, None]:
    """Unauthenticated TestClient."""

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


class TestListProjectsEndpoint:
    """Integration and security tests for GET /projects and GET /api/v1/projects."""

    def test_list_projects_pagination_and_ordering(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Projects are paginated and ordered deterministically by created_at DESC, id DESC."""
        base_time = utc_now()

        p1 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Alpha Project",
            status="active",
            created_at=base_time - timedelta(hours=3),
        )
        p2 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Beta Project",
            status="active",
            created_at=base_time - timedelta(hours=2),
        )
        # p3 and p4 have identical timestamps -> broken deterministically by id DESC
        p3 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Gamma Project",
            status="active",
            created_at=base_time - timedelta(hours=1),
        )
        p4 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Delta Project",
            status="active",
            created_at=base_time - timedelta(hours=1),
        )
        db_session.add_all([p1, p2, p3, p4])
        db_session.commit()

        # Determine expected order between tied projects p3 and p4
        tied_order = [p3, p4] if p3.id > p4.id else [p4, p3]

        # Page 1: limit=2, offset=0 -> tied projects
        resp1 = client.get("/api/v1/projects", params={"limit": 2, "offset": 0})
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["total"] == 4
        assert len(data1["items"]) == 2
        assert data1["limit"] == 2
        assert data1["offset"] == 0
        assert data1["items"][0]["id"] == str(tied_order[0].id)
        assert data1["items"][1]["id"] == str(tied_order[1].id)

        # Page 2: limit=2, offset=2 -> p2 then p1
        resp2 = client.get("/api/v1/projects", params={"limit": 2, "offset": 2})
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 4
        assert len(data2["items"]) == 2
        assert data2["items"][0]["id"] == str(p2.id)
        assert data2["items"][1]["id"] == str(p1.id)

        # Page 3: limit=2, offset=4 -> empty items
        resp3 = client.get("/api/v1/projects", params={"limit": 2, "offset": 4})
        assert resp3.status_code == 200
        data3 = resp3.json()
        assert data3["total"] == 4
        assert data3["items"] == []

    def test_list_projects_tenant_isolation(
        self,
        client: TestClient,
        other_client: TestClient,
        db_session: Session,
        sample_user: User,
        other_user: User,
    ) -> None:
        """Tenant cannot see or count projects owned by another tenant."""
        p_alice_1 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Alice Project 1",
            status="active",
        )
        p_alice_2 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Alice Project 2",
            status="active",
        )
        p_bob_1 = Project(
            owner_user_id=other_user.id,
            kind="manual",
            name="Bob Project 1",
            status="active",
        )
        p_bob_2 = Project(
            owner_user_id=other_user.id,
            kind="manual",
            name="Bob Project 2",
            status="active",
        )
        db_session.add_all([p_alice_1, p_alice_2, p_bob_1, p_bob_2])
        db_session.commit()

        # Alice's client
        resp_alice = client.get("/api/v1/projects")
        assert resp_alice.status_code == 200
        data_alice = resp_alice.json()
        assert data_alice["total"] == 2
        alice_ids = {item["id"] for item in data_alice["items"]}
        assert alice_ids == {str(p_alice_1.id), str(p_alice_2.id)}
        assert str(p_bob_1.id) not in alice_ids
        assert str(p_bob_2.id) not in alice_ids

        # Bob's client
        resp_bob = other_client.get("/api/v1/projects")
        assert resp_bob.status_code == 200
        data_bob = resp_bob.json()
        assert data_bob["total"] == 2
        bob_ids = {item["id"] for item in data_bob["items"]}
        assert bob_ids == {str(p_bob_1.id), str(p_bob_2.id)}
        assert str(p_alice_1.id) not in bob_ids
        assert str(p_alice_2.id) not in bob_ids

    def test_list_projects_soft_deleted_excluded(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Soft-deleted projects are excluded from both returned items and total count."""
        p_active = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Active Project",
            status="active",
        )
        p_deleted = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Deleted Project",
            status="active",
            deleted_at=utc_now(),
        )
        db_session.add_all([p_active, p_deleted])
        db_session.commit()

        resp = client.get("/api/v1/projects")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["id"] == str(p_active.id)
        assert data["items"][0]["name"] == "Active Project"

    def test_list_projects_kind_filters(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Filter projects by kind ('github', 'manual') with single and repeated params."""
        # Create GitHub installation for valid github project constraint
        installation = GitHubInstallation(
            installation_id=54321,
            owner_user_id=sample_user.id,
            account_login="alice-org",
            account_type="Organization",
            status="active",
        )
        db_session.add(installation)
        db_session.commit()

        p_gh = Project(
            owner_user_id=sample_user.id,
            kind="github",
            name="gh-repo",
            installation_id=installation.id,
            github_repo_id=999888,
            full_name="alice-org/gh-repo",
            default_branch="main",
            status="active",
        )
        p_manual = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="manual-repo",
            status="active",
        )
        db_session.add_all([p_gh, p_manual])
        db_session.commit()

        # Filter by kind=github
        r_gh = client.get("/api/v1/projects", params={"kind": "github"})
        assert r_gh.status_code == 200
        assert r_gh.json()["total"] == 1
        assert r_gh.json()["items"][0]["kind"] == "github"
        assert r_gh.json()["items"][0]["id"] == str(p_gh.id)

        # Filter by kind=manual
        r_manual = client.get("/api/v1/projects", params={"kind": "manual"})
        assert r_manual.status_code == 200
        assert r_manual.json()["total"] == 1
        assert r_manual.json()["items"][0]["kind"] == "manual"
        assert r_manual.json()["items"][0]["id"] == str(p_manual.id)

        # Repeated parameter: kind=github & kind=manual
        r_multi = client.get("/api/v1/projects", params=[("kind", "github"), ("kind", "manual")])
        assert r_multi.status_code == 200
        assert r_multi.json()["total"] == 2

    def test_list_projects_status_filters(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Filter projects by status ('active', 'access_lost', 'archived') with single and repeated params."""
        p_active = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Active Repo",
            status="active",
        )
        p_archived = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Archived Repo",
            status="archived",
        )
        p_access_lost = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Lost Access Repo",
            status="access_lost",
        )
        db_session.add_all([p_active, p_archived, p_access_lost])
        db_session.commit()

        # Single status filter
        r_archived = client.get("/api/v1/projects", params={"status": "archived"})
        assert r_archived.status_code == 200
        assert r_archived.json()["total"] == 1
        assert r_archived.json()["items"][0]["status"] == "archived"
        assert r_archived.json()["items"][0]["id"] == str(p_archived.id)

        # Multi-status filter
        r_multi = client.get(
            "/api/v1/projects",
            params=[("status", "active"), ("status", "access_lost")],
        )
        assert r_multi.status_code == 200
        assert r_multi.json()["total"] == 2
        statuses = {item["status"] for item in r_multi.json()["items"]}
        assert statuses == {"active", "access_lost"}

    def test_list_projects_invalid_params_return_422(
        self,
        client: TestClient,
    ) -> None:
        """Invalid pagination bounds or unrecognized enum filters return HTTP 422."""
        assert client.get("/api/v1/projects", params={"limit": 0}).status_code == 422
        assert client.get("/api/v1/projects", params={"limit": 101}).status_code == 422
        assert client.get("/api/v1/projects", params={"offset": -1}).status_code == 422
        assert client.get("/api/v1/projects", params={"kind": "subversion"}).status_code == 422
        assert client.get("/api/v1/projects", params={"status": "deleted"}).status_code == 422

    def test_list_projects_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
    ) -> None:
        """Unauthenticated requests fail with HTTP 401 Unauthorized."""
        resp = unauthenticated_client.get("/api/v1/projects")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_list_projects_empty_returns_empty_list(
        self,
        client: TestClient,
    ) -> None:
        """User with no projects receives an empty list and total=0."""
        resp = client.get("/api/v1/projects")
        assert resp.status_code == 200
        assert resp.json() == {
            "items": [],
            "total": 0,
            "limit": 20,
            "offset": 0,
        }

    def test_list_projects_root_and_v1_routes(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Both /projects and /api/v1/projects return identical payloads."""
        p = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Dual Route Project",
            status="active",
        )
        db_session.add(p)
        db_session.commit()

        resp_root = client.get("/projects")
        resp_v1 = client.get("/api/v1/projects")

        assert resp_root.status_code == 200
        assert resp_v1.status_code == 200
        assert resp_root.json() == resp_v1.json()


class TestGetProjectEndpoint:
    """Integration and security tests for GET /projects/{project_id} and GET /api/v1/projects/{project_id}."""

    def test_get_project_manual_owner_success(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Authenticated owner can retrieve a manual project, including its settings."""
        settings_payload = {
            "scan_depth": "deep",
            "ignore_paths": ["vendor/", "node_modules/"],
            "features": {"ai_summaries": True},
        }
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Manual Analysis Service",
            status="active",
            default_branch="develop",
            settings=settings_payload,
        )
        db_session.add(project)
        db_session.commit()

        resp = client.get(f"/api/v1/projects/{project.id}")
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == str(project.id)
        assert data["name"] == "Manual Analysis Service"
        assert data["kind"] == "manual"
        assert data["status"] == "active"
        assert data["installation_id"] is None
        assert data["github_repo_id"] is None
        assert data["full_name"] is None
        assert data["default_branch"] == "develop"
        assert data["settings"] == settings_payload
        assert "created_at" in data
        assert "updated_at" in data

        # Strict response validation: verify no extra or ORM internal keys leaked
        expected_keys = {
            "id",
            "name",
            "kind",
            "status",
            "installation_id",
            "github_repo_id",
            "full_name",
            "default_branch",
            "settings",
            "created_at",
            "updated_at",
        }
        assert set(data.keys()) == expected_keys

    def test_get_project_github_metadata_success(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Authenticated owner can retrieve a GitHub project and its GitHub metadata."""
        installation = GitHubInstallation(
            installation_id=554433,
            owner_user_id=sample_user.id,
            account_login="sentinel-org",
            account_type="Organization",
            status="active",
        )
        db_session.add(installation)
        db_session.commit()

        settings_payload = {"notifications": True, "branch_protection": "strict"}
        project = Project(
            owner_user_id=sample_user.id,
            kind="github",
            name="sentinel-core",
            installation_id=installation.id,
            github_repo_id=987654321,
            full_name="sentinel-org/sentinel-core",
            default_branch="main",
            status="active",
            settings=settings_payload,
        )
        db_session.add(project)
        db_session.commit()

        resp = client.get(f"/api/v1/projects/{project.id}")
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == str(project.id)
        assert data["name"] == "sentinel-core"
        assert data["kind"] == "github"
        assert data["status"] == "active"
        assert data["installation_id"] == str(installation.id)
        assert data["github_repo_id"] == 987654321
        assert data["full_name"] == "sentinel-org/sentinel-core"
        assert data["default_branch"] == "main"
        assert data["settings"] == settings_payload

    def test_get_project_nonexistent_uuid_returns_404(
        self,
        client: TestClient,
    ) -> None:
        """A nonexistent UUID returns generic HTTP 404."""
        nonexistent_id = uuid.uuid4()
        resp = client.get(f"/api/v1/projects/{nonexistent_id}")
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"Project with ID '{nonexistent_id}' not found"

    def test_get_project_cross_tenant_returns_404(
        self,
        client: TestClient,
        db_session: Session,
        other_user: User,
    ) -> None:
        """Querying another tenant's project returns generic HTTP 404 (Threat T4 mitigation)."""
        other_project = Project(
            owner_user_id=other_user.id,
            kind="manual",
            name="Secret Tenant Project",
            status="active",
        )
        db_session.add(other_project)
        db_session.commit()

        # sample_user attempts to access other_user's project
        resp = client.get(f"/api/v1/projects/{other_project.id}")
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"Project with ID '{other_project.id}' not found"

    def test_get_project_soft_deleted_returns_404(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """A soft-deleted project owned by the caller returns generic HTTP 404."""
        deleted_project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Deleted Project",
            status="active",
            deleted_at=utc_now(),
        )
        db_session.add(deleted_project)
        db_session.commit()

        resp = client.get(f"/api/v1/projects/{deleted_project.id}")
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"Project with ID '{deleted_project.id}' not found"

    def test_get_project_malformed_uuid_returns_422(
        self,
        client: TestClient,
    ) -> None:
        """A malformed UUID in the path returns HTTP 422 Unprocessable Entity."""
        assert client.get("/api/v1/projects/not-a-valid-uuid").status_code == 422
        assert client.get("/api/v1/projects/12345").status_code == 422
        assert client.get("/api/v1/projects/0000-invalid").status_code == 422

    def test_get_project_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """An unauthenticated request returns HTTP 401 Unauthorized."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Protected Project",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        resp = unauthenticated_client.get(f"/api/v1/projects/{project.id}")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_get_project_root_and_v1_routes_equivalent(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Root (/projects/{id}) and versioned (/api/v1/projects/{id}) routes return identical payloads."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="Dual Route Detail Project",
            status="active",
            settings={"mode": "standard"},
        )
        db_session.add(project)
        db_session.commit()

        resp_root = client.get(f"/projects/{project.id}")
        resp_v1 = client.get(f"/api/v1/projects/{project.id}")

        assert resp_root.status_code == 200
        assert resp_v1.status_code == 200
        assert resp_root.json() == resp_v1.json()
