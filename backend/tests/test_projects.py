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
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
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


class TestCreateProjectEndpoint:
    """Integration and security tests for POST /projects and POST /api/v1/projects."""

    def test_create_manual_project_success(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Authenticated owner can create a manual project with full fields."""
        payload = {
            "name": "payments-backend",
            "default_branch": "develop",
            "settings": {"scan_depth": "deep", "ignore_paths": ["vendor/"]},
        }
        resp = client.post("/api/v1/projects", json=payload)
        assert resp.status_code == 201
        data = resp.json()

        assert data["name"] == "payments-backend"
        assert data["kind"] == "manual"
        assert data["status"] == "active"
        assert data["installation_id"] is None
        assert data["github_repo_id"] is None
        assert data["full_name"] is None
        assert data["default_branch"] == "develop"
        assert data["settings"] == {"scan_depth": "deep", "ignore_paths": ["vendor/"]}
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

        # Verify DB persistence and tenant binding
        proj_id = uuid.UUID(data["id"])
        db_project = db_session.get(Project, proj_id)
        assert db_project is not None
        assert db_project.owner_user_id == sample_user.id
        assert db_project.name == "payments-backend"
        assert db_project.kind == "manual"
        assert db_project.status == "active"
        assert db_project.deleted_at is None

    def test_create_manual_project_defaults(
        self,
        client: TestClient,
    ) -> None:
        """Omitting optional fields applies correct defaults."""
        resp = client.post("/api/v1/projects", json={"name": "minimal-project"})
        assert resp.status_code == 201
        data = resp.json()

        assert data["name"] == "minimal-project"
        assert data["kind"] == "manual"
        assert data["status"] == "active"
        assert data["default_branch"] == "main"
        assert data["settings"] is None

    def test_create_manual_project_explicit_kind_manual(
        self,
        client: TestClient,
    ) -> None:
        """Explicitly providing kind='manual' is accepted."""
        resp = client.post("/api/v1/projects", json={"name": "explicit-kind", "kind": "manual"})
        assert resp.status_code == 201
        assert resp.json()["kind"] == "manual"

    def test_create_manual_project_duplicate_name_conflict_409(
        self,
        client: TestClient,
    ) -> None:
        """Attempting to create a duplicate project name for the same owner returns HTTP 409."""
        client.post("/api/v1/projects", json={"name": "inventory-api"})

        resp = client.post("/api/v1/projects", json={"name": "inventory-api"})
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    def test_create_manual_project_case_insensitive_duplicate_conflict_409(
        self,
        client: TestClient,
    ) -> None:
        """Duplicate detection is case-insensitive within the same tenant."""
        client.post("/api/v1/projects", json={"name": "audit-service"})

        resp = client.post("/api/v1/projects", json={"name": "AUDIT-SERVICE"})
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    def test_create_manual_project_same_name_different_tenants_allowed(
        self,
        client: TestClient,
        other_client: TestClient,
        db_session: Session,
        sample_user: User,
        other_user: User,
    ) -> None:
        """Different tenants can create projects with the same name without collision."""
        resp1 = client.post("/api/v1/projects", json={"name": "shared-service"})
        assert resp1.status_code == 201

        resp2 = other_client.post("/api/v1/projects", json={"name": "shared-service"})
        assert resp2.status_code == 201

        p1_id = uuid.UUID(resp1.json()["id"])
        p2_id = uuid.UUID(resp2.json()["id"])
        assert p1_id != p2_id

        p1 = db_session.get(Project, p1_id)
        p2 = db_session.get(Project, p2_id)
        assert p1 is not None and p1.owner_user_id == sample_user.id
        assert p2 is not None and p2.owner_user_id == other_user.id

    def test_create_manual_project_soft_deleted_name_reuse_allowed(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """A user can reuse a project name if previous project was soft-deleted."""
        deleted_proj = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="reusable-name",
            status="active",
            deleted_at=utc_now(),
        )
        db_session.add(deleted_proj)
        db_session.commit()

        resp = client.post("/api/v1/projects", json={"name": "reusable-name"})
        assert resp.status_code == 201
        assert resp.json()["name"] == "reusable-name"
        assert uuid.UUID(resp.json()["id"]) != deleted_proj.id

    def test_create_manual_project_spoofed_owner_user_id_rejected_422(
        self,
        client: TestClient,
        other_user: User,
    ) -> None:
        """Attempting to supply owner_user_id in request payload is rejected with HTTP 422."""
        payload = {
            "name": "spoofed-project",
            "owner_user_id": str(other_user.id),
        }
        resp = client.post("/api/v1/projects", json=payload)
        assert resp.status_code == 422

    def test_create_manual_project_github_kind_and_fields_rejected_422(
        self,
        client: TestClient,
    ) -> None:
        """GitHub kind or GitHub-specific fields are strictly rejected with HTTP 422."""
        # Reject kind="github"
        resp1 = client.post("/api/v1/projects", json={"name": "gh1", "kind": "github"})
        assert resp1.status_code == 422

        # Reject installation_id
        resp2 = client.post(
            "/api/v1/projects",
            json={"name": "gh2", "installation_id": str(uuid.uuid4())},
        )
        assert resp2.status_code == 422

        # Reject github_repo_id
        resp3 = client.post("/api/v1/projects", json={"name": "gh3", "github_repo_id": 12345})
        assert resp3.status_code == 422

        # Reject full_name
        resp4 = client.post("/api/v1/projects", json={"name": "gh4", "full_name": "owner/repo"})
        assert resp4.status_code == 422

        # Reject status override
        resp5 = client.post("/api/v1/projects", json={"name": "gh5", "status": "archived"})
        assert resp5.status_code == 422

        # Reject client-supplied ID
        resp6 = client.post("/api/v1/projects", json={"name": "gh6", "id": str(uuid.uuid4())})
        assert resp6.status_code == 422

    def test_create_manual_project_invalid_names_and_branches_rejected_422(
        self,
        client: TestClient,
    ) -> None:
        """Invalid names or branch formats fail validation with HTTP 422."""
        # Empty name
        assert client.post("/api/v1/projects", json={"name": ""}).status_code == 422

        # Whitespace-only name
        assert client.post("/api/v1/projects", json={"name": "   "}).status_code == 422

        # Name too long (> 100 chars)
        assert client.post("/api/v1/projects", json={"name": "a" * 101}).status_code == 422

        # Name with newline or control character
        assert client.post("/api/v1/projects", json={"name": "bad\nproject"}).status_code == 422
        assert client.post("/api/v1/projects", json={"name": "bad\rproject"}).status_code == 422

        # Branch with spaces
        assert (
            client.post(
                "/api/v1/projects",
                json={"name": "good-name", "default_branch": "my branch"},
            ).status_code
            == 422
        )

        # Branch too long (> 100 chars)
        assert (
            client.post(
                "/api/v1/projects",
                json={"name": "good-name", "default_branch": "b" * 101},
            ).status_code
            == 422
        )

    def test_create_manual_project_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
    ) -> None:
        """Unauthenticated requests fail with HTTP 401."""
        resp = unauthenticated_client.post("/api/v1/projects", json={"name": "unauthed"})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_create_manual_project_root_and_v1_routes_parity(
        self,
        client: TestClient,
    ) -> None:
        """Both /projects and /api/v1/projects successfully create projects."""
        r1 = client.post("/projects", json={"name": "root-created"})
        r2 = client.post("/api/v1/projects", json={"name": "v1-created"})

        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["name"] == "root-created"
        assert r2.json()["name"] == "v1-created"

    def test_create_manual_project_owner_user_id_always_derived_from_user(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """The created project is guaranteed to be owned by CurrentUser."""
        resp = client.post("/api/v1/projects", json={"name": "tenant-bound"})
        assert resp.status_code == 201
        project_id = uuid.UUID(resp.json()["id"])

        db_proj = db_session.get(Project, project_id)
        assert db_proj is not None
        assert db_proj.owner_user_id == sample_user.id

    def test_create_manual_project_unrelated_integrity_error_mapped_to_500(
        self,
        client: TestClient,
    ) -> None:
        """Unrelated integrity error (e.g. unexpected column) maps to HTTP 500 without leaking details."""
        simulated_exc = IntegrityError(
            statement="INSERT INTO projects ...",
            params={},
            orig=Exception("NOT NULL constraint failed: projects.unexpected_internal_col"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.post("/api/v1/projects", json={"name": "error-test"})

        assert resp.status_code == 500
        assert resp.json()["detail"] == "An internal error occurred while creating the project."

    def test_create_manual_project_fk_integrity_error_mapped_to_422(
        self,
        client: TestClient,
    ) -> None:
        """Foreign key integrity error maps to HTTP 422 with validation error."""
        simulated_exc = IntegrityError(
            statement="INSERT INTO projects ...",
            params={},
            orig=Exception("FOREIGN KEY constraint failed"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.post("/api/v1/projects", json={"name": "fk-error-test"})

        assert resp.status_code == 422
        assert resp.json()["detail"] == "Referenced user does not exist."

    def test_create_manual_project_check_constraint_integrity_error_mapped_to_422(
        self,
        client: TestClient,
    ) -> None:
        """Known check constraint integrity error maps to HTTP 422."""
        simulated_exc = IntegrityError(
            statement="INSERT INTO projects ...",
            params={},
            orig=Exception("CHECK constraint failed: ck_projects_kind"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.post("/api/v1/projects", json={"name": "check-error-test"})

        assert resp.status_code == 422
        assert resp.json()["detail"] == "Project data violates database integrity constraints."

    def test_create_manual_project_name_unique_integrity_error_mapped_to_409(
        self,
        client: TestClient,
    ) -> None:
        """Project name unique constraint integrity error maps to HTTP 409."""
        simulated_exc = IntegrityError(
            statement="INSERT INTO projects ...",
            params={},
            orig=Exception("UNIQUE constraint failed: projects.name"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.post("/api/v1/projects", json={"name": "unique-error-test"})

        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]


class TestUpdateProjectEndpoint:
    """Integration and security tests for PATCH /projects/{project_id} and PATCH /api/v1/projects/{project_id}."""

    def test_update_manual_project_full_success(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Authenticated owner can update all supported fields at once."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="initial-name",
            default_branch="main",
            status="active",
            settings={"scan_depth": "shallow"},
        )
        db_session.add(project)
        db_session.commit()

        payload = {
            "name": "updated-name",
            "default_branch": "develop",
            "settings": {"scan_depth": "deep", "features": ["ai"]},
        }
        resp = client.patch(f"/api/v1/projects/{project.id}", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == str(project.id)
        assert data["name"] == "updated-name"
        assert data["kind"] == "manual"
        assert data["status"] == "active"
        assert data["default_branch"] == "develop"
        assert data["settings"] == {"scan_depth": "deep", "features": ["ai"]}

        # Verify DB persistence
        db_session.expire_all()
        refreshed = db_session.get(Project, project.id)
        assert refreshed is not None
        assert refreshed.name == "updated-name"
        assert refreshed.default_branch == "develop"
        assert refreshed.settings == {"scan_depth": "deep", "features": ["ai"]}

    def test_update_manual_project_partial_name_only(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Updating name only preserves default_branch and settings."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="name-one",
            default_branch="main",
            status="active",
            settings={"keep": "me"},
        )
        db_session.add(project)
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{project.id}", json={"name": "name-two"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["name"] == "name-two"
        assert data["default_branch"] == "main"
        assert data["settings"] == {"keep": "me"}

        db_session.expire_all()
        refreshed = db_session.get(Project, project.id)
        assert refreshed is not None
        assert refreshed.name == "name-two"
        assert refreshed.default_branch == "main"
        assert refreshed.settings == {"keep": "me"}

    def test_update_manual_project_partial_branch_only(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Updating default_branch only preserves name and settings."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="keep-name",
            default_branch="main",
            status="active",
            settings={"key": "val"},
        )
        db_session.add(project)
        db_session.commit()

        resp = client.patch(
            f"/api/v1/projects/{project.id}", json={"default_branch": "release/1.0"}
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["name"] == "keep-name"
        assert data["default_branch"] == "release/1.0"
        assert data["settings"] == {"key": "val"}

    def test_update_manual_project_partial_settings_only(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Updating settings only preserves name and default_branch."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="static-name",
            default_branch="master",
            status="active",
            settings={"initial": 1},
        )
        db_session.add(project)
        db_session.commit()

        resp = client.patch(
            f"/api/v1/projects/{project.id}", json={"settings": {"initial": 2, "new": 3}}
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["name"] == "static-name"
        assert data["default_branch"] == "master"
        assert data["settings"] == {"initial": 2, "new": 3}

    def test_update_manual_project_clear_settings_explicit_null(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Explicitly sending settings: null clears the settings field."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="settings-clear-test",
            default_branch="main",
            status="active",
            settings={"to_be_cleared": True},
        )
        db_session.add(project)
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{project.id}", json={"settings": None})
        assert resp.status_code == 200
        data = resp.json()

        assert data["settings"] is None

        db_session.expire_all()
        refreshed = db_session.get(Project, project.id)
        assert refreshed is not None
        assert refreshed.settings is None

    def test_update_manual_project_omitted_settings_preserves_existing(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Omitted settings field in payload leaves existing settings untouched."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="omitted-settings-test",
            default_branch="main",
            status="active",
            settings={"preserved": "yes"},
        )
        db_session.add(project)
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{project.id}", json={"name": "new-title"})
        assert resp.status_code == 200
        assert resp.json()["settings"] == {"preserved": "yes"}

    def test_update_project_same_name_noop_success_200(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Submitting the project's current name is a no-op that succeeds without conflict."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="current-name",
            default_branch="main",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{project.id}", json={"name": "current-name"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "current-name"

    def test_update_project_duplicate_name_conflict_409(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Renaming a project to another active project's name in the same tenant fails with 409."""
        p1 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="existing-alpha",
            status="active",
        )
        p2 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="existing-beta",
            status="active",
        )
        db_session.add_all([p1, p2])
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{p2.id}", json={"name": "existing-alpha"})
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    def test_update_project_case_insensitive_duplicate_conflict_409(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Duplicate detection on rename is case-insensitive."""
        p1 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="my-service",
            status="active",
        )
        p2 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="other-service",
            status="active",
        )
        db_session.add_all([p1, p2])
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{p2.id}", json={"name": "MY-SERVICE"})
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    def test_update_project_same_name_different_tenants_allowed(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
        other_user: User,
    ) -> None:
        """A project can be renamed to match a project name in a different tenant."""
        other_project = Project(
            owner_user_id=other_user.id,
            kind="manual",
            name="cross-tenant-name",
            status="active",
        )
        my_project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="original-name",
            status="active",
        )
        db_session.add_all([other_project, my_project])
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{my_project.id}", json={"name": "cross-tenant-name"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "cross-tenant-name"

    def test_update_project_soft_deleted_name_reuse_allowed(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """A project can be renamed to the name of a soft-deleted project in the same tenant."""
        deleted_proj = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="archived-project",
            status="active",
            deleted_at=utc_now(),
        )
        active_proj = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="live-project",
            status="active",
        )
        db_session.add_all([deleted_proj, active_proj])
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{active_proj.id}", json={"name": "archived-project"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "archived-project"

    def test_update_project_cross_tenant_forbidden_returns_404(
        self,
        client: TestClient,
        db_session: Session,
        other_user: User,
    ) -> None:
        """Attempting to update another tenant's project returns generic 404 (Threat T4)."""
        other_project = Project(
            owner_user_id=other_user.id,
            kind="manual",
            name="other-tenant-proj",
            status="active",
        )
        db_session.add(other_project)
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{other_project.id}", json={"name": "hijacked-name"})
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"Project with ID '{other_project.id}' not found"

    def test_update_project_nonexistent_returns_404(
        self,
        client: TestClient,
    ) -> None:
        """Updating a nonexistent project ID returns generic 404."""
        random_id = uuid.uuid4()
        resp = client.patch(f"/api/v1/projects/{random_id}", json={"name": "new-name"})
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"Project with ID '{random_id}' not found"

    def test_update_project_soft_deleted_returns_404(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Updating a soft-deleted project returns generic 404."""
        deleted_proj = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="deleted-proj",
            status="active",
            deleted_at=utc_now(),
        )
        db_session.add(deleted_proj)
        db_session.commit()

        resp = client.patch(f"/api/v1/projects/{deleted_proj.id}", json={"name": "revived-name"})
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"Project with ID '{deleted_proj.id}' not found"

    def test_update_project_malformed_uuid_returns_422(
        self,
        client: TestClient,
    ) -> None:
        """Malformed UUID path parameter returns HTTP 422."""
        assert (
            client.patch("/api/v1/projects/not-a-uuid", json={"name": "new-name"}).status_code
            == 422
        )
        assert client.patch("/api/v1/projects/12345", json={"name": "new-name"}).status_code == 422

    def test_update_project_protected_fields_rejected_422(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Attempts to update protected fields via PATCH payload are rejected with 422."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="protected-fields-test",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        protected_payloads = [
            {"id": str(uuid.uuid4())},
            {"owner_user_id": str(uuid.uuid4())},
            {"kind": "github"},
            {"status": "archived"},
            {"installation_id": 12345},
            {"github_repo_id": 67890},
            {"full_name": "org/repo"},
            {"created_at": "2026-01-01T00:00:00Z"},
            {"updated_at": "2026-01-01T00:00:00Z"},
            {"deleted_at": "2026-01-01T00:00:00Z"},
        ]
        for payload in protected_payloads:
            resp = client.patch(f"/api/v1/projects/{project.id}", json=payload)
            assert resp.status_code == 422, f"Payload {payload} should have been rejected with 422"

    def test_update_project_invalid_name_and_branch_rejected_422(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Validation rules for name and default_branch are strictly enforced on update."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="validation-test",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        invalid_payloads = [
            {"name": ""},
            {"name": "   "},
            {"name": None},
            {"name": "bad\nname"},
            {"name": "bad\rname"},
            {"name": "bad\tname"},
            {"name": "bad\0name"},
            {"name": "a" * 101},
            {"default_branch": ""},
            {"default_branch": None},
            {"default_branch": "has space"},
            {"default_branch": "has\ttab"},
            {"default_branch": "has\0null"},
            {"default_branch": "b" * 101},
        ]
        for payload in invalid_payloads:
            resp = client.patch(f"/api/v1/projects/{project.id}", json=payload)
            assert resp.status_code == 422, f"Payload {payload} should have been rejected with 422"

    def test_update_project_unauthenticated_returns_401(
        self,
        unauthenticated_client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Unauthenticated requests fail with HTTP 401."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="unauth-test",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        resp = unauthenticated_client.patch(
            f"/api/v1/projects/{project.id}", json={"name": "new-name"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_update_project_preserves_github_metadata(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Updating a GitHub project preserves installation and repository associations."""
        installation = GitHubInstallation(
            installation_id=998877,
            owner_user_id=sample_user.id,
            account_login="github-org",
            account_type="Organization",
            status="active",
        )
        db_session.add(installation)
        db_session.commit()

        project = Project(
            owner_user_id=sample_user.id,
            kind="github",
            name="github-repo",
            installation_id=installation.id,
            github_repo_id=11223344,
            full_name="github-org/github-repo",
            default_branch="main",
            status="active",
            settings={"ci": True},
        )
        db_session.add(project)
        db_session.commit()

        payload = {
            "name": "renamed-gh-repo",
            "default_branch": "develop",
            "settings": {"ci": False, "notifications": True},
        }
        resp = client.patch(f"/api/v1/projects/{project.id}", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == str(project.id)
        assert data["name"] == "renamed-gh-repo"
        assert data["kind"] == "github"
        assert data["status"] == "active"
        assert data["installation_id"] == str(installation.id)
        assert data["github_repo_id"] == 11223344
        assert data["full_name"] == "github-org/github-repo"
        assert data["default_branch"] == "develop"
        assert data["settings"] == {"ci": False, "notifications": True}

        # Verify DB preservation
        db_session.expire_all()
        refreshed = db_session.get(Project, project.id)
        assert refreshed is not None
        assert refreshed.kind == "github"
        assert refreshed.installation_id == installation.id
        assert refreshed.github_repo_id == 11223344
        assert refreshed.full_name == "github-org/github-repo"

    def test_update_project_root_and_v1_routes_parity(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Both /projects/{id} and /api/v1/projects/{id} routes behave identically."""
        p1 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="route-test-root",
            status="active",
        )
        p2 = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="route-test-v1",
            status="active",
        )
        db_session.add_all([p1, p2])
        db_session.commit()

        resp_root = client.patch(f"/projects/{p1.id}", json={"name": "renamed-root"})
        resp_v1 = client.patch(f"/api/v1/projects/{p2.id}", json={"name": "renamed-v1"})

        assert resp_root.status_code == 200
        assert resp_v1.status_code == 200
        assert resp_root.json()["name"] == "renamed-root"
        assert resp_v1.json()["name"] == "renamed-v1"

    def test_update_project_unrelated_integrity_error_mapped_to_500(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Unrelated integrity error on update maps to HTTP 500 without leaking details."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="integ-err-500",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        simulated_exc = IntegrityError(
            statement="UPDATE projects ...",
            params={},
            orig=Exception("NOT NULL constraint failed: projects.unexpected_internal_col"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.patch(f"/api/v1/projects/{project.id}", json={"name": "trigger-error"})

        assert resp.status_code == 500
        assert resp.json()["detail"] == "An internal error occurred while updating the project."

    def test_update_project_name_unique_integrity_error_mapped_to_409(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Project name unique constraint integrity error on update maps to HTTP 409."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="integ-err-409",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        simulated_exc = IntegrityError(
            statement="UPDATE projects ...",
            params={},
            orig=Exception("UNIQUE constraint failed: projects.name"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.patch(f"/api/v1/projects/{project.id}", json={"name": "trigger-conflict"})

        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    def test_update_project_check_constraint_integrity_error_mapped_to_422(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Known check constraint integrity error on update maps to HTTP 422."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="integ-err-ck",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        simulated_exc = IntegrityError(
            statement="UPDATE projects ...",
            params={},
            orig=Exception("CHECK constraint failed: ck_projects_kind"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.patch(f"/api/v1/projects/{project.id}", json={"name": "trigger-check"})

        assert resp.status_code == 422
        assert resp.json()["detail"] == "Project data violates database integrity constraints."

    def test_update_project_fk_integrity_error_mapped_to_422(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
    ) -> None:
        """Foreign key integrity error on update maps to HTTP 422 with validation error."""
        project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="integ-err-fk",
            status="active",
        )
        db_session.add(project)
        db_session.commit()

        simulated_exc = IntegrityError(
            statement="UPDATE projects ...",
            params={},
            orig=Exception("FOREIGN KEY constraint failed"),
        )
        with patch.object(Session, "flush", side_effect=simulated_exc):
            resp = client.patch(f"/api/v1/projects/{project.id}", json={"name": "trigger-fk"})

        assert resp.status_code == 422
        assert resp.json()["detail"] == "Referenced user does not exist."
