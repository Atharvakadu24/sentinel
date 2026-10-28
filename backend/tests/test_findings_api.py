"""Comprehensive API integration tests for Findings Query and Status Review.

Validates Blueprint Section 9.4 (Findings API contracts), Section 7 (Workflow C),
Section 8.1 (Persistent findings and append-only audit trail), and Section 12 (Threat T4 Tenant Isolation):
- GET /projects/{project_id}/findings: stable pagination, filters (status, severity, source), text search, ordering.
- GET /findings/{finding_id}: detail view with latest occurrence evidence, safe fields, secret confidentiality.
- PATCH /findings/{finding_id}/status: state transitions, reason validation (3-500 chars), optimistic concurrency (409 on stale update), atomic history insertion, actor attribution.
- GET /findings/{finding_id}/history: paginated, deterministic reverse chronological ordering.
- Project authorization and cross-project tenant isolation (404 on foreign tenant resources).
- System-driven worker reopening behavior preserved.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Generator
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import (
    Finding,
    FindingStatusHistory,
    Project,
    Scan,
    ScanFinding,
    User,
    UserSession,
)
from app.db.session import get_db_session, session_scope
from app.domain.findings import (
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
)
from app.main import app
from app.services.finding_service import (
    FindingStatusConflictError,
    get_finding_detail,
    persist_scan_findings,
    update_finding_status,
)


@pytest.fixture
def test_engine() -> Engine:
    """Isolated in-memory SQLite engine with foreign key enforcement."""
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
    """Session factory for test database."""
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
    """Primary authenticated user."""
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
    """Second user for tenant isolation and cross-project testing."""
    user = User(
        github_user_id=2002,
        github_login="bob-attacker",
        display_name="Bob Attacker",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def sample_project(db_session: Session, sample_user: User) -> Project:
    """Project owned by primary user."""
    project = Project(
        owner_user_id=sample_user.id,
        kind="manual",
        name="alice-repo",
        status="active",
    )
    db_session.add(project)
    db_session.commit()
    return project


@pytest.fixture
def other_project(db_session: Session, other_user: User) -> Project:
    """Project owned by second user."""
    project = Project(
        owner_user_id=other_user.id,
        kind="manual",
        name="bob-repo",
        status="active",
    )
    db_session.add(project)
    db_session.commit()
    return project


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
    """TestClient with no user authentication override (real session dependency runs)."""

    def override_get_db_session() -> Generator[Session, None, None]:
        with session_scope(session_factory) as session:
            yield session

    app.dependency_overrides[get_db_session] = override_get_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def create_test_finding(
    db_session: Session,
    *,
    project: Project,
    rule_id: str = "python.security.injection.sql",
    source: FindingSource = FindingSource.SEMGREP,
    category: FindingCategory = FindingCategory.INJECTION,
    title: str = "SQL Injection in User Query",
    file_path: str | None = None,
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: FindingConfidence = FindingConfidence.HIGH,
    verification_status: VerificationStatus = VerificationStatus.SCANNER_DETECTED,
    snippet: str = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    description: str = "Direct string formatting into SQL query.",
    remediation: str = "Use parameterized queries.",
    status: str = "open",
    status_reason: str | None = None,
    created_offset_minutes: int = 0,
    code_anchor: str | None = None,
) -> Finding:
    """Helper to persist a test finding with associated Scan and ScanFinding observation."""
    actual_file_path = file_path or f"src/db_{uuid.uuid4().hex[:8]}.py"

    scan = Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        trigger="manual",
        trigger_key=f"scan-key-{uuid.uuid4()}",
        status="succeeded",
    )
    db_session.add(scan)
    db_session.flush()

    finding_time = utc_now() - timedelta(minutes=created_offset_minutes)

    canonical_anchor = code_anchor
    if canonical_anchor is None and (
        category == FindingCategory.HARDCODED_SECRET or source == FindingSource.GITLEAKS
    ):
        canonical_anchor = "0123456789abcdef"

    canonical = CanonicalFinding.create_canonical(
        rule_id=rule_id,
        source=source,
        category=category,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        verification_status=verification_status,
        file_path=actual_file_path,
        start_line=10,
        end_line=12,
        snippet=snippet,
        remediation=remediation,
        code_anchor=canonical_anchor,
    )

    finding = Finding(
        id=uuid.uuid4(),
        project_id=project.id,
        fingerprint=canonical.fingerprint,
        rule_id=rule_id,
        source=source.value,
        category=category.value,
        title=title,
        file_path=actual_file_path,
        status=status,
        status_reason=status_reason,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
        first_seen_at=finding_time,
        last_seen_at=finding_time,
        created_at=finding_time,
    )
    db_session.add(finding)
    db_session.flush()

    sf = ScanFinding(
        id=uuid.uuid4(),
        scan_id=scan.id,
        finding_id=finding.id,
        severity=severity.value,
        confidence=confidence.value,
        verification_status=verification_status.value,
        start_line=10,
        end_line=12,
        snippet=snippet,
        snippet_start_line=10,
        in_diff=True,
        description=description,
        remediation=remediation,
        references=[
            {"type": "cwe", "id": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html"}
        ],
        sources=[{"source": source.value, "rule_id": rule_id}],
        created_at=finding_time,
    )
    db_session.add(sf)
    db_session.commit()
    return finding


class TestListFindingsEndpoint:
    """Tests for GET /projects/{project_id}/findings."""

    def test_list_findings_pagination_and_deterministic_order(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify pagination total, limit, offset, and stable last_seen_at DESC, id ASC order."""
        f1 = create_test_finding(
            db_session, project=sample_project, title="Oldest Finding", created_offset_minutes=30
        )
        f2 = create_test_finding(
            db_session, project=sample_project, title="Middle Finding", created_offset_minutes=15
        )
        f3 = create_test_finding(
            db_session, project=sample_project, title="Newest Finding", created_offset_minutes=0
        )

        # Page 1: limit=2, offset=0
        resp1 = client.get(f"/api/v1/projects/{sample_project.id}/findings?limit=2&offset=0")
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["total"] == 3
        assert data1["limit"] == 2
        assert data1["offset"] == 0
        assert len(data1["items"]) == 2
        assert data1["items"][0]["id"] == str(f3.id)
        assert data1["items"][1]["id"] == str(f2.id)

        # Page 2: limit=2, offset=2
        resp2 = client.get(f"/api/v1/projects/{sample_project.id}/findings?limit=2&offset=2")
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 3
        assert len(data2["items"]) == 1
        assert data2["items"][0]["id"] == str(f1.id)

    def test_list_findings_filter_status(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify filtering by persistent finding status."""
        create_test_finding(db_session, project=sample_project, title="Open 1", status="open")
        create_test_finding(db_session, project=sample_project, title="Open 2", status="open")
        create_test_finding(
            db_session, project=sample_project, title="Accepted 1", status="accepted"
        )

        resp = client.get(f"/api/v1/projects/{sample_project.id}/findings?status=accepted")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["status"] == "accepted"
        assert data["items"][0]["title"] == "Accepted 1"

    def test_list_findings_filter_severity_and_source(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify filtering by latest observed severity and originating source."""
        create_test_finding(
            db_session,
            project=sample_project,
            source=FindingSource.SEMGREP,
            severity=FindingSeverity.CRITICAL,
            title="Critical Semgrep",
        )
        create_test_finding(
            db_session,
            project=sample_project,
            source=FindingSource.GITLEAKS,
            category=FindingCategory.HARDCODED_SECRET,
            severity=FindingSeverity.HIGH,
            title="High Gitleaks",
            snippet="TOKEN = '[REDACTED]'",
        )

        resp = client.get(
            f"/api/v1/projects/{sample_project.id}/findings?source=gitleaks&severity=high"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["source"] == "gitleaks"
        assert data["items"][0]["severity"] == "high"
        assert data["items"][0]["title"] == "High Gitleaks"

    def test_list_findings_text_search(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify bounded substring search across title, file_path, and rule_id."""
        create_test_finding(
            db_session,
            project=sample_project,
            title="Command Injection Flaw",
            file_path="src/executor.py",
            rule_id="python.security.command.injection",
        )
        create_test_finding(
            db_session,
            project=sample_project,
            title="XSS in Template",
            file_path="templates/user.html",
            rule_id="html.security.xss",
        )

        # Search by file path substring
        resp_path = client.get(f"/api/v1/projects/{sample_project.id}/findings?q=executor")
        assert resp_path.status_code == 200
        assert resp_path.json()["total"] == 1
        assert resp_path.json()["items"][0]["file_path"] == "src/executor.py"

        # Search by rule_id substring
        resp_rule = client.get(f"/api/v1/projects/{sample_project.id}/findings?q=command.injection")
        assert resp_rule.status_code == 200
        assert resp_rule.json()["total"] == 1

        # Search by title substring
        resp_title = client.get(f"/api/v1/projects/{sample_project.id}/findings?q=Template")
        assert resp_title.status_code == 200
        assert resp_title.json()["total"] == 1
        assert resp_title.json()["items"][0]["title"] == "XSS in Template"

    def test_list_findings_input_validation(
        self,
        client: TestClient,
        sample_project: Project,
    ) -> None:
        """Verify query parameter validation limits and rejection of invalid values."""
        # limit < 1
        resp_limit_low = client.get(f"/api/v1/projects/{sample_project.id}/findings?limit=0")
        assert resp_limit_low.status_code == 422

        # limit > 100
        resp_limit_high = client.get(f"/api/v1/projects/{sample_project.id}/findings?limit=101")
        assert resp_limit_high.status_code == 422

        # offset < 0
        resp_offset = client.get(f"/api/v1/projects/{sample_project.id}/findings?offset=-1")
        assert resp_offset.status_code == 422

        # invalid status enum
        resp_status = client.get(
            f"/api/v1/projects/{sample_project.id}/findings?status=invalid_status"
        )
        assert resp_status.status_code == 422

        # q search exceeding 100 characters
        resp_q_long = client.get(f"/api/v1/projects/{sample_project.id}/findings?q={'a' * 101}")
        assert resp_q_long.status_code == 422


class TestGetFindingDetailEndpoint:
    """Tests for GET /findings/{finding_id}."""

    def test_get_finding_detail_success_with_evidence(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify finding details return canonical attributes and occurrence evidence."""
        finding = create_test_finding(
            db_session,
            project=sample_project,
            title="Sensitive Secret in Code",
            source=FindingSource.GITLEAKS,
            category=FindingCategory.HARDCODED_SECRET,
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            snippet="API_SECRET = '[REDACTED:generic-secret]'",
            description="Detected API secret in source.",
            remediation="Rotate secret immediately.",
        )

        resp = client.get(f"/api/v1/findings/{finding.id}")
        assert resp.status_code == 200
        data = resp.json()

        # Core finding properties
        assert data["id"] == str(finding.id)
        assert data["project_id"] == str(sample_project.id)
        assert data["title"] == "Sensitive Secret in Code"
        assert data["source"] == "gitleaks"
        assert data["category"] == "hardcoded_secret"
        assert data["status"] == "open"

        # Evidence fields
        assert data["severity"] == "high"
        assert data["confidence"] == "high"
        assert data["verification_status"] == "scanner_detected"
        assert data["start_line"] == 10
        assert data["end_line"] == 12
        assert "[REDACTED:generic-secret]" in data["snippet"]
        assert data["description"] == "Detected API secret in source."
        assert data["remediation"] == "Rotate secret immediately."
        assert len(data["references"]) == 1
        assert data["references"][0]["id"] == "CWE-89"

        # Safety: raw metadata must NEVER be exposed
        assert "raw" not in data

    def test_get_finding_detail_not_found(
        self,
        client: TestClient,
    ) -> None:
        """Verify 404 for non-existent finding ID."""
        random_id = uuid.uuid4()
        resp = client.get(f"/api/v1/findings/{random_id}")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_fallback_occurrence_deterministic_secondary_sort(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When last_seen_scan_id is null, fallback occurrence ordering uses ScanFinding.id.desc() as tie-breaker."""
        finding = create_test_finding(
            db_session,
            project=sample_project,
            title="Tied Timestamp Finding",
        )
        # Clear last_seen_scan_id to force fallback query
        finding.last_seen_scan_id = None
        db_session.flush()

        # Delete automatically created occurrence from create_test_finding
        db_session.query(ScanFinding).filter(ScanFinding.finding_id == finding.id).delete()
        db_session.flush()

        scan1 = Scan(
            id=uuid.uuid4(),
            project_id=sample_project.id,
            trigger="manual",
            trigger_key=f"scan-tied-1-{uuid.uuid4()}",
            status="succeeded",
        )
        scan2 = Scan(
            id=uuid.uuid4(),
            project_id=sample_project.id,
            trigger="manual",
            trigger_key=f"scan-tied-2-{uuid.uuid4()}",
            status="succeeded",
        )
        db_session.add_all([scan1, scan2])
        db_session.flush()

        tied_timestamp = utc_now()
        id_lower = uuid.UUID("00000000-0000-0000-0000-000000000001")
        id_higher = uuid.UUID("00000000-0000-0000-0000-000000000002")

        sf_lower = ScanFinding(
            id=id_lower,
            scan_id=scan1.id,
            finding_id=finding.id,
            severity="medium",
            confidence="high",
            verification_status="scanner_detected",
            start_line=1,
            end_line=2,
            snippet="lower_id_snippet()",
            description="Lower ID description.",
            remediation="Remediate lower.",
            in_diff=True,
            created_at=tied_timestamp,
        )
        sf_higher = ScanFinding(
            id=id_higher,
            scan_id=scan2.id,
            finding_id=finding.id,
            severity="high",
            confidence="high",
            verification_status="scanner_detected",
            start_line=1,
            end_line=2,
            snippet="higher_id_snippet()",
            description="Higher ID description.",
            remediation="Remediate higher.",
            in_diff=True,
            created_at=tied_timestamp,
        )
        db_session.add_all([sf_lower, sf_higher])
        db_session.commit()

        detail = get_finding_detail(db_session, finding.id)
        assert detail is not None
        # Must pick sf_higher because of ScanFinding.id.desc() tie-breaker
        assert detail["snippet"] == "higher_id_snippet()"
        assert detail["severity"] == "high"


class TestPatchFindingStatusEndpoint:
    """Tests for PATCH /findings/{finding_id}/status."""

    def test_status_transition_to_false_positive_with_reason(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Verify successful transition to false_positive with valid 3-500 char reason."""
        finding = create_test_finding(db_session, project=sample_project, status="open")

        payload = {
            "status": "false_positive",
            "expected_status": "open",
            "reason": "Test fixture dummy token used exclusively in mocked unit tests.",
        }

        resp = client.patch(f"/api/v1/findings/{finding.id}/status", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "false_positive"
        assert data["status_reason"] == payload["reason"]
        assert data["status_updated_by"] == str(sample_user.id)
        assert data["status_updated_at"] is not None

        # Verify database persistence & status history audit entry
        db_session.expire_all()
        db_finding = db_session.get(Finding, finding.id)
        assert db_finding is not None
        assert db_finding.status == "false_positive"
        assert db_finding.status_updated_by == sample_user.id

        history = db_session.scalars(
            select(FindingStatusHistory).where(FindingStatusHistory.finding_id == finding.id)
        ).all()
        assert len(history) == 1
        assert history[0].from_status == "open"
        assert history[0].to_status == "false_positive"
        assert history[0].actor_type == "user"
        assert history[0].actor_user_id == sample_user.id
        assert history[0].reason == payload["reason"]

    def test_status_transition_to_accepted_risk(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify transition to accepted risk with valid reason."""
        finding = create_test_finding(db_session, project=sample_project, status="open")

        payload = {
            "status": "accepted",
            "expected_status": "open",
            "reason": "Compensating Web Application Firewall controls are in place in production.",
        }

        resp = client.patch(f"/api/v1/findings/{finding.id}/status", json=payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"

    def test_status_transition_reopen_to_open(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify reopening an accepted/false_positive finding back to open."""
        finding = create_test_finding(
            db_session, project=sample_project, status="accepted", status_reason="Prior waiver"
        )

        payload = {
            "status": "open",
            "expected_status": "accepted",
            "reason": "WAF rule deprecated; reopening finding for active engineering remediation.",
        }

        resp = client.patch(f"/api/v1/findings/{finding.id}/status", json=payload)
        assert resp.status_code == 200
        assert resp.json()["status"] == "open"
        assert resp.json()["status_reason"] == payload["reason"]

    def test_status_transition_reason_validation_errors(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify that transitions requiring reasons fail with 422 if reason is missing, <3, or >500 chars."""
        finding = create_test_finding(db_session, project=sample_project, status="open")

        # 1. Missing reason
        resp_missing = client.patch(
            f"/api/v1/findings/{finding.id}/status",
            json={"status": "false_positive", "expected_status": "open"},
        )
        assert resp_missing.status_code == 422
        assert "reason" in resp_missing.text.lower()

        # 2. Reason too short (<3 characters)
        resp_short = client.patch(
            f"/api/v1/findings/{finding.id}/status",
            json={"status": "false_positive", "expected_status": "open", "reason": "no"},
        )
        assert resp_short.status_code == 422
        assert "between 3 and 500 characters" in resp_short.json()["detail"]

        # 3. Reason too long (>500 characters)
        resp_long = client.patch(
            f"/api/v1/findings/{finding.id}/status",
            json={"status": "false_positive", "expected_status": "open", "reason": "x" * 501},
        )
        assert resp_long.status_code == 422

    def test_status_transition_invalid_same_status(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Transitioning to the same status is rejected with 422."""
        finding = create_test_finding(db_session, project=sample_project, status="open")

        resp = client.patch(
            f"/api/v1/findings/{finding.id}/status",
            json={"status": "open", "expected_status": "open", "reason": "Still open."},
        )
        assert resp.status_code == 422
        assert "already in status" in resp.json()["detail"]

    def test_optimistic_concurrency_conflict_409(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Mismatched expected_status returns 409 Conflict (optimistic concurrency guard)."""
        finding = create_test_finding(db_session, project=sample_project, status="open")

        # Client sends expected_status='fixed', but finding is currently 'open'
        payload = {
            "status": "false_positive",
            "expected_status": "fixed",
            "reason": "Attempting transition with stale status belief.",
        }

        resp = client.patch(f"/api/v1/findings/{finding.id}/status", json=payload)
        assert resp.status_code == 409
        assert "Finding status conflict" in resp.json()["detail"]

        # Verify status did not change
        db_finding = db_session.get(Finding, finding.id)
        assert db_finding is not None
        assert db_finding.status == "open"

    def test_status_update_refreshes_cached_finding_and_detects_conflict(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Verify update_finding_status uses populate_existing=True to refresh identity map from database."""
        finding = create_test_finding(db_session, project=sample_project, status="open")

        # Load finding into db_session's identity map
        cached_finding = db_session.get(Finding, finding.id)
        assert cached_finding is not None
        assert cached_finding.status == "open"

        # Simulate a concurrent transaction modifying the status in the DB
        with session_factory() as concurrent_session:
            concurrent_finding = concurrent_session.get(Finding, finding.id)
            assert concurrent_finding is not None
            concurrent_finding.status = "false_positive"
            concurrent_session.commit()

        # In db_session, without refreshing, cached_finding.status would still be "open" in memory.
        # But update_finding_status uses populate_existing=True on select,
        # which overwrites the in-memory cached attributes with the database state.
        # Therefore, expected_status="open" should conflict with the DB's "false_positive" status.
        with pytest.raises(FindingStatusConflictError) as exc_info:
            update_finding_status(
                db_session,
                finding_id=finding.id,
                new_status="accepted",
                expected_status="open",
                reason="Attempted waiver while stale.",
                user_id=sample_user.id,
            )
        assert "Finding status conflict" in str(exc_info.value)
        assert "false_positive" in str(exc_info.value)
        assert cached_finding.status == "false_positive"


class TestGetFindingHistoryEndpoint:
    """Tests for GET /findings/{finding_id}/history."""

    def test_get_finding_history_pagination_and_ordering(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Verify status history returns paginated records in reverse chronological order."""
        finding = create_test_finding(db_session, project=sample_project, status="open")

        now = utc_now()
        h1 = FindingStatusHistory(
            id=uuid.uuid4(),
            finding_id=finding.id,
            from_status="open",
            to_status="false_positive",
            actor_type="user",
            actor_user_id=sample_user.id,
            reason="First review transition",
            created_at=now - timedelta(minutes=10),
        )
        h2 = FindingStatusHistory(
            id=uuid.uuid4(),
            finding_id=finding.id,
            from_status="false_positive",
            to_status="open",
            actor_type="user",
            actor_user_id=sample_user.id,
            reason="Second review transition (reopened)",
            created_at=now - timedelta(minutes=5),
        )
        db_session.add_all([h1, h2])
        db_session.commit()

        resp = client.get(f"/api/v1/findings/{finding.id}/history?limit=10&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

        # Most recent first
        assert data["items"][0]["id"] == str(h2.id)
        assert data["items"][0]["from_status"] == "false_positive"
        assert data["items"][0]["to_status"] == "open"
        assert data["items"][0]["actor_type"] == "user"
        assert data["items"][0]["actor_user_id"] == str(sample_user.id)

        assert data["items"][1]["id"] == str(h1.id)
        assert data["items"][1]["from_status"] == "open"
        assert data["items"][1]["to_status"] == "false_positive"


class TestAuthorizationAndTenantIsolation:
    """Tests for authentication and cross-project tenant isolation (Threat Mitigation T4)."""

    def test_unauthenticated_requests_fail_closed_401(
        self,
        unauthenticated_client: TestClient,
        sample_project: Project,
        db_session: Session,
    ) -> None:
        """Requests without authenticated session fail closed with 401 Unauthorized."""
        finding = create_test_finding(db_session, project=sample_project)

        # GET /projects/{id}/findings
        r1 = unauthenticated_client.get(f"/api/v1/projects/{sample_project.id}/findings")
        assert r1.status_code == 401
        assert "Authentication required" in r1.json()["detail"]

        # GET /findings/{id}
        r2 = unauthenticated_client.get(f"/api/v1/findings/{finding.id}")
        assert r2.status_code == 401

        # PATCH /findings/{id}/status
        r3 = unauthenticated_client.patch(
            f"/api/v1/findings/{finding.id}/status",
            json={"status": "accepted", "expected_status": "open", "reason": "Test waiver reason."},
        )
        assert r3.status_code == 401

        # GET /findings/{id}/history
        r4 = unauthenticated_client.get(f"/api/v1/findings/{finding.id}/history")
        assert r4.status_code == 401

    def test_cross_project_isolation_returns_404(
        self,
        client: TestClient,
        other_client: TestClient,
        db_session: Session,
        sample_project: Project,
        other_project: Project,
    ) -> None:
        """User cannot view or modify findings belonging to another tenant's project (404 Not Found)."""
        # Alice creates finding in Alice's project
        alice_finding = create_test_finding(
            db_session, project=sample_project, title="Alice Secret"
        )

        # Bob creates finding in Bob's project
        bob_finding = create_test_finding(db_session, project=other_project, title="Bob Secret")

        # Bob attempts to list Alice's project findings -> 404
        r_list = other_client.get(f"/api/v1/projects/{sample_project.id}/findings")
        assert r_list.status_code == 404

        # Bob attempts to read Alice's finding detail -> 404
        r_get = other_client.get(f"/api/v1/findings/{alice_finding.id}")
        assert r_get.status_code == 404

        # Bob attempts to patch Alice's finding status -> 404
        r_patch = other_client.patch(
            f"/api/v1/findings/{alice_finding.id}/status",
            json={
                "status": "false_positive",
                "expected_status": "open",
                "reason": "Unauthorized attempt.",
            },
        )
        assert r_patch.status_code == 404

        # Bob attempts to read Alice's finding history -> 404
        r_hist = other_client.get(f"/api/v1/findings/{alice_finding.id}/history")
        assert r_hist.status_code == 404

        # Alice attempts to read Bob's finding detail -> 404
        r_alice_bob = client.get(f"/api/v1/findings/{bob_finding.id}")
        assert r_alice_bob.status_code == 404

    def test_soft_deleted_user_fails_closed_401(
        self,
        client: TestClient,
        db_session: Session,
        sample_user: User,
        sample_project: Project,
    ) -> None:
        """Sessions belonging to soft-deleted users fail closed with 401 Unauthorized."""
        finding = create_test_finding(db_session, project=sample_project)

        # Baseline: normal authenticated request succeeds
        resp_before = client.get(f"/api/v1/projects/{sample_project.id}/findings")
        assert resp_before.status_code == 200

        # Soft-delete the user
        sample_user.deleted_at = utc_now()
        db_session.commit()

        # Bearer token request must fail with 401 Unauthorized
        resp_after = client.get(f"/api/v1/projects/{sample_project.id}/findings")
        assert resp_after.status_code == 401
        assert "Authentication required" in resp_after.json()["detail"]

        # Detail endpoint must also fail with 401
        resp_detail = client.get(f"/api/v1/findings/{finding.id}")
        assert resp_detail.status_code == 401

        # Patch endpoint must also fail with 401
        resp_patch = client.patch(
            f"/api/v1/findings/{finding.id}/status",
            json={"status": "false_positive", "expected_status": "open", "reason": "Test waiver."},
        )
        assert resp_patch.status_code == 401

    def test_root_path_aliases_work(
        self,
        client: TestClient,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Root-level routes match versioned routes without prefix."""
        finding = create_test_finding(db_session, project=sample_project)

        # Root list
        r1 = client.get(f"/projects/{sample_project.id}/findings")
        assert r1.status_code == 200

        # Root detail
        r2 = client.get(f"/findings/{finding.id}")
        assert r2.status_code == 200

        # Root history
        r3 = client.get(f"/findings/{finding.id}/history")
        assert r3.status_code == 200


class TestPreserveWorkerReopeningBehavior:
    """Verify that worker system-driven reopening of fixed findings is strictly preserved."""

    def test_worker_system_reopening_preserves_audit_trail(
        self,
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """When a scan re-observes a previously 'fixed' finding, it auto-reopens with actor_type='system'."""
        fixed_snippet = "vulnerable_call(input_data)"
        finding = create_test_finding(
            db_session,
            project=sample_project,
            file_path="src/reopen_check.py",
            snippet=fixed_snippet,
            status="fixed",
        )

        # Second scan observes the exact same finding
        scan2 = Scan(
            id=uuid.uuid4(),
            project_id=sample_project.id,
            trigger="manual",
            trigger_key=f"scan-recurrence-{uuid.uuid4()}",
            status="running",
        )
        db_session.add(scan2)
        db_session.flush()

        canonical = CanonicalFinding.create_canonical(
            rule_id=finding.rule_id,
            source=FindingSource(finding.source),
            category=FindingCategory(finding.category),
            title=finding.title,
            description="Re-observed issue.",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.SCANNER_DETECTED,
            file_path="src/reopen_check.py",
            start_line=10,
            end_line=12,
            snippet=fixed_snippet,
            remediation="Remediate again.",
        )

        res = persist_scan_findings(
            db_session,
            project_id=sample_project.id,
            scan_id=scan2.id,
            findings=[canonical],
            auto_commit=True,
        )

        assert res.reopened_count == 1
        db_finding = db_session.get(Finding, finding.id)
        assert db_finding is not None
        assert db_finding.status == "open"
        assert "Reopened by system" in (db_finding.status_reason or "")

        # Verify audit record has actor_type='system'
        history = db_session.scalars(
            select(FindingStatusHistory).where(
                FindingStatusHistory.finding_id == finding.id,
                FindingStatusHistory.actor_type == "system",
            )
        ).all()
        assert len(history) == 1
        assert history[0].from_status == "fixed"
        assert history[0].to_status == "open"
        assert history[0].scan_id == scan2.id
