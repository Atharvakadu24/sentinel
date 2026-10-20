"""Unit tests for SQLAlchemy 2.0 ORM models, relationships, and constraints (Blueprint Section 8)."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.db.models import (
    AIReview,
    Finding,
    FindingStatusHistory,
    GitHubInstallation,
    Job,
    Project,
    Scan,
    ScanFinding,
    User,
    UserSession,
    WebhookEvent,
)


@pytest.fixture
def sqlite_engine() -> Engine:
    """In-memory SQLite engine configured for foreign key enforcement."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db_session(sqlite_engine: Engine) -> Generator[Session, None, None]:
    """Isolated database session fixture for testing ORM operations."""
    factory = sessionmaker(bind=sqlite_engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()


class TestModelDefinitions:
    """Tests for metadata completeness and table declarations."""

    def test_all_eleven_core_tables_registered(self) -> None:
        """Blueprint Section 8.1 lists exactly 11 core tables."""
        expected_tables = {
            "users",
            "user_sessions",
            "github_installations",
            "projects",
            "scans",
            "jobs",
            "findings",
            "scan_findings",
            "finding_status_history",
            "webhook_events",
            "ai_reviews",
        }
        actual_tables = set(Base.metadata.tables.keys())
        assert actual_tables == expected_tables, f"Mismatch: {actual_tables ^ expected_tables}"

    def test_primary_keys_are_uuids(self) -> None:
        """Every table must have a UUID primary key named 'id'."""
        for table_name, table in Base.metadata.tables.items():
            assert "id" in table.columns, f"Table {table_name} missing 'id' column"
            id_col = table.columns["id"]
            assert id_col.primary_key, f"Column {table_name}.id must be primary key"
            assert isinstance(id_col.type, sa.Uuid), f"Column {table_name}.id must be Uuid type"


class TestModelRelationshipsAndLifecycle:
    """End-to-end integration tests using in-memory relational engine."""

    def test_complete_relational_lifecycle(self, db_session: Session) -> None:
        now = datetime.now(UTC)

        # 1. Create User
        user = User(
            github_user_id=12345678,
            github_login="octocat",
            display_name="The Octocat",
            avatar_url="https://avatars.githubusercontent.com/u/12345678",
        )
        db_session.add(user)
        db_session.commit()
        assert user.id is not None

        # 2. Create UserSession
        session_token_hash = b"\x01" * 32
        user_session = UserSession(
            user_id=user.id,
            token_hash=session_token_hash,
            expires_at=now + timedelta(days=7),
        )
        db_session.add(user_session)
        db_session.commit()
        assert len(user.sessions) == 1

        # 3. Create GitHubInstallation
        installation = GitHubInstallation(
            installation_id=98765432,
            owner_user_id=user.id,
            account_login="octocat-org",
            account_type="Organization",
            status="active",
            permissions={"pull_requests": "write", "contents": "read"},
        )
        db_session.add(installation)
        db_session.commit()

        # 4. Create Project
        project = Project(
            owner_user_id=user.id,
            kind="github",
            name="sentinel",
            installation_id=installation.id,
            github_repo_id=555555,
            full_name="octocat-org/sentinel",
            default_branch="main",
            status="active",
            settings={"scan_drafts": False, "ai_enabled": True},
        )
        db_session.add(project)
        db_session.commit()

        # 5. Create Scan and linked Job
        scan = Scan(
            project_id=project.id,
            created_by_user_id=user.id,
            trigger="pull_request",
            trigger_key="pr:42:0123456789abcdef0123456789abcdef01234567",
            pr_number=42,
            head_sha="0123456789abcdef0123456789abcdef01234567",
            status="queued",
            counts={"critical": 1, "high": 0},
        )
        db_session.add(scan)
        db_session.commit()

        job = Job(
            scan_id=scan.id,
            type="scan",
            status="queued",
            attempts=0,
            payload={"files": [{"path": "main.py"}]},
        )
        db_session.add(job)
        db_session.commit()
        assert scan.job is not None
        assert scan.job.scan_id == scan.id

        # 6. Create Finding and ScanFinding
        finding = Finding(
            project_id=project.id,
            fingerprint="a" * 64,
            rule_id="python.injection.sql",
            source="semgrep",
            category="injection",
            title="SQL Injection",
            file_path="app/query.py",
            status="open",
            first_seen_at=now,
            last_seen_at=now,
        )
        db_session.add(finding)
        db_session.commit()

        scan_finding = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="critical",
            confidence="high",
            verification_status="scanner_detected",
            start_line=10,
            end_line=12,
            snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            in_diff=True,
            description="Dynamic SQL formatting",
            remediation="Use parameterized queries",
        )
        db_session.add(scan_finding)
        db_session.commit()

        # 7. Create FindingStatusHistory
        history = FindingStatusHistory(
            finding_id=finding.id,
            from_status="open",
            to_status="accepted",
            actor_type="user",
            actor_user_id=user.id,
            reason="Compensating control in WAF",
            scan_id=scan.id,
        )
        db_session.add(history)
        db_session.commit()

        # 8. Create WebhookEvent
        webhook_event = WebhookEvent(
            delivery_id="delivery-uuid-1234",
            event_type="pull_request",
            action="opened",
            github_installation_id=installation.installation_id,
            github_repo_id=project.github_repo_id,
            pr_number=42,
            head_sha=scan.head_sha,
            outcome="accepted",
            scan_id=scan.id,
        )
        db_session.add(webhook_event)
        db_session.commit()

        # 9. Create AIReview
        ai_review = AIReview(
            scan_id=scan.id,
            owner_user_id=user.id,
            provider="anthropic",
            model="claude-3-5-haiku-20241022",
            prompt_version="v1",
            calls=1,
            input_tokens=1500,
            output_tokens=300,
            status="completed",
        )
        db_session.add(ai_review)
        db_session.commit()

        # Verify all 11 entities are queryable
        assert db_session.query(User).count() == 1
        assert db_session.query(UserSession).count() == 1
        assert db_session.query(GitHubInstallation).count() == 1
        assert db_session.query(Project).count() == 1
        assert db_session.query(Scan).count() == 1
        assert db_session.query(Job).count() == 1
        assert db_session.query(Finding).count() == 1
        assert db_session.query(ScanFinding).count() == 1
        assert db_session.query(FindingStatusHistory).count() == 1
        assert db_session.query(WebhookEvent).count() == 1
        assert db_session.query(AIReview).count() == 1

        # 10. Test Cascade Delete: deleting Project cascades to Scans, Findings, Jobs, ScanFindings, AIReview
        db_session.delete(project)
        db_session.commit()

        assert db_session.query(Project).count() == 0
        assert db_session.query(Scan).count() == 0
        assert db_session.query(Job).count() == 0
        assert db_session.query(Finding).count() == 0
        assert db_session.query(ScanFinding).count() == 0
        assert db_session.query(AIReview).count() == 0

        # User and installation still exist
        assert db_session.query(User).count() == 1
        assert db_session.query(GitHubInstallation).count() == 1
