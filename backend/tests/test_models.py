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

        # Verify relationship navigation
        assert scan.created_by_user is not None
        assert scan.created_by_user.id == user.id
        assert scan.job is not None
        assert scan.job.scan_id == scan.id
        assert scan_finding.scan.id == scan.id
        assert scan_finding.finding.id == finding.id
        assert history.finding.id == finding.id
        assert history.actor_user is not None
        assert history.actor_user.id == user.id
        assert history.scan is not None
        assert history.scan.id == scan.id

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


class TestScanFindingDeduplicationAndUniqueConstraints:
    """Tests for uniqueness invariants supporting deduplication across scans (Blueprint Section 8.1 & 10.6)."""

    def test_scan_unique_project_trigger_key(self, db_session: Session) -> None:
        user = User(github_user_id=101, github_login="dev101")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-trigger")
        db_session.add(project)
        db_session.commit()

        scan1 = Scan(project_id=project.id, trigger="manual", trigger_key="manual-batch-001")
        db_session.add(scan1)
        db_session.commit()

        # Duplicate (project_id, trigger_key) must fail
        scan2 = Scan(project_id=project.id, trigger="manual", trigger_key="manual-batch-001")
        db_session.add(scan2)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_finding_unique_project_fingerprint(self, db_session: Session) -> None:
        user = User(github_user_id=102, github_login="dev102")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-fingerprint")
        db_session.add(project)
        db_session.commit()

        fingerprint = "a" * 64
        finding1 = Finding(
            project_id=project.id,
            fingerprint=fingerprint,
            rule_id="semgrep.py.sql",
            source="semgrep",
            category="injection",
            title="SQL Injection",
            file_path="app/query.py",
        )
        db_session.add(finding1)
        db_session.commit()

        # Deduplication invariant: project cannot have two findings with the same fingerprint
        finding2 = Finding(
            project_id=project.id,
            fingerprint=fingerprint,
            rule_id="semgrep.py.sql.alt",
            source="semgrep",
            category="injection",
            title="SQL Injection Alt",
            file_path="app/query.py",
        )
        db_session.add(finding2)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_scan_finding_unique_scan_and_finding(self, db_session: Session) -> None:
        user = User(github_user_id=103, github_login="dev103")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-scan-finding")
        db_session.add(project)
        db_session.commit()

        scan = Scan(project_id=project.id, trigger="manual", trigger_key="scan-103")
        finding = Finding(
            project_id=project.id,
            fingerprint="b" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="foo.py",
        )
        db_session.add_all([scan, finding])
        db_session.commit()

        sf1 = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="high",
            confidence="high",
            verification_status="scanner_detected",
            start_line=1,
            end_line=5,
            snippet="danger()",
            description="desc",
            remediation="fix",
        )
        db_session.add(sf1)
        db_session.commit()

        # Duplicate (scan_id, finding_id) must fail
        sf2 = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="medium",
            confidence="low",
            verification_status="ai_corroborated",
            start_line=1,
            end_line=5,
            snippet="danger()",
            description="desc2",
            remediation="fix2",
        )
        db_session.add(sf2)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_job_unique_scan_id(self, db_session: Session) -> None:
        user = User(github_user_id=104, github_login="dev104")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-job")
        db_session.add(project)
        db_session.commit()

        scan = Scan(project_id=project.id, trigger="manual", trigger_key="scan-job-1")
        db_session.add(scan)
        db_session.commit()

        job1 = Job(scan_id=scan.id, status="queued")
        db_session.add(job1)
        db_session.commit()

        job2 = Job(scan_id=scan.id, status="queued")
        db_session.add(job2)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()


class TestScanFindingCheckConstraints:
    """Tests for database CHECK constraints enforcing enum domains and SHA lengths."""

    @pytest.fixture
    def setup_project(self, db_session: Session) -> Project:
        user = User(github_user_id=200, github_login="dev200")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-checks")
        db_session.add(project)
        db_session.commit()
        return project

    def test_scan_trigger_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        # Invalid trigger value
        scan = Scan(project_id=setup_project.id, trigger="scheduled", trigger_key="k1")
        db_session.add(scan)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Valid trigger values: 'manual', 'pull_request', 'rerun'
        for valid_trigger in ("manual", "pull_request", "rerun"):
            s = Scan(project_id=setup_project.id, trigger=valid_trigger, trigger_key=f"k-{valid_trigger}")
            db_session.add(s)
            db_session.commit()
            assert s.id is not None

    def test_scan_status_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        scan = Scan(project_id=setup_project.id, trigger="manual", trigger_key="k-status", status="finished")
        db_session.add(scan)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_scan_head_sha_length_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        # Invalid length 39
        scan_short = Scan(
            project_id=setup_project.id,
            trigger="manual",
            trigger_key="k-sha-39",
            head_sha="a" * 39,
        )
        db_session.add(scan_short)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Invalid length 41
        scan_long = Scan(
            project_id=setup_project.id,
            trigger="manual",
            trigger_key="k-sha-41",
            head_sha="a" * 41,
        )
        db_session.add(scan_long)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Valid: length 40 or None
        scan_valid = Scan(
            project_id=setup_project.id,
            trigger="manual",
            trigger_key="k-sha-40",
            head_sha="a" * 40,
        )
        db_session.add(scan_valid)
        db_session.commit()
        assert scan_valid.id is not None

    def test_scan_report_status_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        scan = Scan(
            project_id=setup_project.id,
            trigger="manual",
            trigger_key="k-rep",
            report_status="completed",
        )
        db_session.add(scan)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_finding_source_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        finding = Finding(
            project_id=setup_project.id,
            fingerprint="c" * 64,
            rule_id="r1",
            source="sonarqube",
            category="vuln",
            title="Issue",
            file_path="f.py",
        )
        db_session.add(finding)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

        for valid_source in ("semgrep", "gitleaks", "ai"):
            f = Finding(
                project_id=setup_project.id,
                fingerprint=f"{valid_source[:8].ljust(64, '0')}",
                rule_id="r1",
                source=valid_source,
                category="vuln",
                title=f"Issue {valid_source}",
                file_path="f.py",
            )
            db_session.add(f)
            db_session.commit()
            assert f.id is not None

    def test_finding_status_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        finding = Finding(
            project_id=setup_project.id,
            fingerprint="d" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="f.py",
            status="resolved",
        )
        db_session.add(finding)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_scan_finding_checks(self, db_session: Session, setup_project: Project) -> None:
        scan = Scan(project_id=setup_project.id, trigger="manual", trigger_key="k-sf-checks")
        finding = Finding(
            project_id=setup_project.id,
            fingerprint="1" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="f.py",
        )
        db_session.add_all([scan, finding])
        db_session.commit()

        # Invalid severity
        sf_bad_sev = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="urgent",
            confidence="high",
            verification_status="scanner_detected",
            start_line=1,
            end_line=2,
            snippet="code()",
            description="d",
            remediation="r",
        )
        db_session.add(sf_bad_sev)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Invalid confidence
        sf_bad_conf = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="high",
            confidence="very_high",
            verification_status="scanner_detected",
            start_line=1,
            end_line=2,
            snippet="code()",
            description="d",
            remediation="r",
        )
        db_session.add(sf_bad_conf)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Invalid verification status
        sf_bad_ver = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="high",
            confidence="high",
            verification_status="ai_approved",
            start_line=1,
            end_line=2,
            snippet="code()",
            description="d",
            remediation="r",
        )
        db_session.add(sf_bad_ver)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_job_status_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        scan = Scan(project_id=setup_project.id, trigger="manual", trigger_key="k-job-status")
        db_session.add(scan)
        db_session.commit()

        job = Job(scan_id=scan.id, status="finished")
        db_session.add(job)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_finding_status_history_actor_type_check(self, db_session: Session, setup_project: Project) -> None:
        finding = Finding(
            project_id=setup_project.id,
            fingerprint="2" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="f.py",
        )
        db_session.add(finding)
        db_session.commit()

        history = FindingStatusHistory(
            finding_id=finding.id,
            from_status="open",
            to_status="accepted",
            actor_type="admin",
        )
        db_session.add(history)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_project_kind_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        p_bad = Project(owner_user_id=setup_project.owner_user_id, kind="bitbucket", name="repo-bad-kind")
        db_session.add(p_bad)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_project_status_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        p_bad = Project(
            owner_user_id=setup_project.owner_user_id,
            kind="manual",
            name="repo-bad-status",
            status="paused",
        )
        db_session.add(p_bad)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()

    def test_project_github_fields_check_constraint(self, db_session: Session, setup_project: Project) -> None:
        # kind='github' requires both installation_id and github_repo_id
        p_github_missing = Project(
            owner_user_id=setup_project.owner_user_id,
            kind="github",
            name="repo-gh-missing",
            installation_id=None,
            github_repo_id=None,
        )
        db_session.add(p_github_missing)
        with pytest.raises(sa.exc.IntegrityError):
            db_session.commit()
        db_session.rollback()



class TestFindingStatusHistoryImmutability:
    """Enforce Blueprint Section 8.1 invariant: finding_status_history is an append-only audit trail."""

    @pytest.fixture
    def setup_finding_with_history(self, db_session: Session) -> tuple[Finding, FindingStatusHistory]:
        user = User(github_user_id=300, github_login="dev300")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-immutability")
        db_session.add(project)
        db_session.commit()

        finding = Finding(
            project_id=project.id,
            fingerprint="3" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="f.py",
        )
        db_session.add(finding)
        db_session.commit()

        history = FindingStatusHistory(
            finding_id=finding.id,
            from_status="open",
            to_status="accepted",
            actor_type="user",
            actor_user_id=user.id,
            reason="Accepted risk",
        )
        db_session.add(history)
        db_session.commit()
        return finding, history

    def test_status_history_update_prohibited(
        self, db_session: Session, setup_finding_with_history: tuple[Finding, FindingStatusHistory]
    ) -> None:
        _, history = setup_finding_with_history
        history.reason = "Modified reason"
        with pytest.raises(sa.exc.InvalidRequestError, match="append-only audit log and cannot be updated"):
            db_session.commit()
        db_session.rollback()

    def test_status_history_direct_delete_prohibited(
        self, db_session: Session, setup_finding_with_history: tuple[Finding, FindingStatusHistory]
    ) -> None:
        _, history = setup_finding_with_history
        db_session.delete(history)
        with pytest.raises(sa.exc.InvalidRequestError, match="append-only audit log and cannot be deleted directly"):
            db_session.commit()
        db_session.rollback()

    def test_status_history_append_lifecycle(
        self, db_session: Session, setup_finding_with_history: tuple[Finding, FindingStatusHistory]
    ) -> None:
        finding, _ = setup_finding_with_history

        # Append transition: accepted -> open
        h2 = FindingStatusHistory(
            finding_id=finding.id,
            from_status="accepted",
            to_status="open",
            actor_type="system",
            reason="Regression detected in new scan",
        )
        db_session.add(h2)
        db_session.commit()

        # Append transition: open -> fixed
        h3 = FindingStatusHistory(
            finding_id=finding.id,
            from_status="open",
            to_status="fixed",
            actor_type="system",
            reason="Code fix merged",
        )
        db_session.add(h3)
        db_session.commit()

        # Query history trail
        trail = db_session.query(FindingStatusHistory).filter_by(finding_id=finding.id).all()
        assert len(trail) == 3
        assert [h.to_status for h in trail] == ["accepted", "open", "fixed"]

    def test_status_history_bulk_update_prohibited(
        self, db_session: Session, setup_finding_with_history: tuple[Finding, FindingStatusHistory]
    ) -> None:
        _, history = setup_finding_with_history
        with pytest.raises(sa.exc.InvalidRequestError, match="cannot be updated via bulk DML"):
            db_session.execute(
                sa.update(FindingStatusHistory)
                .where(FindingStatusHistory.id == history.id)
                .values(reason="bypassed")
            )

    def test_status_history_bulk_delete_prohibited(
        self, db_session: Session, setup_finding_with_history: tuple[Finding, FindingStatusHistory]
    ) -> None:
        _, history = setup_finding_with_history
        with pytest.raises(sa.exc.InvalidRequestError, match="cannot be deleted via bulk DML"):
            db_session.execute(
                sa.delete(FindingStatusHistory).where(FindingStatusHistory.id == history.id)
            )

    def test_status_history_query_update_prohibited(
        self, db_session: Session, setup_finding_with_history: tuple[Finding, FindingStatusHistory]
    ) -> None:
        _, history = setup_finding_with_history
        with pytest.raises(sa.exc.InvalidRequestError, match="cannot be updated via bulk DML"):
            db_session.query(FindingStatusHistory).filter_by(id=history.id).update(
                {"reason": "bypassed"}
            )

    def test_status_history_query_delete_prohibited(
        self, db_session: Session, setup_finding_with_history: tuple[Finding, FindingStatusHistory]
    ) -> None:
        _, history = setup_finding_with_history
        with pytest.raises(sa.exc.InvalidRequestError, match="cannot be deleted via bulk DML"):
            db_session.query(FindingStatusHistory).filter_by(id=history.id).delete()


class TestScanFindingCascadeAndIsolation:
    """Verify cascade boundaries between Scans, Jobs, persistent Findings, and occurrences."""

    def test_delete_scan_preserves_persistent_findings(self, db_session: Session) -> None:
        user = User(github_user_id=400, github_login="dev400")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-cascade-scan")
        db_session.add(project)
        db_session.commit()

        scan = Scan(project_id=project.id, trigger="manual", trigger_key="scan-cascade")
        finding = Finding(
            project_id=project.id,
            fingerprint="4" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="f.py",
        )
        db_session.add_all([scan, finding])
        db_session.commit()

        job = Job(scan_id=scan.id, status="queued")
        sf = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="high",
            confidence="high",
            verification_status="scanner_detected",
            start_line=1,
            end_line=2,
            snippet="x",
            description="d",
            remediation="r",
        )
        history = FindingStatusHistory(
            finding_id=finding.id,
            from_status="open",
            to_status="accepted",
            actor_type="user",
            actor_user_id=user.id,
            scan_id=scan.id,
        )
        db_session.add_all([job, sf, history])
        db_session.commit()

        # Deleting Scan cascades to Job and ScanFinding
        db_session.delete(scan)
        db_session.commit()

        assert db_session.query(Scan).count() == 0
        assert db_session.query(Job).count() == 0
        assert db_session.query(ScanFinding).count() == 0

        # Persistent Finding and its status history survive scan deletion
        assert db_session.query(Finding).count() == 1
        assert db_session.query(FindingStatusHistory).count() == 1

    def test_delete_finding_preserves_scans(self, db_session: Session) -> None:
        user = User(github_user_id=401, github_login="dev401")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-cascade-finding")
        db_session.add(project)
        db_session.commit()

        scan = Scan(project_id=project.id, trigger="manual", trigger_key="scan-persists")
        finding = Finding(
            project_id=project.id,
            fingerprint="5" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="f.py",
        )
        db_session.add_all([scan, finding])
        db_session.commit()

        sf = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="low",
            confidence="medium",
            verification_status="scanner_detected",
            start_line=10,
            end_line=12,
            snippet="y",
            description="d",
            remediation="r",
        )
        history = FindingStatusHistory(
            finding_id=finding.id,
            from_status="open",
            to_status="dismissed",
            actor_type="user",
            actor_user_id=user.id,
        )
        db_session.add_all([sf, history])
        db_session.commit()

        # Deleting Finding cascades to ScanFinding and FindingStatusHistory via DB cascade
        db_session.delete(finding)
        db_session.commit()

        assert db_session.query(Finding).count() == 0
        assert db_session.query(ScanFinding).count() == 0
        assert db_session.query(FindingStatusHistory).count() == 0

        # Scan survives
        assert db_session.query(Scan).count() == 1

    def test_delete_project_cascades_all_scans_findings_and_history(
        self, db_session: Session
    ) -> None:
        user = User(github_user_id=402, github_login="dev402")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-full-cascade")
        db_session.add(project)
        db_session.commit()

        scan = Scan(project_id=project.id, trigger="manual", trigger_key="scan-all")
        finding = Finding(
            project_id=project.id,
            fingerprint="6" * 64,
            rule_id="r1",
            source="semgrep",
            category="vuln",
            title="Issue",
            file_path="f.py",
        )
        db_session.add_all([scan, finding])
        db_session.commit()

        job = Job(scan_id=scan.id, status="queued")
        sf = ScanFinding(
            scan_id=scan.id,
            finding_id=finding.id,
            severity="medium",
            confidence="high",
            verification_status="scanner_detected",
            start_line=1,
            end_line=2,
            snippet="z",
            description="d",
            remediation="r",
        )
        history = FindingStatusHistory(
            finding_id=finding.id,
            from_status="open",
            to_status="fixed",
            actor_type="system",
            scan_id=scan.id,
        )
        db_session.add_all([job, sf, history])
        db_session.commit()

        # Deleting project must purge everything under it via foreign key cascade
        db_session.delete(project)
        db_session.commit()

        assert db_session.query(Project).count() == 0
        assert db_session.query(Scan).count() == 0
        assert db_session.query(Job).count() == 0
        assert db_session.query(Finding).count() == 0
        assert db_session.query(ScanFinding).count() == 0
        assert db_session.query(FindingStatusHistory).count() == 0
        # User remains intact
        assert db_session.query(User).count() == 1

    def test_rerun_scan_relationship_navigation(self, db_session: Session) -> None:
        user = User(github_user_id=403, github_login="dev403")
        db_session.add(user)
        db_session.commit()

        project = Project(owner_user_id=user.id, kind="manual", name="repo-rerun")
        db_session.add(project)
        db_session.commit()

        original_scan = Scan(project_id=project.id, trigger="manual", trigger_key="orig-scan")
        db_session.add(original_scan)
        db_session.commit()

        rerun_scan = Scan(
            project_id=project.id,
            trigger="rerun",
            trigger_key="rerun-scan",
            rerun_of=original_scan.id,
        )
        db_session.add(rerun_scan)
        db_session.commit()

        # Verify self-referential relationship navigation
        assert rerun_scan.rerun_scan is not None
        assert rerun_scan.rerun_scan.id == original_scan.id
