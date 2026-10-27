"""Unit and integration tests for finding persistence, deduplication, and lifecycle transitions.

Validates:
1. New finding creation and ScanFinding linkage (Blueprint Section 8.1 & 10.5).
2. Deduplication across multiple scans and correct last-seen updates (Section 10.6).
3. Preservation of accepted, dismissed, and false_positive statuses on recurrence (Section 7 Workflow C).
4. Automatic reopening of recurring fixed findings with append-only system audit trail (Workflow C).
5. Preservation of canonical evidence fields and secret redaction (Threat Mitigation T3).
6. Scan/project mismatch rejection and scan not found validation.
7. Transaction rollback when persistence fails (no partial finding writes).
8. In-batch duplicate fingerprint safety (preventing uq_scan_findings_scan_finding violation).
9. Worker integration: findings and job completion commit atomically.
10. Worker persistence failure: clean rollback and guarded job failure transition.
11. Concurrent identity conflict recovery via database savepoint.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import Finding, FindingStatusHistory, Job, Project, Scan, ScanFinding, User
from app.domain.findings import (
    AIAssessment,
    AITriageVerdict,
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingSource,
    FindingSourceRef,
    VerificationStatus,
)
from app.services.finding_service import (
    FindingPersistenceError,
    PersistedFindingsResult,
    ProjectMismatchError,
    ScanNotFoundError,
    list_scan_findings,
    persist_scan_findings,
)
from app.worker.runner import JobWorker
from app.worker.scanner import (
    CallableScannerEngine,
    ScanExecutionResult,
    ScanJobPayload,
    ScanStatus,
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
    """Isolated session fixture."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_user(db_session: Session) -> User:
    """Persistent test user."""
    user = User(
        github_user_id=888111,
        github_login="findings-tester",
        display_name="Findings Tester",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def sample_project(db_session: Session, sample_user: User) -> Project:
    """Persistent test project."""
    project = Project(
        owner_user_id=sample_user.id,
        kind="manual",
        name="test-repo",
    )
    db_session.add(project)
    db_session.commit()
    return project


@pytest.fixture
def sample_scan(db_session: Session, sample_project: Project, sample_user: User) -> Scan:
    """Persistent test scan in running status."""
    scan = Scan(
        project_id=sample_project.id,
        created_by_user_id=sample_user.id,
        trigger="manual",
        trigger_key=f"manual-{uuid.uuid4()}",
        status="running",
    )
    db_session.add(scan)
    db_session.commit()
    return scan


from app.services.job_service import _normalize_datetime


def make_canonical_finding(
    *,
    rule_id: str = "python.security.injection.sql",
    source: FindingSource = FindingSource.SEMGREP,
    category: FindingCategory = FindingCategory.INJECTION,
    title: str = "SQL Injection in User Query",
    description: str = "Direct string formatting used in SQL query execution.",
    severity: FindingSeverity = FindingSeverity.CRITICAL,
    confidence: FindingConfidence = FindingConfidence.HIGH,
    verification_status: VerificationStatus = VerificationStatus.SCANNER_DETECTED,
    file_path: str = "app/db/user_dao.py",
    start_line: int = 15,
    end_line: int = 17,
    snippet: str = "query = f'SELECT * FROM users WHERE id = {user_id}'\ncursor.execute(query)",
    remediation: str = "Use query parameters instead of string formatting.",
    references: list[FindingReference] | None = None,
    sources: list[FindingSourceRef] | None = None,
    ai_assessment: AIAssessment | None = None,
    raw: dict[str, Any] | None = None,
    code_anchor: str | None = None,
    secret_value: str | None = None,
    fingerprint_key: str | bytes | None = None,
    occ: int = 0,
    in_diff: bool | None = True,
) -> CanonicalFinding:
    """Helper factory for creating valid, deterministic CanonicalFinding instances."""
    eff_code_anchor = code_anchor
    if (
        (category == FindingCategory.HARDCODED_SECRET or source == FindingSource.GITLEAKS)
        and secret_value is None
        and code_anchor is None
    ):
        eff_code_anchor = "0123456789abcdef"

    return CanonicalFinding.create_canonical(
        rule_id=rule_id,
        source=source,
        category=category,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        verification_status=verification_status,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        snippet=snippet,
        remediation=remediation,
        references=references,
        ai_assessment=ai_assessment,
        raw=raw,
        code_anchor=eff_code_anchor,
        secret_value=secret_value,
        fingerprint_key=fingerprint_key,
        occ=occ,
        in_diff=in_diff,
    )


class TestFindingPersistenceService:
    """Unit tests for persist_scan_findings and finding lifecycle mechanics."""

    def test_new_finding_creation_and_scan_finding_linkage(
        self,
        db_session: Session,
        sample_project: Project,
        sample_scan: Scan,
    ) -> None:
        """New findings are persisted with 'open' status, timestamps, and ScanFinding observation linkage."""
        f1 = make_canonical_finding(
            rule_id="rule.sqli",
            severity=FindingSeverity.CRITICAL,
            file_path="app/query.py",
            start_line=10,
            end_line=12,
            snippet="cursor.execute(f'SELECT * FROM x WHERE id={id}')",
        )
        f2 = make_canonical_finding(
            rule_id="rule.xss",
            category=FindingCategory.XSS,
            severity=FindingSeverity.HIGH,
            file_path="app/views.py",
            start_line=50,
            end_line=50,
            snippet="return render_template_string(user_input)",
        )

        t0 = utc_now()
        result = persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=sample_scan.id,
            findings=[f1, f2],
            now=t0,
            auto_commit=True,
        )

        assert isinstance(result, PersistedFindingsResult)
        assert result.new_count == 2
        assert result.recurring_count == 0
        assert result.reopened_count == 0
        assert result.counts == {
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # Verify persistent findings
        persisted = db_session.scalars(
            select(Finding)
            .where(Finding.project_id == sample_project.id)
            .order_by(Finding.file_path)
        ).all()
        assert len(persisted) == 2
        for f in persisted:
            assert f.status == "open"
            assert f.status_reason is None
            assert f.first_seen_scan_id == sample_scan.id
            assert f.last_seen_scan_id == sample_scan.id
            assert f.first_seen_at == t0
            assert f.last_seen_at == t0

        # Verify scan observation linkage
        observations = list_scan_findings(db_session, sample_scan.id)
        assert len(observations) == 2
        severities = {obs.severity for obs in observations}
        assert severities == {"critical", "high"}

        # Scan.counts synchronized
        db_session.refresh(sample_scan)
        assert sample_scan.counts == {
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        # No history entry for fresh open findings
        assert db_session.query(FindingStatusHistory).count() == 0

    def test_deduplication_across_multiple_scans_and_last_seen_updates(
        self,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Recurring findings reuse the same Finding record and update last_seen metadata."""
        t0 = datetime(2026, 10, 20, 10, 0, 0, tzinfo=UTC)
        t1 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=UTC)

        scan1 = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="scan-run-1",
            status="running",
        )
        scan2 = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="scan-run-2",
            status="running",
        )
        db_session.add_all([scan1, scan2])
        db_session.commit()

        shared_finding = make_canonical_finding(
            rule_id="shared.sqli",
            file_path="src/db.py",
            start_line=20,
            end_line=22,
            snippet="cursor.execute(f'SELECT {col}')",
        )
        new_finding = make_canonical_finding(
            rule_id="new.crypto",
            category=FindingCategory.CRYPTO,
            severity=FindingSeverity.MEDIUM,
            file_path="src/crypto.py",
            start_line=5,
            end_line=5,
            snippet="cipher = DES.new(key)",
        )

        # Scan 1: Ingests shared_finding
        res1 = persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=scan1.id,
            findings=[shared_finding],
            now=t0,
            auto_commit=True,
        )
        assert res1.new_count == 1
        assert res1.recurring_count == 0

        # Scan 2: Ingests shared_finding (recurring) + new_finding (novel)
        res2 = persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=scan2.id,
            findings=[shared_finding, new_finding],
            now=t1,
            auto_commit=True,
        )
        assert res2.new_count == 1
        assert res2.recurring_count == 1

        # Deduplication invariant: exactly 2 persistent findings for the project, NOT 3
        all_findings = db_session.scalars(
            select(Finding).where(Finding.project_id == sample_project.id)
        ).all()
        assert len(all_findings) == 2

        # Verify shared finding metadata: first seen preserved, last seen updated
        db_shared = db_session.scalars(
            select(Finding).where(
                Finding.project_id == sample_project.id,
                Finding.fingerprint == shared_finding.fingerprint,
            )
        ).one()
        assert db_shared.first_seen_scan_id == scan1.id
        assert db_shared.last_seen_scan_id == scan2.id
        assert db_shared.first_seen_at == t0
        assert db_shared.last_seen_at == t1

        # Observations: scan1 has 1 observation, scan2 has 2 observations
        assert len(list_scan_findings(db_session, scan1.id)) == 1
        assert len(list_scan_findings(db_session, scan2.id)) == 2

    def test_preservation_of_accepted_dismissed_false_positive_statuses(
        self,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Triage decisions (accepted, dismissed, false_positive) persist across scans."""
        scan1 = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="scan-triage-1",
            status="running",
        )
        scan2 = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="scan-triage-2",
            status="running",
        )
        db_session.add_all([scan1, scan2])
        db_session.commit()

        statuses_to_test = [
            ("accepted", "Compensating firewall rule active"),
            ("dismissed", "Test fixture not in production"),
            ("false_positive", "Compiler macro guarantees buffer safety"),
        ]

        canonical_list: list[CanonicalFinding] = []
        for i, (st, _) in enumerate(statuses_to_test):
            f = make_canonical_finding(
                rule_id=f"rule.test.{st}",
                file_path=f"src/{st}.py",
                start_line=10 + i,
                end_line=12 + i,
                snippet=f"code_block_{st}()",
            )
            canonical_list.append(f)

        # Ingest in scan1
        t0 = utc_now()
        persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=scan1.id,
            findings=canonical_list,
            now=t0,
            auto_commit=True,
        )

        # User triages each finding in the database
        for f_canon, (st, reason) in zip(canonical_list, statuses_to_test, strict=True):
            f_db = db_session.scalars(
                select(Finding).where(Finding.fingerprint == f_canon.fingerprint)
            ).one()
            f_db.status = st
            f_db.status_reason = reason
            f_db.status_updated_at = t0
            f_db.status_updated_by = sample_user.id
            history = FindingStatusHistory(
                id=uuid.uuid4(),
                finding_id=f_db.id,
                from_status="open",
                to_status=st,
                actor_type="user",
                actor_user_id=sample_user.id,
                reason=reason,
                scan_id=scan1.id,
                created_at=t0,
            )
            db_session.add(history)
        db_session.commit()

        # Scan 2: Re-observes the exact same findings at t1
        t1 = t0 + timedelta(days=1)
        res2 = persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=scan2.id,
            findings=canonical_list,
            now=t1,
            auto_commit=True,
        )

        assert res2.recurring_count == 3
        assert res2.reopened_count == 0

        # Verify all statuses and reasons are strictly preserved
        for f_canon, (expected_st, expected_reason) in zip(
            canonical_list, statuses_to_test, strict=True
        ):
            f_db = db_session.scalars(
                select(Finding).where(Finding.fingerprint == f_canon.fingerprint)
            ).one()
            assert f_db.status == expected_st
            assert f_db.status_reason == expected_reason
            assert f_db.last_seen_scan_id == scan2.id
            assert f_db.last_seen_at == t1

        # No new history entries generated by scan 2 (still 3 user audit entries)
        assert db_session.query(FindingStatusHistory).count() == 3

        # Scan 2 observations exist
        assert len(list_scan_findings(db_session, scan2.id)) == 3

    def test_automatic_reopen_recurring_fixed_finding_with_audit_trail(
        self,
        db_session: Session,
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """When a 'fixed' finding recurs, it is automatically reopened with an append-only system audit log."""
        scan1 = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="scan-fix-1",
            status="running",
        )
        scan2 = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="scan-fix-2",
            status="running",
        )
        db_session.add_all([scan1, scan2])
        db_session.commit()

        finding_canon = make_canonical_finding(
            rule_id="regression.sqli",
            file_path="src/auth.py",
            snippet="cursor.execute(f'SELECT * FROM credentials WHERE u={u}')",
        )

        t0 = utc_now()
        persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=scan1.id,
            findings=[finding_canon],
            now=t0,
            auto_commit=True,
        )

        # Developer marks the finding as 'fixed'
        db_finding = db_session.scalars(
            select(Finding).where(Finding.fingerprint == finding_canon.fingerprint)
        ).one()
        db_finding.status = "fixed"
        db_finding.status_reason = "Fixed by parameterized query rewrite"
        db_finding.status_updated_at = t0
        db_finding.status_updated_by = sample_user.id
        user_history = FindingStatusHistory(
            id=uuid.uuid4(),
            finding_id=db_finding.id,
            from_status="open",
            to_status="fixed",
            actor_type="user",
            actor_user_id=sample_user.id,
            reason="Fixed by parameterized query rewrite",
            scan_id=scan1.id,
            created_at=t0,
        )
        db_session.add(user_history)
        db_session.commit()

        # Scan 2: Finding recurs!
        t1 = t0 + timedelta(days=2)
        res2 = persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=scan2.id,
            findings=[finding_canon],
            now=t1,
            auto_commit=True,
        )

        assert res2.reopened_count == 1
        assert res2.recurring_count == 1

        # Finding must now be 'open'
        db_session.refresh(db_finding)
        assert db_finding.status == "open"
        assert db_finding.status_reason == "Reopened by system: finding re-observed in scan"
        assert _normalize_datetime(db_finding.status_updated_at) == _normalize_datetime(t1)
        assert db_finding.status_updated_by is None  # System action

        # Audit trail must contain exactly two records: user mark fixed, then system reopen
        history_trail = db_session.scalars(
            select(FindingStatusHistory)
            .where(FindingStatusHistory.finding_id == db_finding.id)
            .order_by(FindingStatusHistory.created_at.asc())
        ).all()
        assert len(history_trail) == 2

        h1, h2 = history_trail
        assert h1.from_status == "open"
        assert h1.to_status == "fixed"
        assert h1.actor_type == "user"

        assert h2.from_status == "fixed"
        assert h2.to_status == "open"
        assert h2.actor_type == "system"
        assert h2.actor_user_id is None
        assert h2.scan_id == scan2.id
        assert h2.reason == "Reopened by system: finding re-observed in scan"
        assert _normalize_datetime(h2.created_at) == _normalize_datetime(t1)

    def test_preservation_of_canonical_evidence_fields_and_redaction(
        self,
        db_session: Session,
        sample_project: Project,
        sample_scan: Scan,
    ) -> None:
        """ScanFinding retains all evidence fields, AI assessment, references, and redacted secrets."""
        redacted_snippet = "API_KEY = '[REDACTED:gitleaks-api-key]'"
        canon = make_canonical_finding(
            rule_id="gitleaks-api-key",
            source=FindingSource.GITLEAKS,
            category=FindingCategory.HARDCODED_SECRET,
            title="Hardcoded API Secret Detected",
            description="Leaked API secret in source",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            verification_status=VerificationStatus.SCANNER_DETECTED,
            file_path="config/tokens.py",
            start_line=8,
            end_line=8,
            snippet=redacted_snippet,
            remediation="Rotate this token immediately.",
            references=[
                FindingReference(
                    type="cwe",
                    id="CWE-798",
                    url="https://cwe.mitre.org/data/definitions/798.html",
                )
            ],
            ai_assessment=AIAssessment(
                verdict=AITriageVerdict.LIKELY_TRUE_POSITIVE,
                rationale="Matches high-entropy secret format.",
                relocated=False,
            ),
            raw={"rule_id": "gitleaks-api-key", "entropy": 4.5},
            in_diff=True,
        )

        persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=sample_scan.id,
            findings=[canon],
            auto_commit=True,
        )

        observations = list_scan_findings(db_session, sample_scan.id)
        assert len(observations) == 1
        obs = observations[0]

        assert obs.severity == "high"
        assert obs.confidence == "high"
        assert obs.verification_status == "scanner_detected"
        assert obs.start_line == 8
        assert obs.end_line == 8
        assert obs.snippet == redacted_snippet
        assert obs.in_diff is True
        assert obs.references == [
            {
                "type": "cwe",
                "id": "CWE-798",
                "url": "https://cwe.mitre.org/data/definitions/798.html",
            }
        ]
        assert obs.sources == [{"source": "gitleaks", "rule_id": "gitleaks-api-key"}]
        assert obs.ai_assessment == {
            "verdict": "likely_true_positive",
            "rationale": "Matches high-entropy secret format.",
            "relocated": False,
        }
        assert obs.raw == {"rule_id": "gitleaks-api-key", "entropy": 4.5}

    def test_scan_project_mismatch_rejection(
        self,
        db_session: Session,
        sample_project: Project,
        sample_scan: Scan,
        sample_user: User,
    ) -> None:
        """persist_scan_findings rejects scans that belong to a different project or non-existent scans."""
        other_project = Project(
            owner_user_id=sample_user.id,
            kind="manual",
            name="other-repo",
        )
        db_session.add(other_project)
        db_session.commit()

        finding = make_canonical_finding()

        # Project mismatch
        with pytest.raises(ProjectMismatchError, match="belongs to project"):
            persist_scan_findings(
                session=db_session,
                project_id=other_project.id,  # Mismatched!
                scan_id=sample_scan.id,
                findings=[finding],
            )

        # Non-existent scan ID
        missing_scan_id = uuid.uuid4()
        with pytest.raises(ScanNotFoundError, match=f"Scan with ID '{missing_scan_id}' not found"):
            persist_scan_findings(
                session=db_session,
                project_id=sample_project.id,
                scan_id=missing_scan_id,
                findings=[finding],
            )

    def test_in_batch_duplicate_fingerprints_handled_safely(
        self,
        db_session: Session,
        sample_project: Project,
        sample_scan: Scan,
    ) -> None:
        """Duplicate findings in the same batch are deduplicated, avoiding uq_scan_findings_scan_finding violation."""
        f1 = make_canonical_finding(rule_id="dup.rule", file_path="dup.py")
        # Identical canonical finding repeated in the list
        f2 = make_canonical_finding(rule_id="dup.rule", file_path="dup.py")
        assert f1.fingerprint == f2.fingerprint

        result = persist_scan_findings(
            session=db_session,
            project_id=sample_project.id,
            scan_id=sample_scan.id,
            findings=[f1, f2],
            auto_commit=True,
        )

        assert result.new_count == 1
        assert len(result.scan_findings) == 1
        assert db_session.query(Finding).count() == 1
        assert db_session.query(ScanFinding).count() == 1

    def test_transaction_rollback_when_persistence_fails(
        self,
        db_session: Session,
        sample_project: Project,
        sample_scan: Scan,
    ) -> None:
        """When an unhandled error occurs and transaction is rolled back, no partial finding writes persist."""
        f1 = make_canonical_finding()

        with (
            patch.object(
                db_session, "flush", side_effect=SQLAlchemyError("Simulated DB flush crash")
            ),
            pytest.raises(FindingPersistenceError, match="Database error persisting"),
        ):
            persist_scan_findings(
                session=db_session,
                project_id=sample_project.id,
                scan_id=sample_scan.id,
                findings=[f1],
                auto_commit=True,
            )

        # Rollback verified: zero persistent findings and zero scan observations
        assert db_session.query(Finding).count() == 0
        assert db_session.query(ScanFinding).count() == 0

    def test_concurrent_identity_conflict_recovery(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
        sample_scan: Scan,
    ) -> None:
        """Simulate concurrent transaction collision: savepoint recovery fetches existing finding safely."""
        canon = make_canonical_finding(rule_id="race.rule", file_path="race.py")

        # Session 1 inserts the finding in parallel
        s1 = session_factory()
        parallel_finding = Finding(
            id=uuid.uuid4(),
            project_id=sample_project.id,
            fingerprint=canon.fingerprint,
            rule_id=canon.rule_id,
            source="semgrep",
            category="injection",
            title=canon.title,
            file_path=canon.file_path,
            status="open",
            first_seen_scan_id=sample_scan.id,
            last_seen_scan_id=sample_scan.id,
            first_seen_at=utc_now(),
            last_seen_at=utc_now(),
        )
        s1.add(parallel_finding)
        s1.commit()
        s1.close()

        # Session 2 calls persist_scan_findings which safely resolves the existing finding
        s2 = session_factory()
        persist_scan_findings(
            session=s2,
            project_id=sample_project.id,
            scan_id=sample_scan.id,
            findings=[canon],
            auto_commit=True,
        )
        s2.close()

        # Exactly 1 finding exists
        s3 = session_factory()
        assert s3.query(Finding).filter_by(fingerprint=canon.fingerprint).count() == 1
        assert s3.query(ScanFinding).filter_by(scan_id=sample_scan.id).count() == 1
        s3.close()


class TestWorkerFindingPersistenceIntegration:
    """Integration tests verifying JobWorker persistence coordination in Phase 3."""

    def test_worker_persists_findings_and_completes_job_atomically(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """JobWorker._handle_scan_result persists findings and completes the job atomically."""
        scan = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="worker-persist-scan",
            status="queued",
        )
        job = Job(
            scan=scan,
            type="scan",
            status="queued",
            attempts=0,
            payload={"files": [{"path": "main.py", "content": "x = 1"}]},
        )
        with session_factory() as session:
            session.add_all([scan, job])
            session.commit()
            scan_id = scan.id
            job_id = job.id

        finding = make_canonical_finding(
            rule_id="worker.sqli",
            severity=FindingSeverity.HIGH,
            file_path="main.py",
        )

        def mock_scanner(payload: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                components={"semgrep": "passed"},
                findings=[finding],
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-persist-success",
            scanner=CallableScannerEngine(mock_scanner),
        )

        # Run worker processing
        assert worker.run_once() is True

        with session_factory() as session:
            completed_job = session.get(Job, job_id)
            completed_scan = session.get(Scan, scan_id)

            assert completed_job is not None
            assert completed_scan is not None

            # Job and Scan completed
            assert completed_job.status == "succeeded"
            assert completed_job.payload is None  # Payload wiped
            assert completed_scan.status == "succeeded"
            assert completed_scan.components == {"semgrep": "passed"}
            assert completed_scan.counts == {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            }

            # Findings persisted
            persisted_findings = session.scalars(
                select(Finding).where(Finding.project_id == sample_project.id)
            ).all()
            assert len(persisted_findings) == 1
            assert persisted_findings[0].fingerprint == finding.fingerprint

            # ScanFinding linked
            observations = list_scan_findings(session, scan_id)
            assert len(observations) == 1
            assert observations[0].severity == "high"

    def test_worker_persistence_failure_rolls_back_and_fails_scan(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """When persistence fails in worker, partial findings roll back and the scan is marked failed."""
        scan = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="worker-persist-fail-scan",
            status="queued",
        )
        job = Job(
            scan=scan,
            type="scan",
            status="queued",
            attempts=0,
            payload={"files": [{"path": "main.py", "content": "x = 1"}]},
        )
        with session_factory() as session:
            session.add_all([scan, job])
            session.commit()
            scan_id = scan.id
            job_id = job.id

        finding = make_canonical_finding()

        def mock_scanner(payload: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                findings=[finding],
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-persist-fail",
            scanner=CallableScannerEngine(mock_scanner),
        )

        # Force persist_scan_findings to fail during execution
        with patch(
            "app.worker.runner.persist_scan_findings",
            side_effect=FindingPersistenceError("Simulated database failure during persistence"),
        ):
            assert worker.run_once() is True

        with session_factory() as session:
            failed_job = session.get(Job, job_id)
            failed_scan = session.get(Scan, scan_id)

            assert failed_job is not None
            assert failed_scan is not None

            # Scan and Job must NOT be marked clean or succeeded
            assert failed_job.status == "failed"
            assert failed_scan.status == "failed"
            assert failed_scan.error_code == "FINDING_PERSISTENCE_ERROR"
            assert "Simulated database failure" in (failed_scan.error_message or "")

            # No partial findings written to database
            assert session.query(Finding).count() == 0
            assert session.query(ScanFinding).count() == 0

    def test_worker_persists_partial_scan_findings_atomically(
        self,
        session_factory: sessionmaker[Session],
        sample_project: Project,
        sample_user: User,
    ) -> None:
        """Worker persists findings from partial scans while preserving error details."""
        scan = Scan(
            project_id=sample_project.id,
            created_by_user_id=sample_user.id,
            trigger="manual",
            trigger_key="worker-partial-findings-scan",
            status="queued",
        )
        job = Job(
            scan=scan,
            type="scan",
            status="queued",
            attempts=0,
            payload={"files": [{"path": "main.py", "content": "x = 1"}]},
        )
        with session_factory() as session:
            session.add_all([scan, job])
            session.commit()
            scan_id = scan.id

        finding = make_canonical_finding(severity=FindingSeverity.MEDIUM)

        def mock_scanner(payload: ScanJobPayload) -> ScanExecutionResult:
            return ScanExecutionResult(
                status=ScanStatus.PARTIAL,
                error_code="GITLEAKS_TIMEOUT",
                error_message="Gitleaks exceeded timeout limit",
                components={"semgrep": "passed", "gitleaks": "timeout"},
                findings=[finding],
            )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-partial-persist",
            scanner=CallableScannerEngine(mock_scanner),
        )

        assert worker.run_once() is True

        with session_factory() as session:
            partial_scan = session.get(Scan, scan_id)
            assert partial_scan is not None
            assert partial_scan.status == "partial"
            assert partial_scan.error_code == "GITLEAKS_TIMEOUT"
            assert partial_scan.components == {"semgrep": "passed", "gitleaks": "timeout"}
            assert partial_scan.counts == {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "info": 0,
            }

            # Findings from the completed scanner component are safely retained
            assert session.query(Finding).count() == 1
            assert session.query(ScanFinding).count() == 1
