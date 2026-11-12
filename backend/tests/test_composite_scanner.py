"""Unit and integration tests for the unified CompositeScannerEngine.

Validates:
1. Shared single-pass StagedWorkspace execution across Semgrep and Gitleaks.
2. Canonical finding normalization, deterministic ordering, and deduplication.
3. Preservation of distinct findings (e.g. Semgrep + Gitleaks) at identical file/line.
4. Component status tracking (`passed`, `partial`, `failed`, `canceled`, `skipped`).
5. Partial failure isolation vs total failure retryable propagation.
6. Cancellation, worker shutdown separation, and DB-canceled scan protection.
7. End-to-end JobWorker + persist_scan_findings idempotency and secret redaction.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from collections.abc import Generator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base, utc_now
from app.db.models import Finding, Job, Project, Scan, ScanFinding, User
from app.domain.findings import (
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
)
from app.domain.fingerprint import compute_code_anchor, compute_finding_fingerprint
from app.services.job_service import claim_next_job
from app.worker.composite import DEFAULT_SCANNER_ORDER, CompositeScannerEngine
from app.worker.gitleaks import GitleaksScannerAdapter
from app.worker.runner import JobHeartbeat, JobWorker
from app.worker.scanner import (
    DefaultScannerEngine,
    ScanExecutionResult,
    ScanJobPayload,
    ScannedFile,
    ScanStatus,
)
from app.worker.semgrep import SemgrepScannerAdapter
from app.worker.subprocess_runner import CommandResult, CommandStatus

TEST_FINGERPRINT_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def temp_workspace_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Isolated staging parent directory for composite scanner tests."""
    workspace_dir = tmp_path / "composite_staging"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    yield workspace_dir


@pytest.fixture
def temp_rules_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Local Semgrep rules directory (no network rule fetches)."""
    rules_dir = tmp_path / "rules" / "semgrep"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "default.yaml").write_text(
        "rules:\n  - id: test\n    pattern: eval(...)\n",
        encoding="utf-8",
    )
    yield rules_dir


@pytest.fixture
def db_engine() -> Engine:
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
def session_factory(db_engine: Engine) -> sessionmaker[Session]:
    """SQLAlchemy session factory bound to isolated test database."""
    return sessionmaker(bind=db_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def db_session(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Database session fixture."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_project(db_session: Session) -> Project:
    """Create a persistent test user and project."""
    user = User(
        github_user_id=424242,
        github_login="composite-tester",
        display_name="Composite Tester",
    )
    db_session.add(user)
    db_session.flush()

    project = Project(
        owner_user_id=user.id,
        kind="manual",
        name="Composite Engine Repo",
        status="active",
    )
    db_session.add(project)
    db_session.commit()
    return project


def _make_command_result(
    *,
    status: CommandStatus = CommandStatus.SUCCESS,
    exit_code: int | None = 0,
    stdout: bytes | str = b"",
    stderr: bytes | str = b"",
    command: tuple[str, ...] = ("scanner", "run"),
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
    executable_not_found: bool = False,
) -> CommandResult:
    stdout_bytes = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    stderr_bytes = stderr.encode("utf-8") if isinstance(stderr, str) else stderr
    return CommandResult(
        command=command,
        status=status,
        exit_code=exit_code,
        stdout=stdout_bytes,
        stderr=stderr_bytes,
        duration_ms=25.0,
        output_limit_exceeded=output_limit_exceeded,
        timed_out=timed_out,
        executable_not_found=executable_not_found,
    )


def _create_scan_and_job(
    session: Session,
    project: Project,
    *,
    files: list[dict[str, Any]],
    scan_status: str = "queued",
    job_status: str = "queued",
    max_attempts: int = 3,
    run_after: datetime | None = None,
) -> tuple[Scan, Job]:
    scan = Scan(
        project_id=project.id,
        trigger="manual",
        trigger_key=f"composite-{uuid.uuid4()}",
        status=scan_status,
        report_status="not_applicable",
    )
    session.add(scan)
    session.flush()

    job = Job(
        scan_id=scan.id,
        type="scan",
        status=job_status,
        attempts=0,
        max_attempts=max_attempts,
        run_after=run_after or utc_now(),
        payload={"files": files, "run_ai": False},
    )
    session.add(job)
    session.commit()
    return scan, job


def _build_semgrep_finding(
    *,
    rule_id: str,
    file_path: str,
    start_line: int,
    snippet: str,
    severity: FindingSeverity = FindingSeverity.HIGH,
) -> CanonicalFinding:
    anchor = compute_code_anchor(snippet)
    fp = compute_finding_fingerprint(
        rule_id=rule_id,
        source=FindingSource.SEMGREP.value,
        file_path=file_path,
        anchor=anchor,
        occ=0,
    )
    return CanonicalFinding(
        rule_id=rule_id,
        source=FindingSource.SEMGREP,
        category=FindingCategory.INJECTION,
        title=f"Semgrep issue {rule_id}",
        description="Static analysis finding",
        severity=severity,
        confidence=FindingConfidence.HIGH,
        verification_status=VerificationStatus.SCANNER_DETECTED,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        snippet=snippet,
        snippet_start_line=start_line,
        remediation="Avoid unsafe sink calls with untrusted input.",
        fingerprint=fp,
    )


class TestCompositeScannerRegistryAndStaging:
    """Registry configuration and shared-staging behavior of CompositeScannerEngine."""

    def test_default_registration_and_shared_workspace_execution(
        self,
        temp_workspace_dir: Path,
        temp_rules_dir: Path,
    ) -> None:
        """Both Semgrep and Gitleaks execute once inside one shared StagedWorkspace."""
        aws_parts = ("AKIA", "IOSFODNN7", "COMP1234")
        raw_secret = "".join(aws_parts)
        semgrep_cwds: list[Path] = []
        gitleaks_sources: list[Path] = []
        staged_filenames_seen: list[set[str]] = []

        def semgrep_runner(**kwargs: Any) -> CommandResult:
            cmd = list(kwargs["args"])
            target_dir = Path(cmd[-1])
            semgrep_cwds.append(target_dir)
            staged_filenames_seen.append({p.name for p in target_dir.rglob("*") if p.is_file()})
            assert target_dir.is_dir()
            output = {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.eval-detected",
                        "path": "src/app.py",
                        "start": {"line": 2, "col": 1},
                        "end": {"line": 2, "col": 16},
                        "extra": {
                            "message": "Detected use of eval()",
                            "severity": "ERROR",
                            "metadata": {"category": "security", "confidence": "HIGH"},
                            "lines": "result = eval(user_input)",
                        },
                    }
                ],
                "errors": [],
            }
            return _make_command_result(
                exit_code=1,
                stdout=json.dumps(output),
                command=("semgrep",),
            )

        def gitleaks_runner(**kwargs: Any) -> CommandResult:
            cmd = list(kwargs["args"])
            source_dir = Path(cmd[cmd.index("--source") + 1])
            gitleaks_sources.append(source_dir)
            staged_filenames_seen.append({p.name for p in source_dir.rglob("*") if p.is_file()})
            findings = [
                {
                    "Description": "AWS Access Key",
                    "StartLine": 1,
                    "EndLine": 1,
                    "StartColumn": 11,
                    "EndColumn": 31,
                    "Match": f"AWS_KEY = '{raw_secret}'",
                    "Secret": raw_secret,
                    "File": "src/secrets.py",
                    "RuleID": "aws-access-token",
                    "Entropy": 3.8,
                    "Tags": ["key"],
                }
            ]
            return _make_command_result(
                exit_code=1,
                stdout=json.dumps(findings),
                command=("gitleaks",),
            )

        semgrep = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=str(temp_rules_dir),
            runner=semgrep_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        gitleaks = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=gitleaks_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        engine = CompositeScannerEngine(
            semgrep=semgrep,
            gitleaks=gitleaks,
            workspace_base_dir=temp_workspace_dir,
        )
        assert engine.registered_scanners == DEFAULT_SCANNER_ORDER

        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="src/app.py",
                    content="import os\nresult = eval(user_input)\n",
                    scanned=True,
                ),
                ScannedFile(
                    path="src/secrets.py",
                    content=f"AWS_KEY = '{raw_secret}'\n",
                    scanned=True,
                ),
                ScannedFile(
                    path=".gitleaks.toml",
                    content="[extend]\nuseDefault = true\n",
                    scanned=True,
                ),
                ScannedFile(
                    path=".gitleaksignore",
                    content="aws-access-token:src/secrets.py:1\n",
                    scanned=True,
                ),
            ]
        )

        result = engine.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert result.components == {"semgrep": "passed", "gitleaks": "passed"}
        assert result.counts is not None
        assert result.counts["findings"] == 2
        assert result.counts["high"] == 2
        assert len(result.findings) == 2

        # Exactly one shared StagedWorkspace source directory was created and reused
        assert len(semgrep_cwds) == 1
        assert len(gitleaks_sources) == 1
        assert semgrep_cwds[0] == gitleaks_sources[0]
        assert not semgrep_cwds[0].exists()  # cleaned up on exit
        assert not any(temp_workspace_dir.iterdir())

        # Untrusted repository Gitleaks control files must be excluded from shared staging
        assert ".gitleaks.toml" not in staged_filenames_seen[0]
        assert ".gitleaksignore" not in staged_filenames_seen[0]
        assert {"app.py", "secrets.py"} <= staged_filenames_seen[0]

        sources = [f.source for f in result.findings]
        assert sources == [FindingSource.SEMGREP, FindingSource.GITLEAKS]

        # Ensure raw secret is redacted everywhere
        serialized = json.dumps([f.model_dump(mode="json") for f in result.findings])
        assert raw_secret not in serialized

    def test_custom_scanner_registration_and_duplicate_guard(self) -> None:
        """Registry validates names, rejects duplicates unless replace=True."""
        dummy_semgrep = SemgrepScannerAdapter(
            runner=lambda **_: _make_command_result(exit_code=0, stdout='{"results": []}')
        )
        engine = CompositeScannerEngine(scanners=[("semgrep", dummy_semgrep)])
        assert engine.registered_scanners == ("semgrep",)
        assert engine.get_scanner("SEMGREP") is dummy_semgrep

        with pytest.raises(ValueError, match="already registered"):
            engine.register("semgrep", dummy_semgrep)

        with pytest.raises(ValueError, match="non-empty"):
            engine.register("   ", dummy_semgrep)

        replacement = SemgrepScannerAdapter(
            runner=lambda **_: _make_command_result(exit_code=0, stdout='{"results": []}')
        )
        engine.register("Semgrep", replacement, replace=True)
        assert engine.get_scanner("semgrep") is replacement


class TestCompositeScannerOutcomesAndDeduplication:
    """Behavior of partial failures, full failures, zero findings, and dedup."""

    def test_semgrep_only_and_gitleaks_only_findings(
        self,
        temp_workspace_dir: Path,
        temp_rules_dir: Path,
    ) -> None:
        """Composite engine succeeds cleanly when only one scanner detects issues."""
        gl_parts = ("glpat-", "CompositeOnly1234567890")
        raw_secret = "".join(gl_parts)

        semgrep = SemgrepScannerAdapter(
            rules_path=str(temp_rules_dir),
            runner=lambda **_: _make_command_result(
                exit_code=0,
                stdout=json.dumps({"results": [], "errors": []}),
            ),
            workspace_base_dir=temp_workspace_dir,
        )
        gitleaks = GitleaksScannerAdapter(
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=lambda **_: _make_command_result(
                exit_code=1,
                stdout=json.dumps(
                    [
                        {
                            "Description": "GitLab Personal Access Token",
                            "StartLine": 1,
                            "EndLine": 1,
                            "Match": f"TOKEN = '{raw_secret}'",
                            "Secret": raw_secret,
                            "File": "config.py",
                            "RuleID": "gitlab-pat",
                        }
                    ]
                ),
            ),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="config.py", content=f"TOKEN = '{raw_secret}'\n")]
        )
        res = CompositeScannerEngine(semgrep=semgrep, gitleaks=gitleaks).scan(payload)

        assert res.status == ScanStatus.SUCCEEDED
        assert res.components == {"semgrep": "passed", "gitleaks": "passed"}
        assert res.counts is not None
        assert res.counts["findings"] == 1
        assert len(res.findings) == 1
        assert res.findings[0].source == FindingSource.GITLEAKS
        assert raw_secret not in res.findings[0].snippet

    def test_partial_failure_retains_findings_from_succeeding_scanner(
        self,
        temp_workspace_dir: Path,
        temp_rules_dir: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """If Semgrep times out or Gitleaks crashes, surviving findings remain valid."""
        slack_parts = ("xoxb-", "1234567890-", "composite-secret")
        raw_secret = "".join(slack_parts)
        caplog.set_level(logging.WARNING)

        # Case A: Semgrep times out, Gitleaks succeeds
        semgrep_timeout = SemgrepScannerAdapter(
            rules_path=str(temp_rules_dir),
            runner=lambda **_: _make_command_result(
                status=CommandStatus.TIMEOUT,
                exit_code=None,
                timed_out=True,
                stderr=f"leaked diagnostic {raw_secret}",
            ),
            workspace_base_dir=temp_workspace_dir,
        )
        gitleaks_ok = GitleaksScannerAdapter(
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=lambda **_: _make_command_result(
                exit_code=1,
                stdout=json.dumps(
                    [
                        {
                            "Description": "Slack Token",
                            "StartLine": 1,
                            "EndLine": 1,
                            "Match": f"SLACK = '{raw_secret}'",
                            "Secret": raw_secret,
                            "File": "bot.py",
                            "RuleID": "slack-bot-token",
                        }
                    ]
                ),
            ),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="bot.py", content=f"SLACK = '{raw_secret}'\n")]
        )
        res = CompositeScannerEngine(semgrep=semgrep_timeout, gitleaks=gitleaks_ok).scan(payload)

        assert res.status == ScanStatus.PARTIAL
        assert res.retryable is False
        assert res.components == {"semgrep": "failed", "gitleaks": "passed"}
        assert res.error_code == "SEMGREP_TIMEOUT"
        assert res.counts is not None
        assert res.counts["findings"] == 1
        assert len(res.findings) == 1
        assert res.findings[0].source == FindingSource.GITLEAKS
        assert raw_secret not in (res.error_message or "")
        assert raw_secret not in caplog.text

        # Case B: Semgrep succeeds, Gitleaks raises unexpected exception containing secret
        semgrep_finding = _build_semgrep_finding(
            rule_id="py.eval",
            file_path="bot.py",
            start_line=2,
            snippet="eval(x)",
        )

        class _SemgrepStub:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    components={"semgrep": "passed"},
                    counts={"findings": 1, "high": 1},
                    findings=[semgrep_finding],
                )

        class _CrashingGitleaks:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                raise RuntimeError(f"boom with token={raw_secret}")

        res_crash = CompositeScannerEngine(
            semgrep=_SemgrepStub(),
            gitleaks=_CrashingGitleaks(),
        ).scan(ScanJobPayload(files=[ScannedFile(path="bot.py", content="eval(x)\n")]))

        assert res_crash.status == ScanStatus.PARTIAL
        assert res_crash.components == {"semgrep": "passed", "gitleaks": "failed"}
        assert res_crash.error_code == "GITLEAKS_UNHANDLED_ERROR"
        assert len(res_crash.findings) == 1
        assert res_crash.findings[0].rule_id == "py.eval"
        assert raw_secret not in (res_crash.error_message or "")
        assert raw_secret not in caplog.text

    def test_all_scanners_failed_propagates_retryable_only_when_all_retryable(
        self,
        temp_workspace_dir: Path,
        temp_rules_dir: Path,
    ) -> None:
        """All failing retryably -> retryable FAILED; mixed/adapter timeouts reflect sub-scanner retryability."""
        semgrep_to = SemgrepScannerAdapter(
            rules_path=str(temp_rules_dir),
            runner=lambda **_: _make_command_result(
                status=CommandStatus.TIMEOUT,
                exit_code=None,
                timed_out=True,
            ),
            workspace_base_dir=temp_workspace_dir,
        )
        gitleaks_to = GitleaksScannerAdapter(
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=lambda **_: _make_command_result(
                status=CommandStatus.TIMEOUT,
                exit_code=None,
                timed_out=True,
            ),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="a.py", content="x = 1\n")])

        adapter_timeouts = CompositeScannerEngine(semgrep=semgrep_to, gitleaks=gitleaks_to).scan(
            payload
        )
        assert adapter_timeouts.status == ScanStatus.FAILED
        assert adapter_timeouts.retryable is False
        assert adapter_timeouts.error_code == "SCANNER_TIMEOUT"
        assert adapter_timeouts.components == {"semgrep": "failed", "gitleaks": "failed"}
        assert adapter_timeouts.findings == []

        class _RetryableStub:
            def __init__(self, delay: int) -> None:
                self._delay = delay

            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="TRANSIENT_FAILURE",
                    error_message="Temporary outage",
                    retryable=True,
                    retry_delay_sec=self._delay,
                )

        class _FatalStub:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="INVALID_CONFIG",
                    error_message="Broken config",
                    retryable=False,
                )

        all_retryable = CompositeScannerEngine(
            scanners=[("semgrep", _RetryableStub(10)), ("gitleaks", _RetryableStub(25))]
        ).scan(payload)
        assert all_retryable.status == ScanStatus.FAILED
        assert all_retryable.retryable is True
        assert all_retryable.retry_delay_sec == 25
        assert all_retryable.error_code == "TRANSIENT_FAILURE"
        assert all_retryable.findings == []

        mixed_failure = CompositeScannerEngine(
            scanners=[("semgrep", _RetryableStub(10)), ("gitleaks", _FatalStub())]
        ).scan(payload)
        assert mixed_failure.status == ScanStatus.FAILED
        assert mixed_failure.retryable is False
        assert mixed_failure.retry_delay_sec is None
        assert mixed_failure.error_code == "ALL_SCANNERS_FAILED"
        assert mixed_failure.findings == []

    def test_empty_and_zero_scannable_payloads(
        self,
        temp_workspace_dir: Path,
        temp_rules_dir: Path,
    ) -> None:
        """Zero findings, zero scannable files, and excluded-only files all succeed cleanly."""
        calls: list[str] = []

        def semgrep_runner(**kwargs: Any) -> CommandResult:
            calls.append("semgrep")
            return _make_command_result(exit_code=0, stdout='{"results": []}')

        def gitleaks_runner(**kwargs: Any) -> CommandResult:
            calls.append("gitleaks")
            return _make_command_result(exit_code=0, stdout="[]")

        engine = CompositeScannerEngine(
            semgrep=SemgrepScannerAdapter(
                rules_path=str(temp_rules_dir),
                runner=semgrep_runner,
                workspace_base_dir=temp_workspace_dir,
            ),
            gitleaks=GitleaksScannerAdapter(
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=gitleaks_runner,
                workspace_base_dir=temp_workspace_dir,
            ),
            workspace_base_dir=temp_workspace_dir,
        )

        # Unscanned-only files fast-path without invoking subprocesses
        no_scannable = ScanJobPayload(
            files=[ScannedFile(path="big.bin", content="", scanned=False, skip_reason="size")]
        )
        res_skip = engine.scan(no_scannable)
        assert res_skip.status == ScanStatus.SUCCEEDED
        assert res_skip.counts == {
            "findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        assert calls == []

        # Only untrusted .gitleaks.toml marked scanned=True (excluded from shared staging)
        only_control = ScanJobPayload(
            files=[ScannedFile(path=".gitleaks.toml", content="[extend]\n", scanned=True)]
        )
        res_ctrl = engine.scan(only_control)
        assert res_ctrl.status == ScanStatus.SUCCEEDED
        assert res_ctrl.findings == []
        assert calls == []

    def test_same_line_distinct_findings_preserved_while_exact_duplicates_merged(
        self,
        temp_workspace_dir: Path,
        temp_rules_dir: Path,
    ) -> None:
        """Same-line findings with distinct fingerprints stay separate; identical fingerprints dedup."""
        aws_parts = ("AKIA", "SAMELINE1234", "5678")
        raw_secret = "".join(aws_parts)
        shared_line = f"api_key = '{raw_secret}'; exec(api_key)"

        semgrep = SemgrepScannerAdapter(
            rules_path=str(temp_rules_dir),
            runner=lambda **_: _make_command_result(
                exit_code=1,
                stdout=json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.exec-detected",
                                "path": "src/main.py",
                                "start": {"line": 1, "col": 1},
                                "end": {"line": 1, "col": 30},
                                "extra": {
                                    "message": "Dangerous exec()",
                                    "severity": "ERROR",
                                    "metadata": {"confidence": "HIGH"},
                                    "lines": "exec(api_key)",
                                },
                            },
                            # Exact duplicate emission on same rule/line/snippet
                            {
                                "check_id": "python.exec-detected",
                                "path": "src/main.py",
                                "start": {"line": 1, "col": 1},
                                "end": {"line": 1, "col": 30},
                                "extra": {
                                    "message": "Dangerous exec()",
                                    "severity": "ERROR",
                                    "metadata": {"confidence": "HIGH"},
                                    "lines": "exec(api_key)",
                                },
                            },
                        ]
                    }
                ),
            ),
            workspace_base_dir=temp_workspace_dir,
        )
        gitleaks = GitleaksScannerAdapter(
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=lambda **_: _make_command_result(
                exit_code=1,
                stdout=json.dumps(
                    [
                        {
                            "Description": "AWS Key",
                            "StartLine": 1,
                            "EndLine": 1,
                            "Match": f"api_key = '{raw_secret}'",
                            "Secret": raw_secret,
                            "File": "src/main.py",
                            "RuleID": "aws-access-token",
                        }
                    ]
                ),
            ),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="src/main.py", content=shared_line)])
        res = CompositeScannerEngine(semgrep=semgrep, gitleaks=gitleaks).scan(payload)

        assert res.status == ScanStatus.SUCCEEDED
        # Same file_path + start_line (src/main.py:1) must keep BOTH Semgrep + Gitleaks findings!
        # Wait: Semgrep emitted two identical findings on the same line which Semgrep normalizer
        # differentiates by occurrence index or identical fingerprint if same occurrence; verify at
        # minimum both sources (semgrep and gitleaks) remain distinct on line 1.
        sources = {f.source for f in res.findings}
        assert sources == {FindingSource.SEMGREP, FindingSource.GITLEAKS}
        assert all(f.start_line == 1 for f in res.findings)
        assert len({f.fingerprint for f in res.findings}) == len(res.findings)

        # Direct fingerprint collision dedup merges contributing sources safely
        duplicate_finding = _build_semgrep_finding(
            rule_id="custom.dup",
            file_path="a.py",
            start_line=10,
            snippet="bad_call()",
        )

        class _StaticScanner:
            def __init__(self, findings: list[CanonicalFinding]) -> None:
                self._findings = findings

            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    findings=list(self._findings),
                )

        dedup_res = CompositeScannerEngine(
            scanners=[
                ("first", _StaticScanner([duplicate_finding])),
                (
                    "second",
                    _StaticScanner(
                        [
                            duplicate_finding.model_copy(
                                update={"source": FindingSource.AI},
                            )
                        ]
                    ),
                ),
            ]
        ).scan(ScanJobPayload(files=[ScannedFile(path="a.py", content="bad_call()\n")]))

        assert dedup_res.status == ScanStatus.SUCCEEDED
        assert len(dedup_res.findings) == 1
        assert {ref.source for ref in dedup_res.findings[0].sources} == {
            FindingSource.SEMGREP,
            FindingSource.AI,
        }


class TestCompositeWorkerLifecycleAndCancellation:
    """Integration with JobWorker, transactional persistence, retries, and cancellation."""

    def test_worker_end_to_end_persistence_and_rescan_dedup_idempotency(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
        temp_workspace_dir: Path,
        temp_rules_dir: Path,
    ) -> None:
        """JobWorker + CompositeScannerEngine persists canonical findings & avoids duplicate Finding rows on rescan."""
        aws_parts = ("AKIA", "WORKEREND2END123")
        raw_secret = "".join(aws_parts)
        code = f"AWS = '{raw_secret}'\nresult = eval(x)\n"

        semgrep = SemgrepScannerAdapter(
            rules_path=str(temp_rules_dir),
            runner=lambda **_: _make_command_result(
                exit_code=1,
                stdout=json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "py.audit.eval",
                                "path": "app.py",
                                "start": {"line": 2, "col": 10},
                                "end": {"line": 2, "col": 17},
                                "extra": {
                                    "message": "eval call detected",
                                    "severity": "ERROR",
                                    "metadata": {"confidence": "HIGH"},
                                    "lines": "result = eval(x)",
                                },
                            }
                        ]
                    }
                ),
            ),
            workspace_base_dir=temp_workspace_dir,
        )
        gitleaks = GitleaksScannerAdapter(
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=lambda **_: _make_command_result(
                exit_code=1,
                stdout=json.dumps(
                    [
                        {
                            "Description": "AWS Access Key",
                            "StartLine": 1,
                            "EndLine": 1,
                            "Match": f"AWS = '{raw_secret}'",
                            "Secret": raw_secret,
                            "File": "app.py",
                            "RuleID": "aws-access-token",
                        }
                    ]
                ),
            ),
            workspace_base_dir=temp_workspace_dir,
        )
        composite = CompositeScannerEngine(
            semgrep=semgrep,
            gitleaks=gitleaks,
            workspace_base_dir=temp_workspace_dir,
        )
        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-composite-e2e",
            scanner=composite,
        )

        # Scan 1
        scan1, _job1 = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "app.py", "content": code, "scanned": True}],
        )
        processed = worker.run_once()
        assert processed is True

        db_session.expire_all()
        persisted_scan1 = db_session.get(Scan, scan1.id)
        assert persisted_scan1 is not None
        assert persisted_scan1.status == "succeeded"
        assert persisted_scan1.components == {"semgrep": "passed", "gitleaks": "passed"}
        assert persisted_scan1.counts is not None
        assert persisted_scan1.counts["high"] == 2

        project_findings = db_session.scalars(
            select(Finding).where(Finding.project_id == sample_project.id)
        ).all()
        assert len(project_findings) == 2
        for f_row in project_findings:
            assert raw_secret not in (f_row.title or "")

        scan1_links = db_session.scalars(
            select(ScanFinding).where(ScanFinding.scan_id == scan1.id)
        ).all()
        assert len(scan1_links) == 2
        for sf_row in scan1_links:
            assert raw_secret not in (sf_row.snippet or "")
            assert raw_secret not in (sf_row.description or "")
            assert raw_secret not in json.dumps(sf_row.raw)

        # Mark one finding accepted to verify status preservation on Scan 2
        project_findings[0].status = "accepted"
        db_session.commit()

        # Scan 2 over same code reuses canonical findings cleanly
        scan2, _job2 = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "app.py", "content": code, "scanned": True}],
        )
        assert worker.run_once() is True

        db_session.expire_all()
        all_findings_after = db_session.scalars(
            select(Finding).where(Finding.project_id == sample_project.id)
        ).all()
        assert len(all_findings_after) == 2  # No duplicate canonical findings created
        assert any(f.status == "accepted" for f in all_findings_after)

        scan2_links = db_session.scalars(
            select(ScanFinding).where(ScanFinding.scan_id == scan2.id)
        ).all()
        assert len(scan2_links) == 2

    def test_worker_retryable_failure_then_success(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Retryable composite failure requeues job and succeeds cleanly on subsequent attempt."""
        attempt_counter = {"n": 0}

        class _FlakyScanner:
            def __init__(self, name: str) -> None:
                self._name = name

            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                if self._name == "semgrep":
                    attempt_counter["n"] += 1
                if attempt_counter["n"] == 1:
                    return ScanExecutionResult(
                        status=ScanStatus.FAILED,
                        error_code=f"{self._name.upper()}_TRANSIENT_ERROR",
                        error_message="Transient scanner failure",
                        retryable=True,
                        retry_delay_sec=2,
                        components={self._name: "failed"},
                    )
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    components={self._name: "passed"},
                    counts={"findings": 0},
                    findings=[],
                )

        composite = CompositeScannerEngine(
            scanners=[
                ("semgrep", _FlakyScanner("semgrep")),
                ("gitleaks", _FlakyScanner("gitleaks")),
            ]
        )
        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-composite-retry",
            scanner=composite,
        )

        scan, job = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "ok.py", "content": "x = 1\n", "scanned": True}],
            max_attempts=3,
        )

        t0 = utc_now()
        claimed1 = claim_next_job(db_session, worker_id="w-composite-retry", now=t0)
        assert claimed1 is not None
        worker.process_job(claimed1.id, now=t0, completion_now=t0 + timedelta(seconds=1))

        db_session.expire_all()
        job_after_1 = db_session.get(Job, job.id)
        scan_after_1 = db_session.get(Scan, scan.id)
        assert job_after_1 is not None
        assert job_after_1.status == "queued"
        assert scan_after_1 is not None
        assert scan_after_1.status == "queued"

        # Advance time beyond backoff run_after and re-run
        t_retry = (
            job_after_1.run_after.replace(tzinfo=t0.tzinfo)
            if job_after_1.run_after.tzinfo is None
            else job_after_1.run_after
        ) + timedelta(seconds=5)
        claimed2 = claim_next_job(db_session, worker_id="w-composite-retry", now=t_retry)
        assert claimed2 is not None
        worker.process_job(claimed2.id, now=t_retry, completion_now=t_retry + timedelta(seconds=1))

        db_session.expire_all()
        scan_after_2 = db_session.get(Scan, scan.id)
        assert scan_after_2 is not None
        assert scan_after_2.status == "succeeded"

    def test_cancellation_stops_remaining_scanners_and_preserves_canceled_scan_status(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Cancellation prevents unstarted scanners and prevents overwriting canceled DB scans."""
        cancel_event = threading.Event()
        executed: list[str] = []

        class _FirstScanner:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                executed.append("first")
                cancel_event.set()
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    findings=[
                        _build_semgrep_finding(
                            rule_id="r1",
                            file_path="x.py",
                            start_line=1,
                            snippet="eval(1)",
                        )
                    ],
                )

        class _SecondScanner:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                executed.append("second")
                return ScanExecutionResult(status=ScanStatus.SUCCEEDED)

        engine = CompositeScannerEngine(
            scanners=[("first", _FirstScanner()), ("second", _SecondScanner())]
        )
        res = engine.scan(
            ScanJobPayload(files=[ScannedFile(path="x.py", content="eval(1)\n")]),
            cancel_event=cancel_event,
        )
        assert executed == ["first"]
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "SCAN_CANCELED"
        assert res.components is not None
        assert res.components["second"] == "canceled"
        assert res.findings == []

        # Worker Phase 1 skip + Phase 3 discard when DB scan is canceled
        ran_in_worker = {"count": 0}

        class _CountingComposite:
            def scan(
                self,
                _payload: ScanJobPayload,
                *,
                cancel_event: threading.Event | None = None,
            ) -> ScanExecutionResult:
                ran_in_worker["count"] += 1
                # Simulate external cancellation during scan execution
                with session_factory() as s:
                    target_scan = s.scalars(select(Scan)).first()
                    if target_scan is not None and target_scan.status == "running":
                        target_scan.status = "canceled"
                        s.commit()
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    findings=[
                        _build_semgrep_finding(
                            rule_id="r1",
                            file_path="x.py",
                            start_line=1,
                            snippet="eval(1)",
                        )
                    ],
                )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-cancel-test",
            scanner=_CountingComposite(),
        )
        scan, job = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "x.py", "content": "eval(1)\n", "scanned": True}],
        )
        claimed = claim_next_job(db_session, worker_id="w-cancel-test")
        assert claimed is not None
        worker.process_job(claimed.id)

        db_session.expire_all()
        refreshed_scan = db_session.get(Scan, scan.id)
        refreshed_job = db_session.get(Job, job.id)
        assert refreshed_scan is not None
        assert refreshed_scan.status == "canceled"
        assert refreshed_job is not None
        assert refreshed_job.status == "failed"
        assert refreshed_job.locked_by is None
        assert (
            db_session.scalars(select(ScanFinding).where(ScanFinding.scan_id == scan.id)).all()
            == []
        )

    def test_default_scanner_engine_isolation_boundary_and_delegation(self) -> None:
        """DefaultScannerEngine still fails closed without sandbox and delegates when sandbox_available=True."""
        closed_engine = DefaultScannerEngine(sandbox_available=False)
        res_blocked = closed_engine.scan(
            ScanJobPayload(files=[ScannedFile(path="a.py", content="x=1\n")])
        )
        assert res_blocked.status == ScanStatus.FAILED
        assert res_blocked.error_code == "ISOLATION_UNAVAILABLE"

        stub_composite = CompositeScannerEngine(
            scanners=[
                (
                    "semgrep",
                    SemgrepScannerAdapter(
                        runner=lambda **_: _make_command_result(
                            exit_code=0, stdout='{"results": []}'
                        )
                    ),
                )
            ]
        )
        sandboxed_engine = DefaultScannerEngine(
            sandbox_available=True,
            scanner=stub_composite,
        )
        res_ok = sandboxed_engine.scan(
            ScanJobPayload(files=[ScannedFile(path="a.py", content="", scanned=False)])
        )
        assert res_ok.status == ScanStatus.SUCCEEDED
        assert res_ok.components == {"semgrep": "passed"}

    def test_worker_partial_scan_persistence_pre_canceled_skip_and_lost_lease_discard(
        self,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
    ) -> None:
        """Verify partial scan persistence, Phase 1 canceled-scan skip, and lost-lease discard."""
        finding = _build_semgrep_finding(
            rule_id="py.partial.rule",
            file_path="app.py",
            start_line=1,
            snippet="eval(raw)",
        )

        class _OkSemgrep:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    components={"semgrep": "passed"},
                    counts={"findings": 1, "high": 1},
                    findings=[finding],
                )

        class _FailedGitleaks:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="GITLEAKS_TIMEOUT",
                    error_message="Gitleaks timed out",
                    retryable=False,
                    components={"gitleaks": "failed"},
                )

        composite = CompositeScannerEngine(
            scanners=[("semgrep", _OkSemgrep()), ("gitleaks", _FailedGitleaks())]
        )
        worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-partial-lease",
            scanner=composite,
            lease_duration_sec=30,
        )

        # 1. Partial composite outcome persists surviving finding + partial status
        scan_partial, _job_partial = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "app.py", "content": "eval(raw)\n", "scanned": True}],
        )
        t0 = utc_now()
        claimed_partial = claim_next_job(db_session, worker_id="w-partial-lease", now=t0)
        assert claimed_partial is not None
        worker.process_job(claimed_partial.id, now=t0, completion_now=t0 + timedelta(seconds=1))

        db_session.expire_all()
        refreshed_partial = db_session.get(Scan, scan_partial.id)
        assert refreshed_partial is not None
        assert refreshed_partial.status == "partial"
        assert refreshed_partial.components == {"semgrep": "passed", "gitleaks": "failed"}
        assert refreshed_partial.error_code == "GITLEAKS_TIMEOUT"
        assert (
            len(
                db_session.scalars(
                    select(ScanFinding).where(ScanFinding.scan_id == scan_partial.id)
                ).all()
            )
            == 1
        )

        # 2. Pre-canceled scan in DB skips scanner execution in Phase 1 cleanly
        scan_precanceled, job_precanceled = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "app.py", "content": "eval(raw)\n", "scanned": True}],
            run_after=t0,
        )
        claimed_pre = claim_next_job(db_session, worker_id="w-partial-lease", now=t0)
        assert claimed_pre is not None
        scan_obj = db_session.get(Scan, scan_precanceled.id)
        assert scan_obj is not None
        scan_obj.status = "canceled"
        db_session.commit()

        class _FailIfCalled:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                raise AssertionError("Scanner should not execute for already canceled scan")

        pre_cancel_worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-partial-lease",
            scanner=_FailIfCalled(),
        )
        pre_cancel_worker.process_job(claimed_pre.id, now=t0)

        db_session.expire_all()
        refreshed_pre_scan = db_session.get(Scan, scan_precanceled.id)
        refreshed_pre_job = db_session.get(Job, job_precanceled.id)
        assert refreshed_pre_scan is not None
        assert refreshed_pre_scan.status == "canceled"
        assert refreshed_pre_job is not None
        assert refreshed_pre_job.status == "failed"

        # 3. Expired lease discards composite findings cleanly without overwriting
        scan_expired, _job_expired = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "app.py", "content": "eval(raw)\n", "scanned": True}],
            run_after=t0,
        )
        claimed_expired = claim_next_job(db_session, worker_id="w-partial-lease", now=t0)
        assert claimed_expired is not None
        worker.process_job(
            claimed_expired.id,
            now=t0,
            completion_now=t0 + timedelta(seconds=120),
        )
        db_session.expire_all()
        assert (
            db_session.scalars(
                select(ScanFinding).where(ScanFinding.scan_id == scan_expired.id)
            ).all()
            == []
        )

    def test_post_review_edge_cases_cancellation_crash_invalid_findings_and_base_dir_conflict(
        self,
        db_engine: Engine,
        session_factory: sessionmaker[Session],
        db_session: Session,
        sample_project: Project,
        tmp_path: Path,
        temp_rules_dir: Path,
    ) -> None:
        """Verify review-hardened paths: crash+cancel preservation, heartbeat expire_on_commit,
        component partial marking on invalid findings, and conflicting workspace_base_dir rejection.
        """
        # 1. Conflicting workspace_base_dir across adapters fails closed without falling back
        dir_a = tmp_path / "stage_a"
        dir_b = tmp_path / "stage_b"
        dir_a.mkdir()
        dir_b.mkdir()
        conflict_engine = CompositeScannerEngine(
            semgrep=SemgrepScannerAdapter(
                rules_path=str(temp_rules_dir),
                runner=lambda **_: _make_command_result(exit_code=0, stdout='{"results": []}'),
                workspace_base_dir=dir_a,
            ),
            gitleaks=GitleaksScannerAdapter(
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=lambda **_: _make_command_result(exit_code=0, stdout="[]"),
                workspace_base_dir=dir_b,
            ),
        )
        res_conflict = conflict_engine.scan(
            ScanJobPayload(files=[ScannedFile(path="a.py", content="x = 1\n")])
        )
        assert res_conflict.status == ScanStatus.FAILED
        assert res_conflict.error_code == "SCANNER_STAGING_FAILED"

        # 2. Invalid finding emitted by SUCCEEDED component flips its component to 'partial'
        valid_finding = _build_semgrep_finding(
            rule_id="py.valid",
            file_path="app.py",
            start_line=1,
            snippet="eval(a)",
        )

        class _MixedInvalidScanner:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    components={"semgrep": "passed"},
                    findings=[valid_finding, {"bad": "payload"}],
                )

        class _CleanGitleaksStub:
            def scan(self, _payload: ScanJobPayload) -> ScanExecutionResult:
                return ScanExecutionResult(
                    status=ScanStatus.SUCCEEDED,
                    components={"gitleaks": "passed"},
                    findings=[],
                )

        invalid_res = CompositeScannerEngine(
            scanners=[
                ("semgrep", _MixedInvalidScanner()),
                ("gitleaks", _CleanGitleaksStub()),
            ]
        ).scan(ScanJobPayload(files=[ScannedFile(path="app.py", content="eval(a)\n")]))
        assert invalid_res.status == ScanStatus.PARTIAL
        assert invalid_res.error_code == "COMPOSITE_INVALID_FINDINGS"
        assert invalid_res.components == {"semgrep": "partial", "gitleaks": "passed"}
        assert len(invalid_res.findings) == 1

        # 3. Heartbeat with expire_on_commit=True detects superseded scan without errors
        strict_factory = sessionmaker(bind=db_engine, expire_on_commit=True, autoflush=False)
        t0 = utc_now()
        scan_hb, job_hb = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "a.py", "content": "x = 1\n", "scanned": True}],
            run_after=t0,
        )
        claimed_hb = claim_next_job(db_session, worker_id="w-hb-strict", now=t0)
        assert claimed_hb is not None
        scan_obj = db_session.get(Scan, scan_hb.id)
        assert scan_obj is not None
        scan_obj.status = "superseded"
        db_session.commit()

        hb = JobHeartbeat(
            session_factory=strict_factory,
            job_id=job_hb.id,
            worker_id="w-hb-strict",
            interval_sec=0.5,
            lease_extension_sec=30,
            initial_locked_until=claimed_hb.locked_until,
        )
        assert hb.renew_once(now=t0 + timedelta(seconds=1)) is True
        assert hb.scan_cancel_event.is_set() is True
        assert hb.consecutive_transient_failures == 0

        # 4. Crashing scanner after external DB cancellation does NOT overwrite 'canceled'
        scan_crash, job_crash = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "b.py", "content": "x = 2\n", "scanned": True}],
            run_after=t0,
        )
        claimed_crash = claim_next_job(db_session, worker_id="w-crash-cancel", now=t0)
        assert claimed_crash is not None

        class _CrashingAfterCancel:
            def scan(
                self,
                _payload: ScanJobPayload,
                *,
                cancel_event: threading.Event | None = None,
            ) -> ScanExecutionResult:
                with session_factory() as s:
                    target = s.get(Scan, scan_crash.id)
                    assert target is not None
                    target.status = "canceled"
                    s.commit()
                raise RuntimeError("boom after DB cancellation")

        crash_worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-crash-cancel",
            scanner=_CrashingAfterCancel(),
        )
        crash_worker.process_job(
            claimed_crash.id,
            now=t0,
            completion_now=t0 + timedelta(seconds=1),
        )
        db_session.expire_all()
        refreshed_crash_scan = db_session.get(Scan, scan_crash.id)
        refreshed_crash_job = db_session.get(Job, job_crash.id)
        assert refreshed_crash_scan is not None
        assert refreshed_crash_scan.status == "canceled"
        assert refreshed_crash_job is not None
        assert refreshed_crash_job.status == "failed"

        # 5. Graceful worker.stop() finishes in-flight scan without triggering scan cancellation
        scan_stop, _job_stop = _create_scan_and_job(
            db_session,
            sample_project,
            files=[{"path": "c.py", "content": "x = 3\n", "scanned": True}],
            run_after=t0,
        )
        claimed_stop = claim_next_job(db_session, worker_id="w-graceful-stop", now=t0)
        assert claimed_stop is not None
        saw_cancel_set: list[bool] = []
        graceful_worker = JobWorker(
            session_factory=session_factory,
            worker_id="w-graceful-stop",
            scanner=CompositeScannerEngine(
                scanners=[
                    (
                        "semgrep",
                        type(
                            "_StopChecker",
                            (),
                            {
                                "scan": lambda _self, _p, cancel_event=None: (
                                    graceful_worker.stop(),
                                    saw_cancel_set.append(
                                        bool(cancel_event is not None and cancel_event.is_set())
                                    ),
                                    ScanExecutionResult(
                                        status=ScanStatus.SUCCEEDED,
                                        components={"semgrep": "passed"},
                                        counts={"findings": 0},
                                    ),
                                )[-1]
                            },
                        )(),
                    )
                ]
            ),
        )
        graceful_worker.process_job(
            claimed_stop.id,
            now=t0,
            completion_now=t0 + timedelta(seconds=1),
        )
        assert saw_cancel_set == [False]
        db_session.expire_all()
        refreshed_stop_scan = db_session.get(Scan, scan_stop.id)
        assert refreshed_stop_scan is not None
        assert refreshed_stop_scan.status == "succeeded"
