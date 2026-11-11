"""Unit and integration tests for Gitleaks scanner adapter and output normalizer.

Validates:
1. Valid zero-finding output.
2. Valid findings and canonical normalization.
3. Zero-secret disclosure (snippets, raw metadata, titles, descriptions, logs).
4. Multiple findings and occurrence index assignment.
5. Severity mapping from tags.
6. Correct staged-to-original path translation.
7. Authoritative snippet reconstruction with redaction token [REDACTED:{rule_id}].
8. Invalid and malformed JSON reports.
9. Exit code 1 with findings vs exit code 1 with empty findings.
10. Fatal exit codes (> 1).
11. Out-of-workspace paths and unknown/unscanned files.
12. Out-of-bounds coordinates and empty files.
13. Report file reading and prompt unlinking.
14. Network and missing configuration rejection.
15. FINGERPRINT_KEY validation.
16. Timeouts, output limits, and binary not found.
17. Full JobWorker pipeline persistence without secret leakage.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, event, select
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
    _validate_raw_node,
)
from app.domain.fingerprint import (
    compute_finding_fingerprint,
    compute_secret_anchor,
)
from app.worker.gitleaks import (
    GitleaksScannerAdapter,
    _resolve_executable,
)
from app.worker.runner import JobWorker
from app.worker.scanner import (
    ScanJobPayload,
    ScannedFile,
    ScanStatus,
)
from app.worker.subprocess_runner import CommandResult, CommandStatus

TEST_FINGERPRINT_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def temp_workspace_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Temporary directory for staging workspaces."""
    workspace_dir = tmp_path / "sentinel_staging"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    yield workspace_dir


def make_command_result(
    *,
    status: CommandStatus = CommandStatus.SUCCESS,
    exit_code: int | None = 0,
    stdout: bytes | str = b"",
    stderr: bytes | str = b"",
    duration_ms: float = 100.0,
    command: tuple[str, ...] = ("gitleaks", "detect"),
    output_limit_exceeded: bool = False,
    timed_out: bool = False,
    executable_not_found: bool = False,
) -> CommandResult:
    """Helper to construct typed CommandResult instances for mocked tests."""
    stdout_bytes = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    stderr_bytes = stderr.encode("utf-8") if isinstance(stderr, str) else stderr
    return CommandResult(
        command=command,
        status=status,
        exit_code=exit_code,
        stdout=stdout_bytes,
        stderr=stderr_bytes,
        duration_ms=duration_ms,
        output_limit_exceeded=output_limit_exceeded,
        timed_out=timed_out,
        executable_not_found=executable_not_found,
    )


class TestGitleaksAdapter:
    """Test suite covering Gitleaks adapter, normalizer, and zero-secret disclosure."""

    def test_valid_zero_finding_output(self, temp_workspace_dir: Path) -> None:
        """Exit code 0 with empty JSON list produces succeeded status and zero findings."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=0, stdout="[]")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app/main.py", content="print('hello')\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert res.components == {"gitleaks": "passed"}
        assert res.counts == {
            "findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        assert len(res.findings) == 0

    def test_valid_zero_finding_missing_report_file(self, temp_workspace_dir: Path) -> None:
        """Exit code 0 when report file is not created produces succeeded status and zero findings."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            # Gitleaks exit 0 with empty stdout and no report file created
            return make_command_result(exit_code=0, stdout="")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app/main.py", content="print('hello')\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert res.counts is not None
        assert res.counts["findings"] == 0
        assert len(res.findings) == 0

    def test_valid_single_finding_normalization(self, temp_workspace_dir: Path) -> None:
        """Valid secret detection is normalized into CanonicalFinding with all constraints."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        gitleaks_output = [
            {
                "Description": "AWS Access Key",
                "StartLine": 2,
                "EndLine": 2,
                "StartColumn": 11,
                "EndColumn": 31,
                "Match": f"AWS_KEY = '{raw_secret}'",
                "Secret": raw_secret,
                "File": "src/app/config.py",
                "RuleID": "aws-access-token",
                "Entropy": 3.72,
                "Tags": ["key", "AWS"],
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(gitleaks_output))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        code = f"# Config file\nAWS_KEY = '{raw_secret}'\nDEBUG = True\n"
        payload = ScanJobPayload(
            files=[ScannedFile(path="app/config.py", content=code, scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert res.components == {"gitleaks": "passed"}
        assert res.counts is not None
        assert res.counts["findings"] == 1
        assert res.counts["high"] == 1
        assert len(res.findings) == 1

        f: CanonicalFinding = res.findings[0]
        assert f.rule_id == "aws-access-token"
        assert f.source == FindingSource.GITLEAKS
        assert f.category == FindingCategory.HARDCODED_SECRET
        assert f.verification_status == VerificationStatus.SCANNER_DETECTED
        assert f.confidence == FindingConfidence.HIGH
        assert f.severity == FindingSeverity.HIGH
        assert f.file_path == "app/config.py"
        assert f.start_line == 2
        assert f.end_line == 2

        # Check secret redaction in snippet
        expected_token = "[REDACTED:aws-access-token]"
        assert expected_token in f.snippet
        assert raw_secret not in f.snippet
        assert f.snippet == f"AWS_KEY = '{expected_token}'"

        # Check secret HMAC anchor and deterministic fingerprint
        expected_anchor = compute_secret_anchor(raw_secret, TEST_FINGERPRINT_KEY)
        expected_fp = compute_finding_fingerprint(
            rule_id="aws-access-token",
            source=FindingSource.GITLEAKS.value,
            file_path="app/config.py",
            anchor=expected_anchor,
            occ=0,
            category=FindingCategory.HARDCODED_SECRET.value,
        )
        assert f.fingerprint == expected_fp
        assert len(f.fingerprint) == 64
        assert f.fingerprint == f.fingerprint.lower()

        # Check raw metadata
        assert f.raw is not None
        assert "secret" not in f.raw
        assert "match" not in f.raw
        assert "line" not in f.raw
        assert raw_secret not in json.dumps(f.raw)
        _validate_raw_node(f.raw)

    def test_zero_secret_disclosure_strict_invariants(self, temp_workspace_dir: Path) -> None:
        """Raw secrets, Match, Secret, and Line must never leak into any model field."""
        raw_secret = "ghp_111122223333444455556666777788889999"
        raw_match = f'GITHUB_TOKEN = "{raw_secret}"'
        gitleaks_output = [
            {
                "Description": f"GitHub Token secret: {raw_secret}",  # Even if scanner leaks it in desc!
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 16,
                "EndColumn": 56,
                "Match": raw_match,
                "Secret": raw_secret,
                "File": "src/creds.py",
                "RuleID": "github-pat",
                "Entropy": 4.1,
                "Tags": ["github", "token"],
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(gitleaks_output))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        file_content = f"{raw_match}\n"
        payload = ScanJobPayload(
            files=[ScannedFile(path="creds.py", content=file_content, scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 1
        f = res.findings[0]

        # Verify raw_secret is NOT present in ANY attribute of CanonicalFinding
        finding_dict = f.model_dump(mode="json")
        finding_json = json.dumps(finding_dict)
        assert raw_secret not in finding_json
        assert raw_match not in finding_json

        # Verify prohibited keys are absent from raw metadata
        assert f.raw is not None
        for forbidden in ("secret", "match", "line", "raw_secret", "secret_value"):
            assert forbidden not in f.raw
        _validate_raw_node(f.raw)

    def test_multiple_secrets_same_file_occurrence_indexing(self, temp_workspace_dir: Path) -> None:
        """Multiple occurrences of the same secret in one file receive distinct occurrence indices."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        gitleaks_output = [
            {
                "Description": "AWS Access Key",
                "StartLine": 2,
                "EndLine": 2,
                "StartColumn": 10,
                "EndColumn": 30,
                "Match": f"KEY1 = '{raw_secret}'",
                "Secret": raw_secret,
                "File": "src/keys.py",
                "RuleID": "aws-access-token",
            },
            {
                "Description": "AWS Access Key",
                "StartLine": 5,
                "EndLine": 5,
                "StartColumn": 10,
                "EndColumn": 30,
                "Match": f"KEY2 = '{raw_secret}'",
                "Secret": raw_secret,
                "File": "src/keys.py",
                "RuleID": "aws-access-token",
            },
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(gitleaks_output))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        code = (
            "# Header\n"
            f"KEY1 = '{raw_secret}'\n"
            "# Middle comment\n"
            "# Another line\n"
            f"KEY2 = '{raw_secret}'\n"
        )
        payload = ScanJobPayload(files=[ScannedFile(path="keys.py", content=code, scanned=True)])

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 2

        f1, f2 = res.findings
        assert f1.start_line == 2
        assert f2.start_line == 5
        # Same rule, same file, same anchor -> occurrence index 0 and 1 -> distinct fingerprints
        assert f1.fingerprint != f2.fingerprint

    def test_different_secrets_same_rule_different_anchors(self, temp_workspace_dir: Path) -> None:
        """Different secrets produce distinct HMAC anchors and distinct fingerprints."""
        sec1 = "AKIA1111111111EXAMPLE"
        sec2 = "AKIA2222222222EXAMPLE"
        gitleaks_output = [
            {
                "Description": "AWS Access Key",
                "StartLine": 1,
                "EndLine": 1,
                "Match": f"K1='{sec1}'",
                "Secret": sec1,
                "File": "src/multi.py",
                "RuleID": "aws-access-token",
            },
            {
                "Description": "AWS Access Key",
                "StartLine": 2,
                "EndLine": 2,
                "Match": f"K2='{sec2}'",
                "Secret": sec2,
                "File": "src/multi.py",
                "RuleID": "aws-access-token",
            },
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(gitleaks_output))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        code = f"K1='{sec1}'\nK2='{sec2}'\n"
        payload = ScanJobPayload(files=[ScannedFile(path="multi.py", content=code, scanned=True)])

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 2

        anchor1 = compute_secret_anchor(sec1, TEST_FINGERPRINT_KEY)
        anchor2 = compute_secret_anchor(sec2, TEST_FINGERPRINT_KEY)
        assert anchor1 != anchor2
        assert res.findings[0].fingerprint != res.findings[1].fingerprint

    def test_severity_mapping_from_tags(self, temp_workspace_dir: Path) -> None:
        """Tags with 'critical' or 'medium' override default HIGH severity."""
        slack_parts = ["xoxb", "1234567890", "123456789012", "1234567890abcdef"]
        raw_secret = "-".join(slack_parts)
        gitleaks_output = [
            {
                "Description": "Critical Token",
                "StartLine": 1,
                "EndLine": 1,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/token.py",
                "RuleID": "slack-bot-token",
                "Tags": ["critical", "slack"],
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(gitleaks_output))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="token.py", content=f"{raw_secret}\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert res.findings[0].severity == FindingSeverity.CRITICAL
        assert res.counts is not None
        assert res.counts["critical"] == 1

    def test_invalid_json_output(self, temp_workspace_dir: Path) -> None:
        """Unparseable stdout when exit code is 0 returns GITLEAKS_INVALID_JSON."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=0, stdout="not valid json")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_INVALID_JSON"

    def test_malformed_json_root_not_list(self, temp_workspace_dir: Path) -> None:
        """JSON output whose root is not a list returns GITLEAKS_MALFORMED_OUTPUT."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=0, stdout=json.dumps(12345))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_MALFORMED_OUTPUT"

    def test_exit_code_1_with_findings_succeeds(self, temp_workspace_dir: Path) -> None:
        """Gitleaks exit code 1 with valid findings produces SUCCEEDED status."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        findings = [
            {
                "Description": "AWS Access Key",
                "StartLine": 1,
                "EndLine": 1,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/key.txt",
                "RuleID": "aws-access-token",
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="key.txt", content=f"{raw_secret}\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 1

    def test_exit_code_1_with_empty_findings_fails(self, temp_workspace_dir: Path) -> None:
        """Non-zero exit code with empty findings report produces FAILED status."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(
                exit_code=1, stdout="[]", stderr="failed to run scan: internal error"
            )

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_EXECUTION_FAILED"

    def test_fatal_exit_codes(self, temp_workspace_dir: Path) -> None:
        """Exit code 2 (fatal/syntax error) produces FAILED status."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(
                exit_code=2, stdout="", stderr="fatal error: flag syntax invalid"
            )

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_EXECUTION_FAILED"
        assert res.error_message == "Gitleaks execution failed with non-zero exit code"

    def test_timeout(self, temp_workspace_dir: Path) -> None:
        """Timeout status produces FAILED with GITLEAKS_TIMEOUT error code."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(status=CommandStatus.TIMEOUT, timed_out=True)

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_TIMEOUT"

    def test_output_limit_exceeded(self, temp_workspace_dir: Path) -> None:
        """Output limit exceeded produces FAILED with GITLEAKS_OUTPUT_LIMIT_EXCEEDED."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(
                status=CommandStatus.OUTPUT_LIMIT_EXCEEDED, output_limit_exceeded=True
            )

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_OUTPUT_LIMIT_EXCEEDED"

    def test_binary_not_found(self, temp_workspace_dir: Path) -> None:
        """Executable not found produces FAILED with GITLEAKS_BINARY_NOT_FOUND."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(
                status=CommandStatus.EXECUTABLE_NOT_FOUND, executable_not_found=True
            )

        adapter = GitleaksScannerAdapter(
            executable_path="nonexistent-gitleaks-binary",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_BINARY_NOT_FOUND"

    def test_out_of_workspace_path_rejected(self, temp_workspace_dir: Path) -> None:
        """Finding referencing path outside staging workspace is safely rejected."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        findings = [
            {
                "Description": "AWS Access Key",
                "StartLine": 1,
                "EndLine": 1,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "../../etc/passwd",
                "RuleID": "aws-access-token",
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="safe.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_NORMALIZATION_FAILED"

    def test_unscanned_or_unknown_file_rejected(self, temp_workspace_dir: Path) -> None:
        """Finding referencing a file marked scanned=False is safely rejected."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        findings = [
            {
                "Description": "AWS Access Key",
                "StartLine": 1,
                "EndLine": 1,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/ignored.txt",
                "RuleID": "aws-access-token",
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="ignored.txt",
                    content=f"{raw_secret}\n",
                    scanned=False,
                    skip_reason="binary",
                ),
                ScannedFile(path="main.py", content="clean_code = True\n", scanned=True),
            ]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_NORMALIZATION_FAILED"

    def test_out_of_bounds_line_coordinates(self, temp_workspace_dir: Path) -> None:
        """Coordinates exceeding file lines or start_line < 1 are rejected."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        findings = [
            {
                "Description": "AWS Access Key",
                "StartLine": 100,  # Exceeds file line count of 2
                "EndLine": 100,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/app.py",
                "RuleID": "aws-access-token",
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="line1\nline2\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_NORMALIZATION_FAILED"

    def test_report_file_read_and_cleaned_up(self, temp_workspace_dir: Path) -> None:
        """When Gitleaks writes to the report-path file, it is read and unlinked promptly."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        findings = [
            {
                "Description": "AWS Access Key",
                "StartLine": 1,
                "EndLine": 1,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/secret.py",
                "RuleID": "aws-access-token",
            }
        ]

        def mock_runner(args: Any, cwd: Any, **kwargs: Any) -> CommandResult:
            # Simulate real Gitleaks writing report-path file inside cwd
            report_arg_idx = args.index("--report-path")
            report_file = Path(args[report_arg_idx + 1])
            report_file.write_text(json.dumps(findings), encoding="utf-8")
            return make_command_result(exit_code=1, stdout="")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="secret.py", content=f"KEY = '{raw_secret}'\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 1
        assert res.findings[0].rule_id == "aws-access-token"

    def test_network_config_path_rejected(self, temp_workspace_dir: Path) -> None:
        """Network URLs in config_path are rejected to prevent SSRF and unisolated fetches."""
        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            config_path="https://malicious.com/rules.toml",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_INVALID_CONFIG_PATH"

    def test_invalid_fingerprint_key_rejected(self, temp_workspace_dir: Path) -> None:
        """Insecure template placeholder or short FINGERPRINT_KEY fails closed."""
        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key="replace-with-a-secure-random-hex-key-for-fingerprinting",
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_INVALID_FINGERPRINT_KEY"

    def test_no_scannable_files_returns_immediately(self, temp_workspace_dir: Path) -> None:
        """Payload with no files or all unscanned returns SUCCEEDED without running subprocess."""
        called = False

        def mock_runner(**kwargs: Any) -> CommandResult:
            nonlocal called
            called = True
            return make_command_result()

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="test.bin", content="", scanned=False, skip_reason="binary")]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert res.counts is not None
        assert res.counts["findings"] == 0
        assert called is False

    def test_argv_execution_no_shell(self, temp_workspace_dir: Path) -> None:
        """Runner receives list/tuple argument vector and never shell string."""
        passed_args: list[str] | None = None

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal passed_args
            passed_args = args
            return make_command_result(exit_code=0, stdout="[]")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert isinstance(passed_args, list)
        assert passed_args[0] == "gitleaks"
        assert "detect" in passed_args
        assert "--no-git" in passed_args
        assert "--redact" not in passed_args

    def test_job_worker_full_pipeline_persistence(self, temp_workspace_dir: Path) -> None:
        """Full end-to-end integration test with JobWorker, DB queue, and persistence."""
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
        session_factory = sessionmaker(
            bind=engine, class_=Session, expire_on_commit=False, autoflush=False
        )

        raw_secret = "AKIAIOSFODNN7EXAMPLE"

        with session_factory() as session:
            user = User(
                github_user_id=123456,
                github_login="gitleaks-tester",
                display_name="Gitleaks Tester",
            )
            session.add(user)
            session.flush()

            project = Project(
                owner_user_id=user.id,
                kind="manual",
                name="Gitleaks E2E Project",
                status="active",
            )
            session.add(project)
            session.flush()

            scan = Scan(
                project_id=project.id,
                trigger="manual",
                trigger_key=f"gitleaks-test-{uuid.uuid4()}",
                status="queued",
                report_status="not_applicable",
            )
            session.add(scan)
            session.flush()

            code = f"# Configuration\nAPI_KEY = '{raw_secret}'\n"
            payload = {
                "files": [
                    {
                        "path": "app/config.py",
                        "content": code,
                        "scanned": True,
                        "skip_reason": None,
                    }
                ],
                "run_ai": False,
            }

            job = Job(
                scan_id=scan.id,
                type="scan",
                status="queued",
                payload=payload,
                run_after=utc_now(),
            )
            session.add(job)
            session.commit()
            job_id = job.id
            scan_id = scan.id
            project_id = project.id

        gitleaks_output = [
            {
                "Description": "AWS Access Key",
                "StartLine": 2,
                "EndLine": 2,
                "StartColumn": 12,
                "EndColumn": 32,
                "Match": f"API_KEY = '{raw_secret}'",
                "Secret": raw_secret,
                "File": "src/app/config.py",
                "RuleID": "aws-access-token",
                "Entropy": 3.8,
                "Tags": ["key", "AWS"],
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(gitleaks_output))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="test-gitleaks-worker-1",
            scanner=adapter,
        )

        # Worker processes the job
        processed = worker.run_once()
        assert processed is True

        # Verify DB records
        with session_factory() as session:
            completed_job = session.get(Job, job_id)
            assert completed_job is not None
            assert completed_job.status == "succeeded"
            assert completed_job.payload is None  # Payload scrubbed

            completed_scan = session.get(Scan, scan_id)
            assert completed_scan is not None
            assert completed_scan.status == "succeeded"
            assert completed_scan.components == {"gitleaks": "passed"}
            assert completed_scan.counts is not None
            assert completed_scan.counts["findings"] == 1
            assert completed_scan.counts["high"] == 1

            # Verify persistent finding in DB
            findings = session.scalars(
                select(Finding).where(Finding.project_id == project_id)
            ).all()
            assert len(findings) == 1
            f = findings[0]
            assert f.rule_id == "aws-access-token"
            assert f.source == "gitleaks"
            assert f.category == "hardcoded_secret"
            assert f.file_path == "app/config.py"
            assert f.status == "open"

            # Verify ScanFinding row (observations per scan)
            scan_findings = session.scalars(
                select(ScanFinding).where(ScanFinding.scan_id == scan_id)
            ).all()
            assert len(scan_findings) == 1
            sf = scan_findings[0]
            assert sf.finding_id == f.id
            assert sf.severity == "high"
            # Verify snippet in DB has redaction token and NO raw secret!
            assert "[REDACTED:aws-access-token]" in sf.snippet
            assert raw_secret not in sf.snippet
            assert raw_secret not in str(sf.raw)

    def test_zero_secret_leakage_in_error_messages_and_logs(
        self, temp_workspace_dir: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Secrets appearing in stderr or runner exceptions never leak into errors or logs."""
        raw_secret = "ghp_LEAKYTOKEN9876543210ABCDEF123456"

        # Case 1: Stderr contains raw secret during execution failure
        def mock_runner_leaky_stderr(**kwargs: Any) -> CommandResult:
            return make_command_result(
                exit_code=2,
                stdout="",
                stderr=f"fatal error: unauthorized access token {raw_secret} rejected",
            )

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner_leaky_stderr,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        with caplog.at_level("DEBUG"):
            res = adapter.scan(payload)

        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_EXECUTION_FAILED"
        assert res.error_message == "Gitleaks execution failed with non-zero exit code"
        assert raw_secret not in str(res.error_message)
        assert raw_secret not in caplog.text

        # Case 2: Runner raises an exception carrying the raw secret
        caplog.clear()

        def mock_runner_raising(**kwargs: Any) -> CommandResult:
            raise RuntimeError(f"critical connection error with auth {raw_secret}")

        adapter_raising = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner_raising,
            workspace_base_dir=temp_workspace_dir,
        )

        with caplog.at_level("DEBUG"):
            res2 = adapter_raising.scan(payload)

        assert res2.status == ScanStatus.FAILED
        assert res2.error_code == "GITLEAKS_EXECUTION_ERROR"
        assert res2.error_message == "Gitleaks staging or execution failure"
        assert raw_secret not in str(res2.error_message)
        assert raw_secret not in caplog.text

    def test_report_file_oversized_rejected(
        self, temp_workspace_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Report files exceeding maximum size limit are rejected and promptly unlinked."""
        monkeypatch.setattr("app.worker.gitleaks._MAX_REPORT_FILE_BYTES", 256)
        created_report_path: Path | None = None

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal created_report_path
            report_arg_idx = args.index("--report-path")
            created_report_path = Path(args[report_arg_idx + 1])
            created_report_path.write_bytes(b"[" + b"0" * 300 + b"]")
            return make_command_result(exit_code=1, stdout="")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_REPORT_TOO_LARGE"
        assert res.error_message == "Gitleaks report file exceeds maximum allowed size"
        assert created_report_path is not None
        assert not created_report_path.exists()

    def test_report_file_invalid_utf8_rejected(self, temp_workspace_dir: Path) -> None:
        """Report files containing invalid UTF-8 bytes are rejected and promptly unlinked."""
        created_report_path: Path | None = None

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal created_report_path
            report_arg_idx = args.index("--report-path")
            created_report_path = Path(args[report_arg_idx + 1])
            created_report_path.write_bytes(b"\x80\x81\xff\xfe")
            return make_command_result(exit_code=1, stdout="")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_INVALID_REPORT_ENCODING"
        assert res.error_message == "Gitleaks report file contains invalid character encoding"
        assert created_report_path is not None
        assert not created_report_path.exists()

    def test_report_file_symlink_rejected(
        self, temp_workspace_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Report file path resolving to a symlink is rejected for safety."""
        created_report_path: Path | None = None

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal created_report_path
            report_arg_idx = args.index("--report-path")
            created_report_path = Path(args[report_arg_idx + 1])
            created_report_path.write_text("[]", encoding="utf-8")
            return make_command_result(exit_code=0, stdout="")

        monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "gitleaks-report.json")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_UNSAFE_REPORT_FILE"
        assert res.error_message == "Gitleaks report file is invalid or unsafe"

    def test_report_file_unlinked_on_all_paths(self, temp_workspace_dir: Path) -> None:
        """Report file is guaranteed to be unlinked across success, failure, and exceptions."""
        scenarios = [
            (
                "success_findings",
                1,
                json.dumps(
                    [
                        {
                            "RuleID": "test",
                            "File": "src/app.py",
                            "StartLine": 1,
                            "EndLine": 1,
                            "Match": "AKIAIOSFODNN7EXAMPLE",
                            "Secret": "AKIAIOSFODNN7EXAMPLE",
                        }
                    ]
                ),
            ),
            ("success_empty", 0, "[]"),
            ("invalid_json", 1, "{malformed"),
        ]

        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="app.py",
                    content="secret_val = 'AKIAIOSFODNN7EXAMPLE'\n",
                    scanned=True,
                )
            ]
        )

        for name, exit_code, file_content in scenarios:
            created_file: Path | None = None

            def mock_runner(
                args: Any,
                curr_content: str = file_content,
                curr_code: int = exit_code,
                **kwargs: Any,
            ) -> CommandResult:
                nonlocal created_file
                report_arg_idx = args.index("--report-path")
                created_file = Path(args[report_arg_idx + 1])
                created_file.write_text(curr_content, encoding="utf-8")
                return make_command_result(exit_code=curr_code, stdout="")

            adapter = GitleaksScannerAdapter(
                executable_path="gitleaks",
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=mock_runner,
                workspace_base_dir=temp_workspace_dir,
            )
            adapter.scan(payload)
            assert created_file is not None, f"Failed for scenario {name}"
            assert not created_file.exists(), f"File remained on disk for scenario {name}"

        # Also test exception during runner
        created_file_exc: Path | None = None

        def mock_runner_exc(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal created_file_exc
            report_arg_idx = args.index("--report-path")
            created_file_exc = Path(args[report_arg_idx + 1])
            created_file_exc.write_text("[]", encoding="utf-8")
            raise RuntimeError("simulated crash")

        adapter_exc = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner_exc,
            workspace_base_dir=temp_workspace_dir,
        )
        adapter_exc.scan(payload)
        assert created_file_exc is not None
        assert not created_file_exc.exists()

    def test_rule_id_allowlist_validation(self, temp_workspace_dir: Path) -> None:
        """RuleID must conform to conservative allowlisted format."""
        invalid_rule_ids = [
            "aws access key",  # space
            "rule;rm -rf /",  # command separator
            "rule$(whoami)",  # shell substitution
            "a" * 129,  # exceeds 128 characters
            "",  # empty
        ]

        findings = [
            {
                "Description": "Invalid Rule Finding",
                "StartLine": 1,
                "EndLine": 1,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "src/main.py",
                "RuleID": bad_id,
            }
            for bad_id in invalid_rule_ids
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="main.py",
                    content="val = 'AKIAIOSFODNN7EXAMPLE'\n",
                    scanned=True,
                )
            ]
        )

        res = adapter.scan(payload)
        # All findings rejected -> normalization failure
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_NORMALIZATION_FAILED"

        # Now test with one valid rule ID alongside invalid ones
        findings_with_valid = (
            findings
            + [
                {
                    "Description": "Valid Rule Finding",
                    "StartLine": 1,
                    "EndLine": 1,
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "File": "src/main.py",
                    "RuleID": "aws-access-token.v2_final",  # valid chars: alphanumeric, hyphen, dot, underscore
                }
            ]
        )

        def mock_runner_partial(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings_with_valid))

        adapter_partial = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner_partial,
            workspace_base_dir=temp_workspace_dir,
        )

        res2 = adapter_partial.scan(payload)
        assert res2.status == ScanStatus.PARTIAL
        assert len(res2.findings) == 1
        assert res2.findings[0].rule_id == "aws-access-token.v2_final"

    def test_description_strict_string_validation(self, temp_workspace_dir: Path) -> None:
        """Non-string descriptions are handled safely and oversized descriptions are truncated."""
        long_desc = "A" * 1500
        findings = [
            {
                "Description": 12345,  # non-string
                "StartLine": 1,
                "EndLine": 1,
                "Match": "secret1",
                "Secret": "secret1",
                "File": "src/main.py",
                "RuleID": "rule-nonstring-desc",
            },
            {
                "Description": long_desc,  # exceeds 1000 characters
                "StartLine": 2,
                "EndLine": 2,
                "Match": "secret2",
                "Secret": "secret2",
                "File": "src/main.py",
                "RuleID": "rule-long-desc",
            },
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="secret1 = 1\nsecret2 = 2\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 2

        f_nonstring = next(f for f in res.findings if f.rule_id == "rule-nonstring-desc")
        assert f_nonstring.title == "Hardcoded rule-nonstring-desc secret detected"
        assert (
            f_nonstring.description
            == "Hardcoded secret detected matching rule 'rule-nonstring-desc'."
        )

        f_long = next(f for f in res.findings if f.rule_id == "rule-long-desc")
        assert len(f_long.description) <= 1000

    def test_exact_secret_scrubbing_across_all_fields(self, temp_workspace_dir: Path) -> None:
        """Adversarial detected secrets in descriptions, tags, and metadata are completely scrubbed."""
        raw_secret = "ghp_LEAKYTOKENXYZ99999999"
        adversarial_findings = [
            # Finding 1: Secret appears in Description, Tags, and metadata
            {
                "Description": f"Secret leak of {raw_secret} found in prod",
                "StartLine": 1,
                "EndLine": 1,
                "Match": f"token = '{raw_secret}'",
                "Secret": raw_secret,
                "File": "src/main.py",
                "RuleID": "github-pat",
                "Tags": ["api", f"token-{raw_secret[:10]}"],
                "Entropy": 4.5,
            },
            # Finding 2: Adversarial secret in RuleID -> should be safely rejected
            {
                "Description": "Adversarial rule",
                "StartLine": 2,
                "EndLine": 2,
                "Match": f"token2 = '{raw_secret}'",
                "Secret": raw_secret,
                "File": "src/main.py",
                "RuleID": f"rule_{raw_secret}",
            },
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(adversarial_findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="main.py",
                    content=f"token = '{raw_secret}'\ntoken2 = '{raw_secret}'\n",
                    scanned=True,
                )
            ]
        )

        res = adapter.scan(payload)
        # Finding 2's secret-bearing RuleID is safely sanitized rather than discarded;
        # neither finding leaks the full secret or partial fragments into any canonical field.
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 2

        partial_prefix = raw_secret[:10]
        partial_suffix = raw_secret[-10:]
        for f in res.findings:
            dumped = f.model_dump_json()
            assert raw_secret not in dumped
            assert partial_prefix not in dumped
            assert partial_suffix not in dumped
            assert raw_secret not in f.title
            assert raw_secret not in f.description
            assert raw_secret not in f.snippet
            assert raw_secret not in str(f.raw)

        # Finding 1 preserves safe tags while dropping the secret-fragment tag
        assert res.findings[0].raw.get("tags") == ["api"]
        # Finding 2 preserves its safe rule prefix cleanly without exposing the secret
        assert res.findings[1].rule_id.startswith("rule_redacted-")

    def test_tags_validation(self, temp_workspace_dir: Path) -> None:
        """Tags with invalid characters are filtered out and list is capped at 10 items."""
        tags_input = [
            "valid-tag",
            "tag_2",
            "tag.3",
            "<script>",  # invalid char
            "tag with space",  # invalid space
            "tag;drop_table",  # invalid semicolon
            "t" * 65,  # too long (>64)
        ] + [f"extra_{i}" for i in range(15)]  # extra tags to test max 10 cap

        findings = [
            {
                "Description": "Tags test",
                "StartLine": 1,
                "EndLine": 1,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "src/main.py",
                "RuleID": "tags-rule",
                "Tags": tags_input,
            }
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="main.py",
                    content="val = 'AKIAIOSFODNN7EXAMPLE'\n",
                    scanned=True,
                )
            ]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 1
        tags_in_raw = res.findings[0].raw.get("tags", [])
        assert len(tags_in_raw) <= 10
        assert "<script>" not in tags_in_raw
        assert "tag with space" not in tags_in_raw
        assert "tag;drop_table" not in tags_in_raw
        assert all(len(t) <= 64 for t in tags_in_raw)

    def test_strict_line_and_column_coordinates(self, temp_workspace_dir: Path) -> None:
        """Coordinates with booleans, negative/zero numbers, or exceeding line count are rejected."""
        # 1. Invalid line coordinates
        invalid_line_cases: list[dict[str, Any]] = [
            {"StartLine": True, "EndLine": 1},
            {"StartLine": 1, "EndLine": False},
            {"StartLine": 0, "EndLine": 1},
            {"StartLine": -1, "EndLine": 1},
            {"StartLine": 2, "EndLine": 1},  # start > end
            {
                "StartLine": 1,
                "EndLine": 10,
            },  # exceeds file line count (2 lines) -> rejected, not clamped!
        ]

        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        for idx, coords in enumerate(invalid_line_cases):
            finding = {
                "Description": f"Line Case {idx}",
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/main.py",
                "RuleID": "test-rule",
                **coords,
            }

            def mock_runner(curr_finding: dict[str, Any] = finding, **kwargs: Any) -> CommandResult:
                return make_command_result(exit_code=1, stdout=json.dumps([curr_finding]))

            adapter = GitleaksScannerAdapter(
                executable_path="gitleaks",
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=mock_runner,
                workspace_base_dir=temp_workspace_dir,
            )
            payload = ScanJobPayload(
                files=[
                    ScannedFile(
                        path="main.py",
                        content=f"line1 = '{raw_secret}'\nline2 = '{raw_secret}'\n",
                        scanned=True,
                    )
                ]
            )
            res = adapter.scan(payload)
            assert res.status == ScanStatus.FAILED, (
                f"Failed to reject invalid line coords: {coords}"
            )
            assert res.error_code == "GITLEAKS_NORMALIZATION_FAILED"

        # 2. Invalid column coordinates
        invalid_col_cases: list[dict[str, Any]] = [
            {"StartColumn": True},
            {"StartColumn": 0},
            {"StartColumn": -1},
            {"StartColumn": 50},  # line is only 10 chars -> exceeds line length + 1
            {"StartColumn": 8, "EndColumn": 4},  # single line start_col > end_col
        ]

        for idx, col_coords in enumerate(invalid_col_cases):
            finding = {
                "Description": f"Col Case {idx}",
                "StartLine": 1,
                "EndLine": 1,
                "Match": "12345",
                "Secret": "12345",
                "File": "src/main.py",
                "RuleID": "test-rule",
                **col_coords,
            }

            def mock_runner_col(
                curr_finding: dict[str, Any] = finding, **kwargs: Any
            ) -> CommandResult:
                return make_command_result(exit_code=1, stdout=json.dumps([curr_finding]))

            adapter_col = GitleaksScannerAdapter(
                executable_path="gitleaks",
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=mock_runner_col,
                workspace_base_dir=temp_workspace_dir,
            )
            payload = ScanJobPayload(
                files=[ScannedFile(path="main.py", content="1234567890\n", scanned=True)]
            )
            res_col = adapter_col.scan(payload)
            assert res_col.status == ScanStatus.FAILED, (
                f"Failed to reject invalid col coords: {col_coords}"
            )

        # 3. Missing column coordinates allowed
        finding_no_cols = {
            "Description": "Missing columns",
            "StartLine": 1,
            "EndLine": 1,
            "Match": raw_secret,
            "Secret": raw_secret,
            "File": "src/main.py",
            "RuleID": "test-rule",
        }

        def mock_runner_no_cols(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps([finding_no_cols]))

        adapter_no_cols = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner_no_cols,
            workspace_base_dir=temp_workspace_dir,
        )
        res_no_cols = adapter_no_cols.scan(
            ScanJobPayload(
                files=[
                    ScannedFile(
                        path="main.py",
                        content=f"val = '{raw_secret}'\n",
                        scanned=True,
                    )
                ]
            )
        )
        assert res_no_cols.status == ScanStatus.SUCCEEDED
        assert len(res_no_cols.findings) == 1
        assert "start_column" not in res_no_cols.findings[0].raw

    def test_deduplicate_exact_duplicate_findings(self, temp_workspace_dir: Path) -> None:
        """Exact duplicate findings from scanner are deduplicated while separate occurrences are preserved."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        findings = [
            # Two exact duplicate records at line 1
            {
                "Description": "AWS Access Key",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 1,
                "EndColumn": 20,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/main.py",
                "RuleID": "aws-access-token",
            },
            {
                "Description": "AWS Access Key",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 1,
                "EndColumn": 20,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/main.py",
                "RuleID": "aws-access-token",
            },
            # A distinct third finding at line 2
            {
                "Description": "AWS Access Key",
                "StartLine": 2,
                "EndLine": 2,
                "StartColumn": 1,
                "EndColumn": 20,
                "Match": raw_secret,
                "Secret": raw_secret,
                "File": "src/main.py",
                "RuleID": "aws-access-token",
            },
        ]

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[
                ScannedFile(path="main.py", content=f"{raw_secret}\n{raw_secret}\n", scanned=True)
            ]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        # Duplicate record collapsed -> exactly 2 distinct findings
        assert len(res.findings) == 2
        f1, f2 = res.findings
        assert f1.start_line == 1
        assert f2.start_line == 2
        assert f1.fingerprint != f2.fingerprint

    def test_cli_does_not_pass_redact_flag(self, temp_workspace_dir: Path) -> None:
        """Gitleaks CLI argv must NOT contain --redact so raw secret can produce distinct HMAC anchors."""
        passed_args: list[str] | None = None

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal passed_args
            passed_args = args
            return make_command_result(exit_code=0, stdout="[]")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert passed_args is not None
        assert "--redact" not in passed_args

    def test_resolve_executable_validation(self, tmp_path: Path) -> None:
        """Executable resolver rejects directories, non-existent files, and non-executables."""
        # 1. Empty string
        assert _resolve_executable("") is None
        assert _resolve_executable("   ") is None

        # 2. Directory path
        dir_path = tmp_path / "somedir"
        dir_path.mkdir()
        assert _resolve_executable(dir_path) is None

        # 3. Non-existent path
        missing_path = tmp_path / "nonexistent_bin"
        assert _resolve_executable(missing_path) is None

        # 4. Valid executable file
        bin_path = tmp_path / "my_gitleaks"
        bin_path.write_text("#!/bin/sh\nexit 0\n")
        bin_path.chmod(0o755)
        resolved = _resolve_executable(bin_path)
        assert resolved is not None
        assert Path(resolved).resolve() == bin_path.resolve()


class TestGitleaksSecurityHardening:
    """Regression tests covering Gitleaks security hardening fixes."""

    def test_report_file_descriptor_o_nofollow_and_toctou_inode_mismatch(
        self, temp_workspace_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Descriptor-based report reading validates fstat regular file and rejects inode swaps."""
        import os

        from app.worker.gitleaks import _read_and_cleanup_report_file

        report_file = temp_workspace_dir / "gitleaks-report.json"
        report_file.write_text('{"secret": "leak"}', encoding="utf-8")

        real_lstat = os.lstat
        real_fstat = os.fstat
        observed_flags: list[int] = []
        real_open = os.open

        def spy_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if Path(path) == report_file:
                observed_flags.append(flags)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)
        text, err = _read_and_cleanup_report_file(report_file)
        assert err is None
        assert text == '{"secret": "leak"}'
        assert not os.path.lexists(report_file)
        assert observed_flags
        if hasattr(os, "O_NOFOLLOW"):
            assert observed_flags[0] & os.O_NOFOLLOW

        # Now simulate an inode swap (TOCTOU) between initial lstat and fstat
        report_file.write_text('[{"Secret": "ghp_SHOULDNOTREAD99999999"}]', encoding="utf-8")
        orig_lstat_res = real_lstat(report_file)

        class _FakeFstat:
            st_mode = orig_lstat_res.st_mode
            st_size = orig_lstat_res.st_size
            st_dev = orig_lstat_res.st_dev
            st_ino = (orig_lstat_res.st_ino or 100) + 999

        lstat_swapped = {"done": False}
        fstat_swapped = {"done": False}

        def guarded_lstat(p: Any) -> Any:
            if not lstat_swapped["done"] and Path(p) == report_file:
                lstat_swapped["done"] = True
                return orig_lstat_res
            return real_lstat(p)

        def guarded_fstat(fd: int) -> Any:
            if not fstat_swapped["done"]:
                fstat_swapped["done"] = True
                return _FakeFstat()
            return real_fstat(fd)

        monkeypatch.setattr(os, "lstat", guarded_lstat)
        monkeypatch.setattr(os, "fstat", guarded_fstat)
        text2, err2 = _read_and_cleanup_report_file(report_file)
        assert text2 is None
        assert err2 == "GITLEAKS_UNSAFE_REPORT_FILE"
        assert not os.path.lexists(report_file)

    def test_report_file_non_regular_and_real_symlink_rejected(
        self, temp_workspace_dir: Path
    ) -> None:
        """Non-regular report paths (directory and real symlink where supported) are rejected."""
        import os

        from app.worker.gitleaks import _read_and_cleanup_report_file

        # Directory cannot be opened/treated as regular report file
        dir_report = temp_workspace_dir / "dir_report.json"
        dir_report.mkdir()
        text, err = _read_and_cleanup_report_file(dir_report)
        assert text is None
        assert err in ("GITLEAKS_UNSAFE_REPORT_FILE", "GITLEAKS_CLEANUP_FAILED")
        if dir_report.exists():
            dir_report.rmdir()

        # Real OS symlink test where filesystem/privileges allow symlinks
        target = temp_workspace_dir / "outside_secret.txt"
        target.write_text("TOP_SECRET_TARGET", encoding="utf-8")
        symlink_report = temp_workspace_dir / "link-report.json"
        try:
            os.symlink(target, symlink_report)
        except OSError:
            pytest.skip("OS or user privileges do not permit creating symlinks in test env")

        text_sym, err_sym = _read_and_cleanup_report_file(symlink_report)
        assert text_sym is None
        assert err_sym == "GITLEAKS_UNSAFE_REPORT_FILE"
        assert not os.path.lexists(symlink_report)
        assert target.read_text(encoding="utf-8") == "TOP_SECRET_TARGET"

    @pytest.mark.parametrize(
        ("cmd_status", "exit_code", "stdout_bytes"),
        [
            (CommandStatus.TIMEOUT, None, b""),
            (CommandStatus.ERROR, None, b""),
            (CommandStatus.OUTPUT_LIMIT_EXCEEDED, None, b""),
            (CommandStatus.EXECUTABLE_NOT_FOUND, None, b""),
            (CommandStatus.NONZERO_EXIT, 2, b""),
            (CommandStatus.SUCCESS, 0, b"{not json"),
            (
                CommandStatus.NONZERO_EXIT,
                1,
                b'[{"RuleID": "github-pat", "File": "src/main.py", "StartLine": 999, "EndLine": 999, "Secret": "ghp_secret1234567890"}]',
            ),
        ],
    )
    def test_report_file_cleaned_up_on_every_execution_outcome(
        self,
        temp_workspace_dir: Path,
        cmd_status: CommandStatus,
        exit_code: int | None,
        stdout_bytes: bytes,
    ) -> None:
        """Ephemeral report files are removed across timeouts, errors, fatal codes, bad JSON, and bad findings."""
        seen_report_paths: list[Path] = []
        seen_workspaces: list[Path] = []

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            report_path = Path(args[args.index("--report-path") + 1])
            seen_report_paths.append(report_path)
            seen_workspaces.append(report_path.parent)
            # Simulate Gitleaks writing sensitive partial report before terminating abnormally
            report_path.write_text(
                '[{"Secret": "ghp_SHOULD_BE_WIPED_ON_ALL_OUTCOMES"}]', encoding="utf-8"
            )
            return CommandResult(
                command=args,
                status=cmd_status,
                exit_code=exit_code,
                stdout=stdout_bytes,
                stderr=b"sensitive stderr detail ghp_LEAK",
                duration_ms=5,
                timed_out=(cmd_status == CommandStatus.TIMEOUT),
                output_limit_exceeded=(cmd_status == CommandStatus.OUTPUT_LIMIT_EXCEEDED),
                executable_not_found=(cmd_status == CommandStatus.EXECUTABLE_NOT_FOUND),
            )

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert "ghp_LEAK" not in (res.error_message or "")
        assert "ghp_SHOULD_BE_WIPED" not in (res.error_message or "")
        assert len(seen_report_paths) == 1
        assert not seen_report_paths[0].exists()
        assert not seen_workspaces[0].exists()

    def test_report_file_cleaned_up_when_runner_raises(self, temp_workspace_dir: Path) -> None:
        """Ephemeral report file and workspace are cleaned up even if runner raises an exception."""
        seen_paths: list[Path] = []

        def raising_runner(args: Any, **kwargs: Any) -> CommandResult:
            report_path = Path(args[args.index("--report-path") + 1])
            seen_paths.append(report_path)
            report_path.write_text('[{"Secret": "ghp_ExceptionCleanupTest"}]', encoding="utf-8")
            raise RuntimeError("boom with secret ghp_ExceptionCleanupTest")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=raising_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        res = adapter.scan(
            ScanJobPayload(files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)])
        )
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_EXECUTION_ERROR"
        assert "ghp_ExceptionCleanupTest" not in (res.error_message or "")
        assert len(seen_paths) == 1
        assert not seen_paths[0].exists()
        assert not seen_paths[0].parent.exists()

    def test_report_cleanup_failure_never_returns_success_or_leaks_content(
        self,
        temp_workspace_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """If ephemeral report unlink fails, failure is surfaced explicitly without logging secrets."""
        secret = "ghp_CleanupFailSecretValue123456"

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            report_path = Path(args[args.index("--report-path") + 1])
            report_path.write_text(json.dumps([]), encoding="utf-8")
            return make_command_result(exit_code=0, stdout="")

        orig_unlink = Path.unlink

        def failing_unlink(self: Path, missing_ok: bool = False) -> None:
            if self.name == "gitleaks-report.json":
                raise PermissionError(f"cannot remove file containing {secret}")
            orig_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", failing_unlink)

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        with caplog.at_level("ERROR"):
            res = adapter.scan(payload)

        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_CLEANUP_FAILED"
        assert secret not in (res.error_message or "")
        assert secret not in caplog.text
        assert "gitleaks-report.json" not in caplog.text

    def test_report_cleanup_failure_on_early_command_failure(
        self,
        temp_workspace_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Early command failures (e.g. timeout) report cleanup failure safely if unlink fails."""
        secret = "ghp_TimeoutCleanupFailSecret1234"

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            report_path = Path(args[args.index("--report-path") + 1])
            report_path.write_text(f'[{{"Secret": "{secret}"}}]', encoding="utf-8")
            return CommandResult(
                command=args,
                status=CommandStatus.TIMEOUT,
                exit_code=None,
                stdout=b"",
                stderr=b"timeout stderr leak " + secret.encode("utf-8"),
                duration_ms=30,
                timed_out=True,
            )

        orig_unlink = Path.unlink

        def failing_unlink(self: Path, missing_ok: bool = False) -> None:
            if self.name == "gitleaks-report.json":
                raise PermissionError(f"cannot unlink {secret}")
            orig_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", failing_unlink)

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        with caplog.at_level("ERROR"):
            res = adapter.scan(payload)

        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_TIMEOUT"
        assert "; ephemeral report cleanup failed" in (res.error_message or "")
        assert secret not in (res.error_message or "")
        assert secret not in caplog.text
        assert "gitleaks-report.json" not in caplog.text

    def test_workspace_cleanup_failure_fails_scan_safely(
        self, temp_workspace_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """StagedWorkspace cleanup failures propagate cleanly and never report scan success."""
        from app.worker.staging import StagedWorkspace, StagingCleanupError

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            return make_command_result(exit_code=0, stdout="[]")

        def fail_cleanup(self: StagedWorkspace) -> None:
            raise StagingCleanupError("simulated leftover files containing sensitive tokens")

        monkeypatch.setattr(StagedWorkspace, "cleanup", fail_cleanup)

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )
        res = adapter.scan(payload)
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_CLEANUP_FAILED"
        assert "sensitive tokens" not in (res.error_message or "")

    def test_executable_trust_production_and_malicious_path_and_symlinks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Production rejects ambient PATH/relative lookup; dev PATH skips relative/CWD/symlinks."""
        import os
        import stat

        from app.core.config import Settings
        from app.worker.gitleaks import _resolve_executable

        trusted_bin_dir = tmp_path / "trusted_bin"
        trusted_bin_dir.mkdir()
        bin_name = "gitleaks.exe" if os.name == "nt" else "gitleaks"
        trusted_bin = trusted_bin_dir / bin_name
        trusted_bin.write_bytes(b"#!/bin/sh\necho ok\n")
        trusted_bin.chmod(0o755)

        cwd_dir = tmp_path / "cwd_hijack"
        cwd_dir.mkdir()
        cwd_evil = cwd_dir / bin_name
        cwd_evil.write_bytes(b"evil")
        cwd_evil.chmod(0o755)

        rel_dir = tmp_path / "rel_hijack"
        rel_dir.mkdir()
        (rel_dir / bin_name).write_bytes(b"evil_rel")
        (rel_dir / bin_name).chmod(0o755)

        monkeypatch.chdir(cwd_dir)

        # 1. Production mode rejects bare PATH command even if binary is on PATH
        prod_settings = Settings(
            APP_ENV="production",
            SECRET_KEY="12345678901234567890123456789012",
            SESSION_SECRET="abcdef0123456789abcdef0123456789",
            FINGERPRINT_KEY="fedcba9876543210fedcba9876543210",
            GITLEAKS_PATH=str(trusted_bin),
        )
        monkeypatch.setattr("app.worker.gitleaks.get_settings", lambda: prod_settings)
        monkeypatch.setenv("PATH", str(trusted_bin_dir))

        assert _resolve_executable("gitleaks") is None
        assert _resolve_executable(f"./{bin_name}") is None
        assert _resolve_executable(trusted_bin) == os.path.abspath(trusted_bin)

        # Adapter using real run_command_bounded refuses ambient PATH in production
        prod_adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            workspace_base_dir=tmp_path / "ws",
        )
        prod_res = prod_adapter.scan(
            ScanJobPayload(files=[ScannedFile(path="app.py", content="x=1\n", scanned=True)])
        )
        assert prod_res.status == ScanStatus.FAILED
        assert prod_res.error_code == "GITLEAKS_BINARY_NOT_FOUND"

        # 2. Malicious PATH (CWD-only, empty entries, '.', relative dirs, UNC) must never match
        monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "..", "rel_hijack", r"\\evil\share"]))
        assert _resolve_executable("gitleaks", allow_path_lookup=True) is None

        # Prepending malicious '.' before trusted_bin_dir still resolves ONLY trusted_bin
        monkeypatch.setenv("PATH", os.pathsep.join([".", "", str(trusted_bin_dir)]))
        assert _resolve_executable("gitleaks", allow_path_lookup=True) == os.path.abspath(
            trusted_bin
        )

        # 3. Invalid executables rejected
        assert _resolve_executable(trusted_bin_dir) is None
        assert _resolve_executable(r"\\evil-server\share\gitleaks.exe") is None
        assert _resolve_executable("https://evil.example/gitleaks") is None
        if os.name != "nt":
            non_exec = tmp_path / "not_exec_gitleaks"
            non_exec.write_text("echo nope\n", encoding="utf-8")
            non_exec.chmod(0o644)
            assert _resolve_executable(non_exec) is None

            world_writable = tmp_path / "ww_gitleaks"
            world_writable.write_text("#!/bin/sh\n", encoding="utf-8")
            world_writable.chmod(0o777)
            assert _resolve_executable(world_writable) is None

        # 4. Symlink executable policy: rejected both by explicit symlink check and OS symlink
        symlink_bin = tmp_path / ("sym_" + bin_name)
        monkeypatch.setattr(Path, "is_symlink", lambda self: self == symlink_bin)
        symlink_bin.write_bytes(b"target")
        symlink_bin.chmod(0o755)
        assert _resolve_executable(symlink_bin) is None
        monkeypatch.undo()

        # Re-establish real symlink test if OS allows it
        real_sym = tmp_path / ("real_sym_" + bin_name)
        try:
            os.symlink(trusted_bin, real_sym)
        except OSError:
            pass
        else:
            assert stat.S_ISLNK(os.lstat(real_sym).st_mode)
            assert _resolve_executable(real_sym) is None

    def test_rule_id_partial_and_full_secret_sanitized_with_deterministic_fingerprint(
        self, temp_workspace_dir: Path
    ) -> None:
        """Full/partial secrets in RuleID are scrubbed cleanly while preserving useful rule context and fingerprints."""
        stripe_prefix_parts = ["sk", "live", ""]
        stripe_prefix = "_".join(stripe_prefix_parts)
        frag_middle = "SuperSecretToken"
        frag_tail = "9876543210"
        secret = f"{stripe_prefix}{frag_middle}{frag_tail}"

        def make_adapter(line_offset: int = 0) -> GitleaksScannerAdapter:
            def runner_fn(args: Any, **kwargs: Any) -> CommandResult:
                raw_findings = [
                    # Full secret used directly as RuleID
                    {
                        "RuleID": secret,
                        "File": "src/a.py",
                        "StartLine": 1 + line_offset,
                        "EndLine": 1 + line_offset,
                        "Secret": secret,
                        "Description": f"Leaked {frag_middle}",
                    },
                    # Partial secret embedded inside RuleID while preserving rule name prefix
                    {
                        "RuleID": f"custom-stripe-{frag_middle}-check",
                        "File": "src/a.py",
                        "StartLine": 2 + line_offset,
                        "EndLine": 2 + line_offset,
                        "Secret": secret,
                        "Description": "Custom rule finding",
                    },
                    # Benign legitimate rule remains untouched
                    {
                        "RuleID": "stripe-access-token",
                        "File": "src/a.py",
                        "StartLine": 3 + line_offset,
                        "EndLine": 3 + line_offset,
                        "Secret": secret,
                        "Description": "Stripe Access Token",
                    },
                ]
                return make_command_result(exit_code=1, stdout=json.dumps(raw_findings))

            return GitleaksScannerAdapter(
                executable_path="gitleaks",
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=runner_fn,
                workspace_base_dir=temp_workspace_dir,
            )

        content_v1 = f"k1 = '{secret}'\nk2 = '{secret}'\nk3 = '{secret}'\n"
        # Same code shifted down by 3 blank lines must produce identical fingerprints
        content_v2 = "\n\n\n" + content_v1

        res1 = make_adapter(0).scan(
            ScanJobPayload(files=[ScannedFile(path="a.py", content=content_v1, scanned=True)])
        )
        res2 = make_adapter(3).scan(
            ScanJobPayload(files=[ScannedFile(path="a.py", content=content_v2, scanned=True)])
        )

        assert res1.status == ScanStatus.SUCCEEDED
        assert res2.status == ScanStatus.SUCCEEDED
        assert len(res1.findings) == 3
        assert len(res2.findings) == 3

        f_full, f_partial, f_clean = res1.findings
        for finding in res1.findings:
            dumped = finding.model_dump_json()
            assert secret not in dumped
            assert frag_middle not in dumped
            assert frag_tail not in dumped
            assert stripe_prefix not in finding.rule_id
            assert stripe_prefix not in finding.snippet

        assert f_full.rule_id.startswith("redacted-rule-")
        assert f_partial.rule_id.startswith("custom-stripe-redacted-check-")
        assert f_full.rule_id != f_partial.rule_id
        assert f_clean.rule_id == "stripe-access-token"
        assert "[REDACTED:stripe-access-token]" in f_clean.snippet

        # Deterministic fingerprinting invariant across line shifts
        for a, b in zip(res1.findings, res2.findings, strict=True):
            assert a.rule_id == b.rule_id
            assert a.fingerprint == b.fingerprint

    def test_custom_config_validation_trusted_paths_size_symlinks_and_toml(
        self, temp_workspace_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Custom Gitleaks configs must stay inside trusted dirs, avoid symlinks/oversize/remote directives."""
        import os

        import app.worker.gitleaks as gitleaks_mod

        trusted_dir = tmp_path / "rules" / "gitleaks"
        trusted_dir.mkdir(parents=True)
        untrusted_dir = tmp_path / "untrusted"
        untrusted_dir.mkdir(parents=True)

        runner_calls: list[Any] = []

        def tracking_runner(args: Any, **kwargs: Any) -> CommandResult:
            runner_calls.append(args)
            return make_command_result(exit_code=0, stdout="[]")

        payload = ScanJobPayload(
            files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]
        )

        # 1. Valid local TOML including legitimate URL-matching regex passes
        valid_toml = trusted_dir / "valid.toml"
        valid_toml.write_text(
            'title = "Sentinel Rules"\n\n'
            "[[rules]]\n"
            'id = "url-creds"\n'
            'description = "Credentials in URL"\n'
            "regex = '''https?://[^:]+:[^@]+@'''\n",
            encoding="utf-8",
        )
        ok_adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            config_path=valid_toml,
            trusted_config_dirs=[trusted_dir],
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=tracking_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        ok_res = ok_adapter.scan(payload)
        assert ok_res.status == ScanStatus.SUCCEEDED
        assert len(runner_calls) == 1
        assert "--config" in runner_calls[0]

        runner_calls.clear()

        # 2. Untrusted location rejected BEFORE calling runner
        outside_toml = untrusted_dir / "outside.toml"
        outside_toml.write_text('title = "Evil"\n', encoding="utf-8")
        # 3. Non-.toml extension inside trusted dir rejected
        non_toml = trusted_dir / "rules.yaml"
        non_toml.write_text("rules: []\n", encoding="utf-8")
        # 4. External [extend] URL and [extend] path rejected
        extend_url_toml = trusted_dir / "extend_url.toml"
        extend_url_toml.write_text(
            '[extend]\nurl = "https://attacker.example/base.toml"\n', encoding="utf-8"
        )
        extend_path_toml = trusted_dir / "extend_path.toml"
        extend_path_toml.write_text(
            '[extend]\npath = "../untrusted/outside.toml"\n', encoding="utf-8"
        )
        include_toml = trusted_dir / "include.toml"
        include_toml.write_text('include = ["other.toml"]\n', encoding="utf-8")
        # 5. Malformed TOML syntax & invalid UTF-8 rejected
        bad_toml = trusted_dir / "broken.toml"
        bad_toml.write_text("[rules\nbroken = ", encoding="utf-8")
        bad_utf8_toml = trusted_dir / "bad_utf8.toml"
        bad_utf8_toml.write_bytes(b"\xff\xfe[extend]\n")

        bad_configs: list[str | Path] = [
            "s3://bucket/gitleaks.toml",
            "file:///etc/gitleaks.toml",
            r"\\server\share\gitleaks.toml",
            outside_toml,
            non_toml,
            extend_url_toml,
            extend_path_toml,
            include_toml,
            bad_toml,
            bad_utf8_toml,
        ]

        for bad_cfg in bad_configs:
            bad_adapter = GitleaksScannerAdapter(
                executable_path="gitleaks",
                config_path=bad_cfg,
                trusted_config_dirs=[trusted_dir],
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=tracking_runner,
                workspace_base_dir=temp_workspace_dir,
            )
            bad_res = bad_adapter.scan(payload)
            assert bad_res.status == ScanStatus.FAILED, f"Expected failure for {bad_cfg}"
            assert bad_res.error_code == "GITLEAKS_INVALID_CONFIG_PATH"
        assert runner_calls == []

        # 6. Oversized TOML rejected
        monkeypatch.setattr(gitleaks_mod, "_MAX_CONFIG_FILE_BYTES", 64)
        oversized_toml = trusted_dir / "big.toml"
        oversized_toml.write_text('title = "' + ("a" * 100) + '"\n', encoding="utf-8")
        big_res = GitleaksScannerAdapter(
            executable_path="gitleaks",
            config_path=oversized_toml,
            trusted_config_dirs=[trusted_dir],
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=tracking_runner,
            workspace_base_dir=temp_workspace_dir,
        ).scan(payload)
        assert big_res.status == ScanStatus.FAILED
        assert big_res.error_code == "GITLEAKS_INVALID_CONFIG_PATH"
        monkeypatch.undo()

        # 7. Symlink TOML rejected (simulated is_symlink + real symlink where supported)
        sym_cfg = trusted_dir / "sym.toml"
        sym_cfg.write_text('title = "Link"\n', encoding="utf-8")
        monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "sym.toml")
        sym_res = GitleaksScannerAdapter(
            executable_path="gitleaks",
            config_path=sym_cfg,
            trusted_config_dirs=[trusted_dir],
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=tracking_runner,
            workspace_base_dir=temp_workspace_dir,
        ).scan(payload)
        assert sym_res.status == ScanStatus.FAILED
        assert sym_res.error_code == "GITLEAKS_INVALID_CONFIG_PATH"
        monkeypatch.undo()

        real_sym_cfg = trusted_dir / "real_sym.toml"
        try:
            os.symlink(outside_toml, real_sym_cfg)
        except OSError:
            pass
        else:
            real_sym_res = GitleaksScannerAdapter(
                executable_path="gitleaks",
                config_path=real_sym_cfg,
                trusted_config_dirs=[trusted_dir],
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=tracking_runner,
                workspace_base_dir=temp_workspace_dir,
            ).scan(payload)
            assert real_sym_res.status == ScanStatus.FAILED
            assert real_sym_res.error_code == "GITLEAKS_INVALID_CONFIG_PATH"

    def test_metadata_and_secret_fragment_sanitization_all_fields(
        self, temp_workspace_dir: Path
    ) -> None:
        """Secret fragments cannot leak through Description, Tags, Snippet, raw dict keys/values, or other fields."""
        from app.worker.gitleaks import _sanitize_metadata, _sanitize_metadata_node

        secret = "tok_live_AlphaFrag99_OmegaFrag88"
        frag_a = "AlphaFrag99"
        frag_b = "OmegaFrag88"
        frag_prefix = "tok_live_Alpha"

        # Direct unit checks on metadata sanitizers
        nested = {
            f"key_{frag_a}": f"value with {frag_b} and {frag_prefix}",
            "nested": [{"note": f"prefix={frag_prefix}", "safe": "retain-me"}],
            "tags": ["pci-dss", f"tag_{frag_a}", frag_b],
        }
        cleaned_node = _sanitize_metadata_node(nested, secret_to_scrub=secret)
        assert frag_a not in str(cleaned_node)
        assert frag_b not in str(cleaned_node)
        assert frag_prefix not in str(cleaned_node)
        assert "retain-me" in str(cleaned_node)

        cleaned_meta = _sanitize_metadata(nested, secret_to_scrub=secret)
        assert frag_a not in json.dumps(cleaned_meta)
        assert frag_b not in json.dumps(cleaned_meta)
        assert frag_prefix not in json.dumps(cleaned_meta)

        def mock_runner(**kwargs: Any) -> CommandResult:
            findings = [
                {
                    "RuleID": "custom-api-token",
                    "Description": f"Found {frag_a} and trailing {frag_b} in app",
                    "File": "src/cfg.py",
                    "StartLine": 1,
                    "EndLine": 1,
                    "Secret": secret,
                    "Tags": ["high", "pci-dss", f"x-{frag_a}", frag_b],
                    "Entropy": 4.9,
                }
            ]
            return make_command_result(exit_code=1, stdout=json.dumps(findings))

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        res = adapter.scan(
            ScanJobPayload(
                files=[ScannedFile(path="cfg.py", content=f'API = "{secret}"\n', scanned=True)]
            )
        )
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 1
        finding = res.findings[0]
        dumped = finding.model_dump_json()

        for forbidden in (secret, frag_a, frag_b, frag_prefix):
            assert forbidden not in dumped
            assert forbidden not in finding.title
            assert forbidden not in finding.description
            assert forbidden not in finding.snippet
            assert forbidden not in finding.fingerprint
            assert forbidden not in finding.remediation
            assert forbidden not in str(finding.raw)

        # Safe metadata and severity remain usable
        assert finding.severity.value == "high"
        assert finding.raw["tags"] == ["high", "pci-dss"]
        assert "Found [REDACTED] and trailing [REDACTED] in app" in finding.description

    def test_stdout_fallback_invalid_utf8_strict_error(self, temp_workspace_dir: Path) -> None:
        """Stdout fallback uses strict UTF-8 decoding and fails cleanly on invalid byte sequences."""

        def mock_runner(args: Any, **kwargs: Any) -> CommandResult:
            # Leave report_file absent so adapter falls back to stdout
            return CommandResult(
                command=args,
                status=CommandStatus.NONZERO_EXIT,
                exit_code=1,
                stdout=b'[{"RuleID": "test", "Secret": "\xff\xfe"}]',
                stderr=b"",
                duration_ms=1,
            )

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        res = adapter.scan(
            ScanJobPayload(files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)])
        )
        assert res.status == ScanStatus.FAILED
        assert res.error_code == "GITLEAKS_INVALID_REPORT_ENCODING"

    def test_multiline_coordinates_boundary_and_long_secret_truncation_redaction(
        self, temp_workspace_dir: Path
    ) -> None:
        """Multi-line coordinates validate start/end lines independently and 15-line truncated snippets stay fully redacted."""
        body_lines = [f"MIIEBodyLine{i:02d}SecretChunkXYZ123" for i in range(1, 14)]
        pem_secret = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "\n".join(body_lines)
            + "\n-----END RSA PRIVATE KEY-----"
        )
        # File lines:
        # Line 1: prefix + PEM header (col 10..end), Line 2..14: body lines, Line 15: PEM end (col 1..30)
        file_content = (
            'PRIV = """-----BEGIN RSA PRIVATE KEY-----\n'
            + "\n".join(body_lines)
            + '\n-----END RSA PRIVATE KEY-----"""\n'
        )
        total_lines = len(file_content.splitlines())
        end_line_len = len(file_content.splitlines()[total_lines - 1])

        def make_res_for_finding(item: dict[str, Any]) -> Any:
            def runner_fn(**kwargs: Any) -> CommandResult:
                return make_command_result(exit_code=1, stdout=json.dumps([item]))

            return GitleaksScannerAdapter(
                executable_path="gitleaks",
                fingerprint_key=TEST_FINGERPRINT_KEY,
                runner=runner_fn,
                workspace_base_dir=temp_workspace_dir,
            ).scan(
                ScanJobPayload(
                    files=[ScannedFile(path="key.py", content=file_content, scanned=True)]
                )
            )

        # 1. Valid multi-line finding where StartColumn (43) > EndColumn (31) and span exceeds 12 lines
        valid_res = make_res_for_finding(
            {
                "RuleID": "private-key",
                "File": "src/key.py",
                "StartLine": 1,
                "EndLine": total_lines,
                "StartColumn": 11,
                "EndColumn": end_line_len + 1,  # boundary exclusive end col allowed
                "Secret": pem_secret,
                "Description": "Asymmetric Private Key",
            }
        )
        assert valid_res.status == ScanStatus.SUCCEEDED
        assert len(valid_res.findings) == 1
        finding = valid_res.findings[0]
        for body_ln in body_lines[:11]:
            assert body_ln not in finding.snippet
        assert "[REDACTED:private-key]" in finding.snippet

        # 2. Boundary failures on multi-line spans
        invalid_items = [
            # EndColumn out of range for EndLine
            {
                "RuleID": "private-key",
                "File": "src/key.py",
                "StartLine": 1,
                "EndLine": 3,
                "StartColumn": 5,
                "EndColumn": len(file_content.splitlines()[2]) + 2,
                "Secret": body_lines[0],
            },
            # StartColumn out of range for StartLine
            {
                "RuleID": "private-key",
                "File": "src/key.py",
                "StartLine": 2,
                "EndLine": 3,
                "StartColumn": len(file_content.splitlines()[1]) + 2,
                "EndColumn": 5,
                "Secret": body_lines[0],
            },
            # EndLine > file line count
            {
                "RuleID": "private-key",
                "File": "src/key.py",
                "StartLine": 1,
                "EndLine": total_lines + 1,
                "Secret": body_lines[0],
            },
            # Boolean coordinate rejected
            {
                "RuleID": "private-key",
                "File": "src/key.py",
                "StartLine": 1,
                "EndLine": 2,
                "EndColumn": True,
                "Secret": body_lines[0],
            },
        ]
        for bad_item in invalid_items:
            bad_res = make_res_for_finding(bad_item)
            assert bad_res.status == ScanStatus.FAILED
            assert bad_res.error_code == "GITLEAKS_NORMALIZATION_FAILED"

    def test_cross_finding_same_line_and_window_secrets_fully_redacted(
        self, temp_workspace_dir: Path
    ) -> None:
        """Two-pass normalization scrubs co-located secrets across same-line, 12-line window, and overlap cases."""
        secret_a = "custom_alpha_tok_77889911"
        secret_b = "custom_beta_pwd_44556622"
        overlap_1 = "tok_live_SHARED888_ALPHA11"
        overlap_2 = "SHARED888_BETA22_END99"

        # Case 1: Two distinct non-pattern secrets on the SAME line + another in a 12-line window
        content_same_and_window = (
            f'ALPHA = "{secret_a}"; BETA = "{secret_b}"\n'
            "SAFE_VAR = 'benign-config'\n"
            "DEBUG_FLAG = False\n"
            "RETRY_COUNT = 3\n"
            f'OVERLAP = "{overlap_1}" + "{overlap_2}"\n'
        )
        raw_findings = [
            {
                "RuleID": "custom-alpha-rule",
                "Description": "Alpha rule",
                "File": "app/config.py",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 10,
                "EndColumn": 35,
                "Secret": secret_a,
            },
            {
                "RuleID": "custom-beta-rule",
                "Description": "Beta rule",
                "File": "app/config.py",
                "StartLine": 1,
                "EndLine": 3,
                "StartColumn": 45,
                "EndColumn": 12,
                "Secret": secret_b,
            },
            {
                "RuleID": "overlap-rule-1",
                "Description": "Overlap 1",
                "File": "app/config.py",
                "StartLine": 1,
                "EndLine": 5,
                "Secret": overlap_1,
            },
            {
                "RuleID": "overlap-rule-2",
                "Description": "Overlap 2",
                "File": "app/config.py",
                "StartLine": 5,
                "EndLine": 5,
                "Secret": overlap_2,
            },
        ]

        def runner_factory(args: Any, **kwargs: Any) -> CommandResult:
            report_path = Path(args[args.index("--report-path") + 1])
            report_path.write_text(json.dumps(raw_findings), encoding="utf-8")
            return make_command_result(exit_code=1, stdout="[]")

        payload = ScanJobPayload(
            files=[ScannedFile(path="app/config.py", content=content_same_and_window, scanned=True)]
        )
        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=runner_factory,
            workspace_base_dir=temp_workspace_dir,
        )
        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 4

        sensitive_needles = [
            secret_a,
            secret_b,
            overlap_1,
            overlap_2,
            "alpha_tok_778899",
            "beta_pwd_445566",
            "SHARED888",
            "ALPHA11",
            "BETA22_END99",
        ]
        for finding in res.findings:
            dumped = finding.model_dump_json()
            for needle in sensitive_needles:
                assert needle not in dumped
            assert "[REDACTED:" in finding.snippet

        # Benign prose on same line / window stays intact
        assert 'ALPHA = "' in res.findings[0].snippet
        assert 'BETA = "' in res.findings[0].snippet
        assert "SAFE_VAR = 'benign-config'" in res.findings[1].snippet

        # Deterministic fingerprints on repeated runs
        res_repeat = adapter.scan(payload)
        assert [f.fingerprint for f in res_repeat.findings] == [f.fingerprint for f in res.findings]
        assert len({f.fingerprint for f in res.findings}) == 4

    def test_cross_finding_field_leakage_and_deterministic_dedup(
        self, temp_workspace_dir: Path
    ) -> None:
        """Secrets from another finding in the same file are scrubbed across descriptions/tags/raw/RuleID."""
        secret_1 = "CustomSecretOne_998811"
        secret_2 = "CustomSecretTwo_776622"
        content = f'ONE = "{secret_1}"\nTWO = "{secret_2}"\n'

        raw_findings = [
            {
                "RuleID": f"rule-with-{secret_2}",
                "Description": f"Found token {secret_2} and fragment One_998811 in code",
                "Tags": ["high", f"tag_{secret_2}", "audit-ok"],
                "File": "src/keys.py",
                "StartLine": 1,
                "EndLine": 1,
                "Secret": secret_1,
            },
            # Exact duplicate of finding 1 should deduplicate identically
            {
                "RuleID": f"rule-with-{secret_2}",
                "Description": f"Found token {secret_2} and fragment One_998811 in code",
                "Tags": ["high", f"tag_{secret_2}", "audit-ok"],
                "File": "src/keys.py",
                "StartLine": 1,
                "EndLine": 1,
                "Secret": secret_1,
            },
            {
                "RuleID": "second-key",
                "Description": "Second secret",
                "File": "src/keys.py",
                "StartLine": 2,
                "EndLine": 2,
                "Secret": secret_2,
            },
        ]

        def runner_factory(args: Any, **kwargs: Any) -> CommandResult:
            report_path = Path(args[args.index("--report-path") + 1])
            report_path.write_text(json.dumps(raw_findings), encoding="utf-8")
            return make_command_result(exit_code=1, stdout="[]")

        payload = ScanJobPayload(
            files=[ScannedFile(path="src/keys.py", content=content, scanned=True)]
        )
        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=runner_factory,
            workspace_base_dir=temp_workspace_dir,
        )
        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 2

        f1 = res.findings[0]
        dumped = f1.model_dump_json()
        for leak in (secret_1, secret_2, "SecretOne_99", "SecretTwo_77", "One_998811"):
            assert leak not in dumped
        assert "audit-ok" in f1.raw.get("tags", [])

    def test_untrusted_repo_control_files_excluded_and_default_config_materialized(
        self, temp_workspace_dir: Path
    ) -> None:
        """Repo .gitleaks.toml/.gitleaksignore are excluded without payload mutation and default config is materialized."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE2"
        repo_toml = ScannedFile(
            path=".gitleaks.toml",
            content='[allowlist]\nregexes = [".*"]\n',
            scanned=True,
        )
        repo_ignore = ScannedFile(
            path="nested/.gitleaksignore",
            content="aws-access-token\n",
            scanned=True,
        )
        app_file = ScannedFile(
            path="app/secrets.py",
            content=f'KEY = "{raw_secret}"\n',
            scanned=True,
        )
        payload = ScanJobPayload(files=[repo_toml, repo_ignore, app_file])

        observed: dict[str, Any] = {}

        def inspect_runner(args: Any, **kwargs: Any) -> CommandResult:
            cfg_idx = args.index("--config")
            cfg_path = Path(args[cfg_idx + 1])
            src_dir = Path(args[args.index("--source") + 1])
            ws_dir = src_dir.parent

            observed["cfg_path"] = cfg_path
            observed["cfg_parent"] = cfg_path.parent
            observed["ws_dir"] = ws_dir
            observed["cfg_text"] = cfg_path.read_text(encoding="utf-8")
            observed["staged_files"] = [
                p.relative_to(src_dir).as_posix() for p in src_dir.rglob("*") if p.is_file()
            ]
            report_path = Path(args[args.index("--report-path") + 1])
            report_path.write_text(
                json.dumps(
                    [
                        {
                            "RuleID": "aws-access-token",
                            "File": "app/secrets.py",
                            "StartLine": 1,
                            "EndLine": 1,
                            "Secret": raw_secret,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            return make_command_result(exit_code=1, stdout="[]")

        adapter = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=inspect_runner,
            workspace_base_dir=temp_workspace_dir,
        )
        res = adapter.scan(payload)
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 1

        # Materialized config was placed inside workspace root (outside source_dir) and uses Sentinel default TOML
        assert observed["cfg_parent"] == observed["ws_dir"]
        assert observed["cfg_path"].name == "gitleaks-config.toml"
        assert "Sentinel Default Gitleaks Configuration" in observed["cfg_text"]
        assert "useDefault = true" in observed["cfg_text"]

        # Only normal source files hit workspace.source_dir; control files excluded
        assert observed["staged_files"] == ["app/secrets.py"]
        assert repo_toml.scanned is True
        assert repo_ignore.scanned is True

        # Payload containing only excluded repo control files succeeds cleanly without invoking scanner
        called_only_control = False

        def fail_if_called(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal called_only_control
            called_only_control = True
            return make_command_result(exit_code=0, stdout="[]")

        res_only_ctrl = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=fail_if_called,
            workspace_base_dir=temp_workspace_dir,
        ).scan(ScanJobPayload(files=[repo_toml, repo_ignore]))
        assert res_only_ctrl.status == ScanStatus.SUCCEEDED
        assert res_only_ctrl.findings == []
        assert called_only_control is False

    def test_missing_or_invalid_default_config_fails_closed(
        self, temp_workspace_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing or unsafe GITLEAKS_CONFIG_PATH fails closed without invoking runner."""
        from app.core.config import Settings

        called = False

        def never_run(args: Any, **kwargs: Any) -> CommandResult:
            nonlocal called
            called = True
            return make_command_result(exit_code=0, stdout="[]")

        payload = ScanJobPayload(
            files=[ScannedFile(path="app.py", content="x = 1\n", scanned=True)]
        )

        # 1. Missing config inside configured trusted dir
        trusted_dir = tmp_path / "trusted_gitleaks"
        trusted_dir.mkdir()
        monkeypatch.setattr(
            "app.worker.gitleaks.get_settings",
            lambda: Settings(
                GITLEAKS_CONFIG_PATH=str(trusted_dir / "missing.toml"),
                GITLEAKS_TRUSTED_CONFIG_DIR=str(trusted_dir),
            ),
        )
        res_missing = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=never_run,
            workspace_base_dir=temp_workspace_dir,
        ).scan(payload)
        assert res_missing.status == ScanStatus.FAILED
        assert res_missing.error_code == "GITLEAKS_CONFIG_NOT_FOUND"
        assert called is False

        # 2. Invalid/network directive in default config
        bad_default = trusted_dir / "bad_default.toml"
        bad_default.write_text(
            '[extend]\nurl = "https://evil.example/base.toml"\n', encoding="utf-8"
        )
        monkeypatch.setattr(
            "app.worker.gitleaks.get_settings",
            lambda: Settings(
                GITLEAKS_CONFIG_PATH=str(bad_default),
                GITLEAKS_TRUSTED_CONFIG_DIR=str(trusted_dir),
            ),
        )
        res_invalid = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=never_run,
            workspace_base_dir=temp_workspace_dir,
        ).scan(payload)
        assert res_invalid.status == ScanStatus.FAILED
        assert res_invalid.error_code == "GITLEAKS_INVALID_CONFIG_PATH"
        assert called is False

    def test_config_and_executable_trust_boundaries_and_toctou_isolation(
        self, temp_workspace_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SEMGREP_RULES_PATH is excluded, broad trusted dirs/unsafe ancestors fail, and config is isolated."""
        import os
        import stat as stat_mod
        import tempfile

        from app.core.config import Settings
        from app.worker.gitleaks import _resolve_executable, _validate_and_load_config

        # 1. SEMGREP_RULES_PATH parent directory must NOT be trusted for Gitleaks configs
        semgrep_dir = tmp_path / "semgrep_rules"
        semgrep_dir.mkdir()
        stray_toml = semgrep_dir / "rogue.toml"
        stray_toml.write_text('title = "Rogue"\n', encoding="utf-8")

        monkeypatch.setattr(
            "app.worker.gitleaks.get_settings",
            lambda: Settings(SEMGREP_RULES_PATH=str(semgrep_dir / "default.yaml")),
        )
        path_res, cfg_bytes, err_code, _ = _validate_and_load_config(stray_toml)
        assert path_res is None and cfg_bytes is None
        assert err_code == "GITLEAKS_INVALID_CONFIG_PATH"
        monkeypatch.undo()

        # 2. Broad trusted config directories (filesystem root, temp root, CWD) are rejected
        trusted_sub = tmp_path / "trusted_cfg"
        trusted_sub.mkdir()
        valid_toml = trusted_sub / "valid.toml"
        valid_toml.write_text('title = "Safe"\n', encoding="utf-8")
        for broad_dir in (
            Path(os.path.abspath("/")),
            Path(os.path.abspath(tempfile.gettempdir())),
            Path.cwd(),
        ):
            r_path, r_bytes, r_err, _ = _validate_and_load_config(
                valid_toml, trusted_config_dirs=[broad_dir]
            )
            assert r_path is None and r_bytes is None
            assert r_err == "GITLEAKS_INVALID_CONFIG_PATH"

        # 3. Ancestor symlink and world-writable ancestor directory rejected for config AND executable
        anc_dir = tmp_path / "ww_ancestor" / "sub_trusted"
        anc_dir.mkdir(parents=True)
        anc_cfg = anc_dir / "cfg.toml"
        anc_cfg.write_text('title = "Safe"\n', encoding="utf-8")
        bin_name = "gitleaks.exe" if os.name == "nt" else "gitleaks"
        anc_bin = anc_dir / bin_name
        anc_bin.write_bytes(b"#!/bin/sh\necho ok\n")
        anc_bin.chmod(0o755)

        real_lstat = os.lstat

        def fake_ww_ancestor_lstat(p: Any, *args: Any, **kwargs: Any) -> Any:
            res = list(real_lstat(p, *args, **kwargs))
            if Path(p) == tmp_path / "ww_ancestor":
                res[0] = (res[0] & ~0o777) | stat_mod.S_IFDIR | 0o777  # non-sticky 0777
            return os.stat_result(res)

        monkeypatch.setattr("app.worker.gitleaks._is_posix_platform", lambda: True)
        monkeypatch.setattr(os, "lstat", fake_ww_ancestor_lstat)
        _, _, anc_err, _ = _validate_and_load_config(anc_cfg, trusted_config_dirs=[anc_dir])
        assert anc_err == "GITLEAKS_INVALID_CONFIG_PATH"
        assert _resolve_executable(anc_bin) is None
        monkeypatch.undo()

        # Sticky-bit parent ancestor (e.g. Linux /tmp 01777) IS allowed above trusted subdirs
        def fake_sticky_tmp_ancestor_lstat(p: Any, *args: Any, **kwargs: Any) -> Any:
            import stat as st_m

            res = list(real_lstat(p, *args, **kwargs))
            p_obj = Path(p)
            if p_obj == tmp_path / "ww_ancestor":
                res[0] = st_m.S_IFDIR | 0o1777
            elif st_m.S_ISDIR(res[0]):
                res[0] = st_m.S_IFDIR | 0o755
            elif p_obj == anc_bin:
                res[0] = st_m.S_IFREG | 0o755
            else:
                res[0] = st_m.S_IFREG | 0o644
            return os.stat_result(res)

        real_fstat = os.fstat

        def fake_sticky_tmp_fstat(fd: int) -> os.stat_result:
            import stat as st_m

            res = list(real_fstat(fd))
            res[0] = st_m.S_IFREG | 0o644
            return os.stat_result(res)

        monkeypatch.setattr("app.worker.gitleaks._is_posix_platform", lambda: True)
        monkeypatch.setattr(os, "lstat", fake_sticky_tmp_ancestor_lstat)
        monkeypatch.setattr(os, "fstat", fake_sticky_tmp_fstat)
        monkeypatch.setattr(os, "access", lambda _p, _m: True)
        ok_cfg, ok_bytes, ok_err, _ = _validate_and_load_config(
            anc_cfg, trusted_config_dirs=[anc_dir]
        )
        assert ok_err is None and ok_cfg == anc_cfg and ok_bytes is not None
        assert _resolve_executable(anc_bin) == os.path.abspath(anc_bin)
        monkeypatch.undo()

        # Symlinked ancestor directory rejected for both config and executable
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda self: self == (tmp_path / "ww_ancestor"),
        )
        _, _, sym_anc_err, _ = _validate_and_load_config(anc_cfg, trusted_config_dirs=[anc_dir])
        assert sym_anc_err == "GITLEAKS_INVALID_CONFIG_PATH"
        assert _resolve_executable(anc_bin) is None
        monkeypatch.undo()

        # 4. Inode swap TOCTOU during config open fails closed
        def swap_fstat(_fd: int) -> os.stat_result:
            st = list(real_lstat(valid_toml))
            st[1] = (st[1] or 100) + 999  # force st_ino mismatch
            return os.stat_result(st)

        monkeypatch.setattr(os, "fstat", swap_fstat)
        _, _, toctou_err, _ = _validate_and_load_config(
            valid_toml, trusted_config_dirs=[trusted_sub]
        )
        assert toctou_err == "GITLEAKS_INVALID_CONFIG_PATH"
        monkeypatch.undo()

        # 5. Materialized config prevents post-validation source mutation from affecting runner
        runner_seen_text: list[str] = []

        def mutating_source_runner(args: Any, **kwargs: Any) -> CommandResult:
            cfg_arg = Path(args[args.index("--config") + 1])
            # Mutate the source TOML after validation - materialized copy in workspace stays clean
            valid_toml.write_text(
                '[extend]\nurl = "https://attacker.example/tamper"\n', encoding="utf-8"
            )
            runner_seen_text.append(cfg_arg.read_text(encoding="utf-8"))
            assert cfg_arg != valid_toml
            return make_command_result(exit_code=0, stdout="[]")

        iso_res = GitleaksScannerAdapter(
            executable_path="gitleaks",
            config_path=valid_toml,
            trusted_config_dirs=[trusted_sub],
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=mutating_source_runner,
            workspace_base_dir=temp_workspace_dir,
        ).scan(ScanJobPayload(files=[ScannedFile(path="main.py", content="x = 1\n", scanned=True)]))
        assert iso_res.status == ScanStatus.SUCCEEDED
        assert runner_seen_text == ['title = "Safe"\n']

    def test_near_cap_snippet_redaction_expansion_clamped_to_schema_limit(
        self, temp_workspace_dir: Path
    ) -> None:
        """Snippets expanded past 2000 chars by [REDACTED:<rule_id>] are safely re-clamped."""
        short_secret = "s3cr3t99"
        long_rule = "very-long-custom-rule-identifier-for-redaction-expansion-test"
        long_line = f'TOKEN = "{short_secret}"; PAD = "' + ("x" * 1970) + '"\n'
        assert 1985 <= len(long_line.rstrip("\n")) <= 2000

        def runner_fn(args: Any, **kwargs: Any) -> CommandResult:
            report_path = Path(args[args.index("--report-path") + 1])
            report_path.write_text(
                json.dumps(
                    [
                        {
                            "RuleID": long_rule,
                            "File": "app/long_line.py",
                            "StartLine": 1,
                            "EndLine": 1,
                            "Secret": short_secret,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            return make_command_result(exit_code=1, stdout="[]")

        res = GitleaksScannerAdapter(
            executable_path="gitleaks",
            fingerprint_key=TEST_FINGERPRINT_KEY,
            runner=runner_fn,
            workspace_base_dir=temp_workspace_dir,
        ).scan(
            ScanJobPayload(
                files=[ScannedFile(path="app/long_line.py", content=long_line, scanned=True)]
            )
        )
        assert res.status == ScanStatus.SUCCEEDED
        assert len(res.findings) == 1
        finding = res.findings[0]
        assert len(finding.snippet) == 2000
        assert finding.snippet.endswith("...")
        assert f"[REDACTED:{long_rule}]" in finding.snippet
        assert short_secret not in finding.model_dump_json()
