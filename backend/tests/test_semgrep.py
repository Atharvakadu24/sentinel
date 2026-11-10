"""Unit and integration tests for Semgrep scanner adapter and output normalizer.

Validates:
1. Valid zero-finding output.
2. Valid findings and canonical normalization.
3. Multiple findings and occurrence index assignment.
4. Severity and confidence mapping.
5. Correct staged-to-original path translation.
6. Authoritative snippet reconstruction.
7. Invalid and malformed JSON.
8. Missing or malformed result fields.
9. Out-of-workspace paths.
10. Findings referencing unstaged or unknown files.
11. Secret and metadata sanitization.
12. Executable missing.
13. Timeout.
14. Output-limit exceeded.
15. Semgrep findings exit code behavior.
16. Fatal scanner errors.
17. No shell execution.
18. No network-dependent rule fetching.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from app.domain.findings import (
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
    _validate_raw_node,
)
from app.worker.scanner import (
    ScanExecutionResult,
    ScanJobPayload,
    ScannedFile,
    ScanStatus,
)
from app.worker.semgrep import SemgrepScannerAdapter
from app.worker.subprocess_runner import CommandResult, CommandStatus


@pytest.fixture
def temp_workspace_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Temporary directory for staging workspaces."""
    workspace_dir = tmp_path / "sentinel_staging"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    yield workspace_dir


@pytest.fixture
def temp_rules_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Temporary local rules directory."""
    rules_dir = tmp_path / "rules" / "semgrep"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "default.yaml").write_text(
        "rules:\n  - id: test\n    pattern: test\n", encoding="utf-8"
    )
    yield rules_dir


def make_command_result(
    *,
    status: CommandStatus = CommandStatus.SUCCESS,
    exit_code: int | None = 0,
    stdout: bytes | str = b"",
    stderr: bytes | str = b"",
    duration_ms: float = 100.0,
    command: tuple[str, ...] = ("semgrep", "scan"),
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


class TestSemgrepAdapter:
    """Test suite covering the 18 specific Semgrep adapter and normalizer requirements."""

    def test_valid_zero_finding_output(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 1: Valid JSON output with zero findings produces succeeded status."""
        semgrep_output = {
            "results": [],
            "errors": [],
            "paths": {"scanned": ["src/app/main.py"]},
            "version": "1.0.0",
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="app/main.py",
                    content="def add(a: int, b: int) -> int:\n    return a + b\n",
                )
            ]
        )

        result: ScanExecutionResult = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert result.components == {"semgrep": "passed"}
        assert result.counts is not None
        assert result.counts["findings"] == 0
        assert len(result.findings) == 0

    def test_valid_findings_and_canonical_normalization(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 2: Valid findings normalize into CanonicalFinding with complete metadata."""
        code = (
            "import os\n"
            "from flask import request\n\n"
            "def handler():\n"
            "    user_input = request.args.get('target')\n"
            "    os.system('ping ' + user_input)\n"
        )
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.lang.security.injection.os-system",
                    "path": "src/app/routes.py",
                    "start": {"line": 6, "col": 5},
                    "end": {"line": 6, "col": 35},
                    "extra": {
                        "message": "Direct concatenation of untrusted input into os.system call",
                        "severity": "ERROR",
                        "metadata": {
                            "category": "security",
                            "cwe": ["CWE-78: OS Command Injection"],
                            "owasp": ["A03:2021 - Injection"],
                            "confidence": "HIGH",
                            "remediation": "Use subprocess.run with an argument sequence instead.",
                        },
                        "lines": "UNTRUSTED_SCANNER_LINES",
                    },
                }
            ],
            "errors": [],
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="app/routes.py", content=code)])

        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert len(result.findings) == 1
        finding = result.findings[0]

        assert isinstance(finding, CanonicalFinding)
        assert finding.rule_id == "python.lang.security.injection.os-system"
        assert finding.source == FindingSource.SEMGREP
        assert finding.category == FindingCategory.INJECTION
        assert finding.severity == FindingSeverity.HIGH
        assert finding.confidence == FindingConfidence.HIGH
        assert finding.verification_status == VerificationStatus.SCANNER_DETECTED
        assert finding.file_path == "app/routes.py"
        assert finding.start_line == 6
        assert finding.end_line == 6
        assert finding.snippet == "    os.system('ping ' + user_input)"  # authoritative from code
        assert len(finding.fingerprint) == 64
        assert len(finding.references) >= 2
        assert any(r.type == "cwe" and "78" in r.id for r in finding.references)
        assert any(r.type == "owasp" for r in finding.references)
        assert finding.raw is not None
        _validate_raw_node(finding.raw)

    def test_multiple_findings_and_occurrence_indexing(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 3: Multiple findings receive deterministic, distinct fingerprints via occ."""
        code = (
            "eval(param1)\n"  # Line 1: identical pattern
            "do_something()\n"
            "eval(param1)\n"  # Line 3: identical pattern & identical code snippet
            "x = 1\n"
            "eval(other)\n"  # Line 5: different code snippet
        )
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.eval",
                    "path": "src/app/calc.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 13},
                    "extra": {"message": "eval call 1", "severity": "ERROR"},
                },
                {
                    "check_id": "python.eval",
                    "path": "src/app/calc.py",
                    "start": {"line": 3, "col": 1},
                    "end": {"line": 3, "col": 13},
                    "extra": {"message": "eval call 2", "severity": "ERROR"},
                },
                {
                    "check_id": "python.eval",
                    "path": "src/app/calc.py",
                    "start": {"line": 5, "col": 1},
                    "end": {"line": 5, "col": 12},
                    "extra": {"message": "eval call 3", "severity": "WARNING"},
                },
            ],
            "errors": [],
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="app/calc.py", content=code)])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert len(result.findings) == 3

        f1, f2, f3 = result.findings
        # Findings 1 and 2 have identical rule_id, file_path, and code anchor, but different occ
        assert f1.start_line == 1
        assert f2.start_line == 3
        assert f1.snippet == f2.snippet
        assert f1.fingerprint != f2.fingerprint  # Distinct fingerprints via occ!
        assert f3.fingerprint not in (f1.fingerprint, f2.fingerprint)

    def test_severity_and_confidence_mapping(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 4: Severities (including metadata overrides) and confidence map correctly."""
        code = "line1\nline2\nline3\nline4\nline5\n"
        semgrep_output = {
            "results": [
                {
                    "check_id": "rule.crit",
                    "path": "src/test.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"severity": "critical", "confidence": "HIGH"},
                    },
                },
                {
                    "check_id": "rule.high",
                    "path": "src/test.py",
                    "start": {"line": 2, "col": 1},
                    "end": {"line": 2, "col": 5},
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"confidence": "MEDIUM"},
                    },
                },
                {
                    "check_id": "rule.med",
                    "path": "src/test.py",
                    "start": {"line": 3, "col": 1},
                    "end": {"line": 3, "col": 5},
                    "extra": {
                        "severity": "WARNING",
                        "metadata": {"confidence": "LOW"},
                    },
                },
                {
                    "check_id": "rule.low",
                    "path": "src/test.py",
                    "start": {"line": 4, "col": 1},
                    "end": {"line": 4, "col": 5},
                    "extra": {
                        "severity": "INFO",
                        "metadata": {"severity": "low"},
                    },
                },
                {
                    "check_id": "rule.info",
                    "path": "src/test.py",
                    "start": {"line": 5, "col": 1},
                    "end": {"line": 5, "col": 5},
                    "extra": {
                        "severity": "INFO",
                        "metadata": {"severity": "info"},
                    },
                },
            ]
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="test.py", content=code)])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert len(result.findings) == 5
        f_crit, f_high, f_med, f_low, f_info = result.findings

        assert f_crit.severity == FindingSeverity.CRITICAL
        assert f_crit.confidence == FindingConfidence.HIGH

        assert f_high.severity == FindingSeverity.HIGH
        assert f_high.confidence == FindingConfidence.MEDIUM

        assert f_med.severity == FindingSeverity.MEDIUM
        assert f_med.confidence == FindingConfidence.LOW

        assert f_low.severity == FindingSeverity.LOW
        assert f_info.severity == FindingSeverity.INFO

    def test_correct_staged_to_original_path_translation(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 5: Staged paths (absolute, relative from src, with ./) map back to original."""
        code = "a = 1\nb = 2\n"

        def mock_runner(**kwargs: Any) -> CommandResult:
            cwd = Path(kwargs["cwd"])
            source_dir = cwd / "src"
            abs_staged = (source_dir / "nested" / "deep" / "file.py").resolve()
            output = {
                "results": [
                    {
                        "check_id": "rule.test",
                        "path": str(abs_staged),  # Full absolute path on disk
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 5},
                        "extra": {"message": "found"},
                    },
                    {
                        "check_id": "rule.test",
                        "path": "./src/nested/deep/file.py",  # Relative with ./ and src/
                        "start": {"line": 2, "col": 1},
                        "end": {"line": 2, "col": 5},
                        "extra": {"message": "found"},
                    },
                ]
            }
            return make_command_result(stdout=json.dumps(output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="nested/deep/file.py", content=code)])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert len(result.findings) == 2
        for f in result.findings:
            assert f.file_path == "nested/deep/file.py"

    def test_authoritative_snippet_reconstruction(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 6: Snippet is extracted from ScannedFile.content, not untrusted extra.lines."""
        original_code = "\n".join([f"line_{i} = {i}" for i in range(1, 25)])
        semgrep_output = {
            "results": [
                {
                    "check_id": "rule.snippet",
                    "path": "src/code.py",
                    "start": {"line": 2, "col": 1},
                    "end": {"line": 18, "col": 10},  # 17 lines total (> 12 lines max)
                    "extra": {
                        "message": "test",
                        "lines": "ATTACKER_INJECTED_SCANNER_SNIPPET",
                    },
                }
            ]
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="code.py", content=original_code)])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert len(result.findings) == 1
        f = result.findings[0]

        # Must NOT contain scanner lines
        assert "ATTACKER_INJECTED" not in f.snippet
        # Must be extracted from authoritative file lines
        assert "line_2 = 2" in f.snippet
        # Sliced to 12 lines max per Section 10.5
        assert len(f.snippet.splitlines()) == 12

    def test_invalid_and_malformed_json(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 7: Malformed or unparseable JSON fails with SEMGREP_INVALID_JSON."""

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout="<html>502 Bad Gateway</html>")

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="x = 1\n")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_INVALID_JSON"
        assert result.components == {"semgrep": "failed"}

    def test_missing_or_malformed_result_fields(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 8: Missing results key or invalid coordinate fields handled safely."""
        code = "a = 1\nb = 2\n"

        # Case A: Top-level results missing
        adapter_missing_results = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=lambda **kw: make_command_result(stdout=json.dumps({"version": "1"})),
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content=code)])
        res_a = adapter_missing_results.scan(payload)
        assert res_a.status == ScanStatus.FAILED
        assert res_a.error_code == "SEMGREP_MALFORMED_OUTPUT"

        # Case B: Individual item has invalid line coordinates
        output_bad_lines = {
            "results": [
                {
                    "check_id": "rule.bad_coords",
                    "path": "src/main.py",
                    "start": {"line": "not_an_int"},
                    "end": {"line": 2},
                    "extra": {"message": "bad"},
                },
                {
                    "check_id": "rule.good",
                    "path": "src/main.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"message": "good"},
                },
            ]
        }
        adapter_bad_coords = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=lambda **kw: make_command_result(stdout=json.dumps(output_bad_lines)),
            workspace_base_dir=temp_workspace_dir,
        )
        res_b = adapter_bad_coords.scan(payload)
        # 1 valid finding normalized, 1 invalid finding rejected -> PARTIAL
        assert res_b.status == ScanStatus.PARTIAL
        assert len(res_b.findings) == 1
        assert res_b.findings[0].rule_id == "rule.good"

    def test_out_of_workspace_paths(self, temp_workspace_dir: Path, temp_rules_dir: Path) -> None:
        """Requirement 9: Paths outside the staging workspace are rejected."""
        semgrep_output = {
            "results": [
                {
                    "check_id": "rule.escape",
                    "path": "/etc/shadow",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"message": "escape attempt"},
                }
            ]
        }

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=lambda **kw: make_command_result(stdout=json.dumps(semgrep_output)),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="app.py", content="valid_content = 1\n")])
        result = adapter.scan(payload)

        # Single finding was rejected -> NORMALIZATION_FAILED
        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_NORMALIZATION_FAILED"
        assert len(result.findings) == 0

    def test_findings_referencing_unstaged_or_unknown_files(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 10: Findings for unstaged or skipped files are rejected."""
        semgrep_output = {
            "results": [
                {
                    "check_id": "rule.skipped",
                    "path": "src/ignored.txt",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {"message": "found in skipped file"},
                }
            ]
        }

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=lambda **kw: make_command_result(stdout=json.dumps(semgrep_output)),
            workspace_base_dir=temp_workspace_dir,
        )

        # ignored.txt has scanned=False
        payload = ScanJobPayload(
            files=[
                ScannedFile(
                    path="ignored.txt",
                    content="secret",
                    scanned=False,
                    skip_reason="binary",
                ),
                ScannedFile(path="main.py", content="clean_code = True\n"),
            ]
        )
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_NORMALIZATION_FAILED"
        assert len(result.findings) == 0

    def test_secret_and_metadata_sanitization(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 11: Raw metadata is sanitized, forbidden keys removed, secrets redacted."""
        code = "val = 1\n"
        semgrep_output = {
            "results": [
                {
                    "check_id": "rule.sensitive",
                    "path": "src/main.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 7},
                    "extra": {
                        "message": "check",
                        "metadata": {
                            "secret": "TOP_SECRET_VALUE",
                            "password": "plain_password",
                            "api_key": "AKIA1234567890123456",
                            "nested": {
                                "credential": "bad",
                                "safe_field": "clean_value",
                            },
                        },
                    },
                }
            ]
        }

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=lambda **kw: make_command_result(stdout=json.dumps(semgrep_output)),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content=code)])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert len(result.findings) == 1
        finding = result.findings[0]

        assert finding.raw is not None
        # Must pass CanonicalFinding raw validation without errors
        _validate_raw_node(finding.raw)

        raw_str = json.dumps(finding.raw)
        assert "TOP_SECRET_VALUE" not in raw_str
        assert "plain_password" not in raw_str
        assert "AKIA" not in raw_str
        assert "clean_value" in raw_str

    def test_executable_missing(self, temp_workspace_dir: Path, temp_rules_dir: Path) -> None:
        """Requirement 12: Missing binary fails safely with SEMGREP_BINARY_NOT_FOUND."""
        # Case A: Real path check when runner is run_command_bounded
        adapter_real = SemgrepScannerAdapter(
            executable_path="/nonexistent/bin/semgrep",
            rules_path=temp_rules_dir,
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])
        result_a = adapter_real.scan(payload)
        assert result_a.status == ScanStatus.FAILED
        assert result_a.error_code == "SEMGREP_BINARY_NOT_FOUND"

        # Case B: Mocked CommandStatus.EXECUTABLE_NOT_FOUND
        adapter_mock = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=lambda **kw: make_command_result(
                status=CommandStatus.EXECUTABLE_NOT_FOUND,
                executable_not_found=True,
            ),
            workspace_base_dir=temp_workspace_dir,
        )
        result_b = adapter_mock.scan(payload)
        assert result_b.status == ScanStatus.FAILED
        assert result_b.error_code == "SEMGREP_BINARY_NOT_FOUND"

    def test_timeout_handling(self, temp_workspace_dir: Path, temp_rules_dir: Path) -> None:
        """Requirement 13: Subprocess timeout maps to SEMGREP_TIMEOUT error."""
        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            timeout_sec=30,
            runner=lambda **kw: make_command_result(
                status=CommandStatus.TIMEOUT,
                timed_out=True,
            ),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_TIMEOUT"
        assert result.components == {"semgrep": "failed"}

    def test_output_limit_exceeded(self, temp_workspace_dir: Path, temp_rules_dir: Path) -> None:
        """Requirement 14: Output limit exceeded maps to SEMGREP_OUTPUT_LIMIT_EXCEEDED."""
        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            max_output_bytes=1000,
            runner=lambda **kw: make_command_result(
                status=CommandStatus.OUTPUT_LIMIT_EXCEEDED,
                output_limit_exceeded=True,
            ),
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_OUTPUT_LIMIT_EXCEEDED"
        assert result.components == {"semgrep": "failed"}

    def test_semgrep_findings_exit_code_behavior(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Requirement 15: Semgrep exit code 1 with valid JSON findings succeeds."""
        code = "import pickle\npickle.loads(data)\n"
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.pickle.deserialization",
                    "path": "src/main.py",
                    "start": {"line": 2, "col": 1},
                    "end": {"line": 2, "col": 19},
                    "extra": {
                        "message": "Unsafe pickle deserialization",
                        "severity": "ERROR",
                    },
                }
            ],
            "errors": [],
        }

        # Semgrep exits with 1 when findings are present and --error is active
        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(
                status=CommandStatus.NONZERO_EXIT,
                exit_code=1,
                stdout=json.dumps(semgrep_output),
            )

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content=code)])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "python.pickle.deserialization"

    def test_fatal_scanner_errors(self, temp_workspace_dir: Path, temp_rules_dir: Path) -> None:
        """Requirement 16: Exit code 2 (fatal/crash) fails with SEMGREP_EXECUTION_FAILED."""

        # Case A: Exit code 2 with unparseable stdout / stderr
        def mock_runner_crash(**kwargs: Any) -> CommandResult:
            return make_command_result(
                status=CommandStatus.NONZERO_EXIT,
                exit_code=2,
                stdout="",
                stderr="Fatal error: invalid configuration rule syntax at line 4",
            )

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner_crash,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_EXECUTION_FAILED"

        # Case B: Exit code 2 with fatal error list in JSON and no results
        semgrep_err_output = {
            "results": [],
            "errors": [{"message": "Rule parse error in custom.yaml", "level": "error"}],
        }

        def mock_runner_json_err(**kwargs: Any) -> CommandResult:
            return make_command_result(
                status=CommandStatus.NONZERO_EXIT,
                exit_code=2,
                stdout=json.dumps(semgrep_err_output),
            )

        adapter_b = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner_json_err,
            workspace_base_dir=temp_workspace_dir,
        )
        result_b = adapter_b.scan(payload)

        assert result_b.status == ScanStatus.FAILED
        assert result_b.error_code == "SEMGREP_EXECUTION_FAILED"

    def test_no_shell_execution(self, temp_workspace_dir: Path, temp_rules_dir: Path) -> None:
        """Requirement 17: Command arguments are passed as an argument vector, never through shell."""
        captured_args: list[str] = []

        def mock_runner(**kwargs: Any) -> CommandResult:
            captured_args.extend(kwargs["args"])
            return make_command_result(stdout=json.dumps({"results": []}))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        # Check command vector structure
        assert isinstance(captured_args, list)
        assert captured_args[0] == "semgrep"
        assert captured_args[1] == "scan"
        assert "--config" in captured_args
        assert "--json" in captured_args
        assert "--metrics=off" in captured_args
        assert "--disable-version-check" in captured_args
        assert "--no-git-ignore" in captured_args
        assert "--jobs" in captured_args
        assert "--quiet" in captured_args

    def test_no_network_dependent_rule_fetching(self, temp_workspace_dir: Path) -> None:
        """Requirement 18: Network rule registries (p/..., r/..., http://, auto) are rejected."""
        disallowed_rules = [
            "p/ci",
            "p/default",
            "r/python",
            "auto",
            "https://semgrep.dev/c/p/security-audit",
            "http://rules.internal/pack.yaml",
        ]

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])

        for bad_rule in disallowed_rules:
            called = False

            def mock_runner(**kwargs: Any) -> CommandResult:
                nonlocal called
                called = True
                return make_command_result(stdout="{}")

            adapter = SemgrepScannerAdapter(
                executable_path="semgrep",
                rules_path=bad_rule,
                runner=mock_runner,
                workspace_base_dir=temp_workspace_dir,
            )

            result = adapter.scan(payload)

            assert result.status == ScanStatus.FAILED
            assert result.error_code == "SEMGREP_INVALID_RULES_PATH"
            assert not called, f"Runner was invoked for prohibited rule '{bad_rule}'!"

    def test_empty_scannable_payload_succeeds_without_subprocess(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Verify that a payload with no scannable files succeeds immediately."""
        called = False

        def mock_runner(**kwargs: Any) -> CommandResult:
            nonlocal called
            called = True
            return make_command_result(stdout="{}")

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        # All files have scanned=False
        payload = ScanJobPayload(
            files=[
                ScannedFile(path="bin.dat", content="binary", scanned=False, skip_reason="binary")
            ]
        )
        result = adapter.scan(payload)

        assert result.status == ScanStatus.SUCCEEDED
        assert result.counts == {
            "findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        assert not called

    def test_rules_path_missing_on_disk_with_real_runner(self, temp_workspace_dir: Path) -> None:
        """Verify that a missing local rules path fails closed when run_command_bounded is active."""
        import sys

        adapter = SemgrepScannerAdapter(
            executable_path=sys.executable,
            rules_path="/nonexistent/rules/semgrep",
            workspace_base_dir=temp_workspace_dir,
        )
        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_RULES_NOT_FOUND"

    def test_nonzero_exit_code_with_empty_results_and_empty_errors(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Verify non-zero exit code with empty results and empty errors fails instead of succeeding."""
        # Non-zero exit code (e.g. exit code 1) with valid JSON, empty results, empty errors
        semgrep_empty: dict[str, list[Any]] = {"results": [], "errors": []}

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(
                status=CommandStatus.NONZERO_EXIT,
                exit_code=1,
                stdout=json.dumps(semgrep_empty),
            )

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="main.py", content="code = 1\n")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_EXECUTION_FAILED"
        assert result.components == {"semgrep": "failed"}

    def test_finding_coordinates_boundary_validation(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Verify first line, last valid line, and beyond-EOF coordinates."""
        # 5-line source file
        code = "line_1 = 1\nline_2 = 2\nline_3 = 3\nline_4 = 4\nline_5 = 5\n"

        semgrep_output = {
            "results": [
                {
                    "check_id": "rule.first_line",
                    "path": "src/app.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {"message": "first line"},
                },
                {
                    "check_id": "rule.last_valid_line",
                    "path": "src/app.py",
                    "start": {"line": 5, "col": 1},
                    "end": {"line": 5, "col": 10},
                    "extra": {"message": "last line"},
                },
                {
                    "check_id": "rule.beyond_eof",
                    "path": "src/app.py",
                    "start": {"line": 6, "col": 1},
                    "end": {"line": 6, "col": 10},
                    "extra": {"message": "beyond EOF"},
                },
            ],
            "errors": [],
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="app.py", content=code)])
        result = adapter.scan(payload)

        # 2 valid findings accepted, 1 beyond-EOF finding rejected -> PARTIAL
        assert result.status == ScanStatus.PARTIAL
        assert len(result.findings) == 2

        f_first = next(f for f in result.findings if f.rule_id == "rule.first_line")
        assert f_first.start_line == 1
        assert f_first.snippet == "line_1 = 1"

        f_last = next(f for f in result.findings if f.rule_id == "rule.last_valid_line")
        assert f_last.start_line == 5
        assert f_last.snippet == "line_5 = 5"

        # Beyond-EOF finding must NOT be present
        assert not any(f.rule_id == "rule.beyond_eof" for f in result.findings)

    def test_empty_source_file_finding_rejected(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Verify that findings referencing an empty source file are safely rejected."""
        semgrep_output = {
            "results": [
                {
                    "check_id": "rule.empty_file",
                    "path": "src/empty.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 1},
                    "extra": {"message": "finding in empty file"},
                }
            ],
            "errors": [],
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        payload = ScanJobPayload(files=[ScannedFile(path="empty.py", content="")])
        result = adapter.scan(payload)

        assert result.status == ScanStatus.FAILED
        assert result.error_code == "SEMGREP_NORMALIZATION_FAILED"
        assert len(result.findings) == 0


class TestSemgrepWorkerIntegration:
    """End-to-end integration tests connecting SemgrepScannerAdapter to JobWorker."""

    def test_job_worker_processes_semgrep_findings(
        self, temp_workspace_dir: Path, temp_rules_dir: Path
    ) -> None:
        """Verify JobWorker claims a job, runs SemgrepScannerAdapter, and persists findings."""
        import uuid

        from sqlalchemy import create_engine, event, select
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from app.db.base import Base, utc_now
        from app.db.models import Finding, Job, Project, Scan, ScanFinding, User
        from app.worker.runner import JobWorker

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
        session_factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

        # Seed database: user, project, scan, job
        with session_factory() as session:
            user = User(
                github_user_id=123456,
                github_login="semgrep-tester",
                display_name="Semgrep Tester",
            )
            session.add(user)
            session.flush()

            project = Project(
                owner_user_id=user.id,
                kind="manual",
                name="Semgrep E2E Project",
                status="active",
            )
            session.add(project)
            session.flush()

            scan = Scan(
                project_id=project.id,
                trigger="manual",
                trigger_key=f"semgrep-test-{uuid.uuid4()}",
                status="queued",
                report_status="not_applicable",
            )
            session.add(scan)
            session.flush()

            code = "import os\ndef ping(ip):\n    os.system('ping ' + ip)\n"
            payload = {
                "files": [
                    {
                        "path": "app/net.py",
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

        semgrep_output = {
            "results": [
                {
                    "check_id": "python.security.os-system",
                    "path": "src/app/net.py",
                    "start": {"line": 3, "col": 5},
                    "end": {"line": 3, "col": 33},
                    "extra": {
                        "message": "Command injection vulnerability",
                        "severity": "ERROR",
                        "metadata": {
                            "category": "security",
                            "cwe": ["CWE-78"],
                            "confidence": "HIGH",
                        },
                    },
                }
            ],
            "errors": [],
        }

        def mock_runner(**kwargs: Any) -> CommandResult:
            return make_command_result(stdout=json.dumps(semgrep_output))

        adapter = SemgrepScannerAdapter(
            executable_path="semgrep",
            rules_path=temp_rules_dir,
            runner=mock_runner,
            workspace_base_dir=temp_workspace_dir,
        )

        worker = JobWorker(
            session_factory=session_factory,
            worker_id="test-semgrep-worker-1",
            scanner=adapter,
        )

        # Worker processes one job from queue
        processed = worker.run_once()
        assert processed is True

        # Verify job and scan completed in DB
        with session_factory() as session:
            completed_job = session.get(Job, job_id)
            assert completed_job is not None
            assert completed_job.status == "succeeded"
            assert completed_job.payload is None  # Payload scrubbed

            completed_scan = session.get(Scan, scan_id)
            assert completed_scan is not None
            assert completed_scan.status == "succeeded"
            assert completed_scan.components == {"semgrep": "passed"}
            assert completed_scan.counts is not None
            assert completed_scan.counts["findings"] == 1
            assert completed_scan.counts["high"] == 1

            # Verify persistent finding in DB
            findings = session.scalars(
                select(Finding).where(Finding.project_id == project_id)
            ).all()
            assert len(findings) == 1
            f = findings[0]
            assert f.rule_id == "python.security.os-system"
            assert f.file_path == "app/net.py"
            assert f.status == "open"

            # Verify ScanFinding row (observations per scan)
            scan_findings = session.scalars(
                select(ScanFinding).where(ScanFinding.scan_id == scan_id)
            ).all()
            assert len(scan_findings) == 1
            sf = scan_findings[0]
            assert sf.finding_id == f.id
            assert sf.severity == "high"
            assert sf.snippet == "    os.system('ping ' + ip)"
