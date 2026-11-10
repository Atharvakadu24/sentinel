"""Semgrep static analysis scanner adapter and output normalizer.

Implements Blueprint Section 10.3 (Deterministic static analysis - Semgrep CLI),
Section 10.5 (Canonical Finding Schema), Section 10.6 (Fingerprint Generation),
and Threat Mitigations T2 (Subprocess isolation) and T8 (Path safety).
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.config import get_settings
from app.domain.findings import (
    _FORBIDDEN_RAW_KEYS,
    _SECRET_VALUE_PATTERNS,
    CanonicalFinding,
    FindingCategory,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingSource,
    VerificationStatus,
    _validate_raw_node,
)
from app.domain.fingerprint import (
    assign_occurrence_indices,
    compute_code_anchor,
    compute_finding_fingerprint,
)
from app.worker.scanner import (
    ScanExecutionResult,
    ScanJobPayload,
    ScannedFile,
    ScannerInterface,
    ScanStatus,
)
from app.worker.staging import StagedWorkspace, StagingPathMappingError
from app.worker.subprocess_runner import (
    CommandResult,
    CommandStatus,
    run_command_bounded,
)

logger = logging.getLogger("sentinel.worker.semgrep")

_CWE_PATTERN = re.compile(r"\b(CWE-\d+)\b", re.IGNORECASE)
_OWASP_PATTERN = re.compile(r"\b(A\d{2}:\d{4}[^\s,]*)\b", re.IGNORECASE)
_NETWORK_RULES_PREFIXES = ("p/", "r/", "http://", "https://")


class SemgrepError(Exception):
    """Base exception for Semgrep adapter operations."""


class SemgrepExecutionError(SemgrepError):
    """Raised when Semgrep process execution fails."""


class SemgrepNormalizationError(SemgrepError):
    """Raised when Semgrep output normalization fails."""


def _resolve_executable(executable: str | Path) -> str | None:
    """Resolve an executable path safely without ambient PATH lookup when qualified.

    Args:
        executable: Configured executable name or path.

    Returns:
        Absolute filesystem path to the executable, or None if not found.
    """
    p_str = str(executable).strip()
    if not p_str:
        return None

    p = Path(p_str)
    if p.is_absolute() or "/" in p_str or "\\" in p_str:
        resolved = p.resolve()
        if resolved.is_file():
            return str(resolved)
        return None

    found = shutil.which(p_str)
    if found:
        return str(Path(found).resolve())
    return None


def _is_network_rules_path(rules_path: str | Path) -> bool:
    """Check whether a rules configuration attempts network rule fetching."""
    clean = str(rules_path).strip().lower()
    if clean == "auto":
        return True
    return any(clean.startswith(prefix) for prefix in _NETWORK_RULES_PREFIXES)


def _map_severity(
    raw_severity: str | None, metadata: dict[str, Any] | None = None
) -> FindingSeverity:
    """Map Semgrep severity and metadata attributes to canonical FindingSeverity."""
    if metadata and isinstance(metadata, dict):
        meta_sev = str(metadata.get("severity", "")).strip().lower()
        if meta_sev in ("critical", "crit"):
            return FindingSeverity.CRITICAL
        if meta_sev == "high":
            return FindingSeverity.HIGH
        if meta_sev in ("medium", "med"):
            return FindingSeverity.MEDIUM
        if meta_sev == "low":
            return FindingSeverity.LOW
        if meta_sev in ("info", "informational"):
            return FindingSeverity.INFO

        impact = str(metadata.get("impact", "")).strip().lower()
        if impact in ("critical", "crit"):
            return FindingSeverity.CRITICAL

    if raw_severity:
        sev_clean = str(raw_severity).strip().upper()
        if sev_clean == "ERROR":
            return FindingSeverity.HIGH
        if sev_clean == "WARNING":
            return FindingSeverity.MEDIUM
        if sev_clean == "INFO":
            return FindingSeverity.LOW

    return FindingSeverity.MEDIUM


def _map_confidence(raw_confidence: str | None) -> FindingConfidence:
    """Map Semgrep rule confidence metadata to canonical FindingConfidence."""
    if raw_confidence:
        conf_clean = str(raw_confidence).strip().upper()
        if conf_clean in ("HIGH", "CERTAIN"):
            return FindingConfidence.HIGH
        if conf_clean in ("MEDIUM", "MED"):
            return FindingConfidence.MEDIUM
        if conf_clean in ("LOW", "INFORMATIVE"):
            return FindingConfidence.LOW
    return FindingConfidence.HIGH


def _map_category(category_hint: str | None, check_id: str) -> FindingCategory:
    """Map Semgrep category metadata or rule ID keywords to canonical FindingCategory."""
    combined = f"{category_hint or ''} {check_id}".lower()

    if any(
        k in combined
        for k in (
            "injection",
            "sqli",
            "sql-injection",
            "command-injection",
            "code-injection",
            "eval",
        )
    ):
        return FindingCategory.INJECTION
    if "xss" in combined or "cross-site-scripting" in combined:
        return FindingCategory.XSS
    if any(
        k in combined
        for k in (
            "path-traversal",
            "pathtraversal",
            "directory-traversal",
            "path_traversal",
            "traversal",
        )
    ):
        return FindingCategory.PATH_TRAVERSAL
    if any(
        k in combined
        for k in (
            "hardcoded-secret",
            "hardcoded_secret",
            "secret",
            "credential",
            "private-key",
        )
    ):
        return FindingCategory.HARDCODED_SECRET
    if any(k in combined for k in ("crypto", "cryptography", "cipher", "hash", "random")):
        return FindingCategory.CRYPTO
    if any(k in combined for k in ("deserialization", "unpickle", "pickle", "yaml-unsafe")):
        return FindingCategory.DESERIALIZATION
    if "ssrf" in combined or "server-side-request-forgery" in combined:
        return FindingCategory.SSRF
    if any(
        k in combined for k in ("auth", "jwt", "rbac", "permission", "session", "access-control")
    ):
        return FindingCategory.AUTHN_AUTHZ
    if any(
        k in combined
        for k in (
            "config",
            "cors",
            "csrf",
            "misconfiguration",
            "header",
            "cookie",
            "insecure",
        )
    ):
        return FindingCategory.INSECURE_CONFIG
    if any(k in combined for k in ("exposure", "leak", "information-disclosure", "sensitive-data")):
        return FindingCategory.DATA_EXPOSURE
    if any(k in combined for k in ("logic", "bypass")):
        return FindingCategory.LOGIC_BUG
    if any(k in combined for k in ("error-handling", "exception")):
        return FindingCategory.ERROR_HANDLING

    return FindingCategory.OTHER


def _extract_references(metadata: dict[str, Any]) -> list[FindingReference]:
    """Extract and validate security references (CWE, OWASP, external links)."""
    refs: list[FindingReference] = []
    seen: set[tuple[str, str]] = set()

    # CWE references
    cwe_val = metadata.get("cwe")
    cwe_items = cwe_val if isinstance(cwe_val, list) else ([cwe_val] if cwe_val else [])
    for item in cwe_items:
        if not isinstance(item, str):
            continue
        match = _CWE_PATTERN.search(item)
        if match:
            cwe_id = match.group(1).upper()
            cwe_num = cwe_id.split("-")[1]
            url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            key = ("cwe", cwe_id)
            if key not in seen:
                seen.add(key)
                refs.append(FindingReference(type="cwe", id=cwe_id, url=url))

    # OWASP references
    owasp_val = metadata.get("owasp")
    owasp_items = owasp_val if isinstance(owasp_val, list) else ([owasp_val] if owasp_val else [])
    for item in owasp_items:
        if not isinstance(item, str):
            continue
        clean_text = item.strip()
        match = _OWASP_PATTERN.search(clean_text)
        owasp_id = match.group(1).upper() if match else clean_text[:100]
        if owasp_id:
            key = ("owasp", owasp_id)
            if key not in seen:
                seen.add(key)
                refs.append(
                    FindingReference(
                        type="owasp",
                        id=owasp_id,
                        url="https://owasp.org/Top10/",
                    )
                )

    # General URLs
    ref_urls = metadata.get("references")
    url_items = ref_urls if isinstance(ref_urls, list) else ([ref_urls] if ref_urls else [])
    for url_item in url_items:
        if isinstance(url_item, str) and url_item.startswith(("http://", "https://")):
            url_clean = url_item.strip()
            key = ("link", url_clean)
            if key not in seen and len(url_clean) <= 500:
                seen.add(key)
                refs.append(FindingReference(type="link", id="reference", url=url_clean))

    return refs


def _sanitize_metadata_node(data: Any, depth: int = 0) -> Any:
    """Recursively scrub forbidden keys, secret patterns, and oversized metadata."""
    if depth > 8:
        return None

    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            if not isinstance(k, str):
                continue
            k_lower = k.strip().lower()
            if k_lower in _FORBIDDEN_RAW_KEYS or k_lower in ("lines", "match"):
                continue
            if any(
                bad in k_lower
                for bad in (
                    "secret",
                    "token",
                    "password",
                    "passwd",
                    "credential",
                    "api_key",
                )
            ):
                continue
            cleaned_val = _sanitize_metadata_node(v, depth + 1)
            if cleaned_val is not None:
                cleaned[k] = cleaned_val
        return cleaned

    if isinstance(data, list):
        scrubbed_list = [_sanitize_metadata_node(item, depth + 1) for item in data[:50]]
        return [item for item in scrubbed_list if item is not None]

    if isinstance(data, str):
        for pattern in _SECRET_VALUE_PATTERNS:
            if pattern.search(data):
                return "[REDACTED]"
        return data[:500]

    if isinstance(data, (int, float, bool)):
        return data

    return None


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Sanitize and validate raw metadata for canonical findings."""
    cleaned = _sanitize_metadata_node(metadata)
    if not isinstance(cleaned, dict):
        return {}

    try:
        serialized = json.dumps(cleaned, ensure_ascii=False)
        if len(serialized.encode("utf-8")) > 8192:
            cleaned = {"truncated": True}
        _validate_raw_node(cleaned)
    except (ValueError, TypeError):
        return {}

    return cleaned


def _extract_snippet(content: str, start_line: int, end_line: int) -> tuple[str, int]:
    """Extract authoritative code snippet from file content within line bounds.

    Blueprint Section 10.5:
    - Slices up to 12 lines
    - Caps snippet length to 2000 characters
    - Returns tuple of (snippet, snippet_start_line)
    """
    lines = content.splitlines()
    total_lines = len(lines)

    if total_lines == 0 or start_line > total_lines or start_line < 1:
        return ("", start_line)

    clamped_end = max(start_line, min(end_line, total_lines))
    selected_lines = lines[start_line - 1 : clamped_end]
    if len(selected_lines) > 12:
        selected_lines = selected_lines[:12]

    snippet = "\n".join(selected_lines)
    if len(snippet) > 2000:
        snippet = snippet[:1997] + "..."

    return (snippet, start_line)


class SemgrepScannerAdapter(ScannerInterface):
    """Production Semgrep CLI adapter conforming to ScannerInterface.

    Stages files via StagedWorkspace, executes Semgrep bounded via run_command_bounded(),
    parses Semgrep JSON results, reconstructs authoritative code snippets from ScannedFile,
    and normalizes results to CanonicalFinding schema.
    """

    def __init__(
        self,
        *,
        executable_path: str | Path | None = None,
        rules_path: str | Path | None = None,
        timeout_sec: int | None = None,
        max_output_bytes: int = 10 * 1024 * 1024,
        runner: Callable[..., CommandResult] = run_command_bounded,
        workspace_base_dir: str | Path | None = None,
    ) -> None:
        """Initialize the Semgrep adapter.

        Args:
            executable_path: Semgrep binary path or command name.
            rules_path: Path to local rules directory or file.
            timeout_sec: Subprocess execution timeout in seconds.
            max_output_bytes: Maximum output bytes allowed before termination.
            runner: Callable executing subprocess commands (defaults to run_command_bounded).
            workspace_base_dir: Optional base directory for staging workspaces.
        """
        settings = get_settings()
        self.executable_path = str(executable_path or settings.SEMGREP_PATH)
        self.rules_path = str(rules_path or settings.SEMGREP_RULES_PATH)
        self.timeout_sec = timeout_sec if timeout_sec is not None else settings.SEMGREP_TIMEOUT_SEC
        self.max_output_bytes = max_output_bytes
        self.runner = runner
        self.workspace_base_dir = workspace_base_dir

    def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
        """Execute Semgrep analysis over submitted files and return structured results."""
        # 1. Check for scannable files
        scannable_files = [f for f in payload.files if f.scanned]
        if not scannable_files:
            return ScanExecutionResult(
                status=ScanStatus.SUCCEEDED,
                components={"semgrep": "passed"},
                counts={
                    "findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                findings=[],
            )

        # 2. Reject network-dependent rule fetching
        if _is_network_rules_path(self.rules_path):
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_INVALID_RULES_PATH",
                error_message="Network-dependent rule fetching is prohibited; rules_path must be a local path",
                retryable=False,
                components={"semgrep": "failed"},
            )

        # 3. Resolve executable path
        resolved_exec = _resolve_executable(self.executable_path)
        if resolved_exec is None:
            if self.runner is run_command_bounded:
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="SEMGREP_BINARY_NOT_FOUND",
                    error_message=f"Semgrep executable '{self.executable_path}' not found",
                    retryable=False,
                    components={"semgrep": "failed"},
                )
            resolved_exec = self.executable_path

        # 4. Validate local rules path on disk when executing bounded runner
        rules_path_obj = Path(self.rules_path).resolve()
        if self.runner is run_command_bounded and not rules_path_obj.exists():
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_RULES_NOT_FOUND",
                error_message=f"Semgrep rules path '{self.rules_path}' does not exist",
                retryable=False,
                components={"semgrep": "failed"},
            )

        # 5. Execute analysis inside ephemeral StagedWorkspace
        try:
            with StagedWorkspace(payload.files, base_dir=self.workspace_base_dir) as workspace:
                return self._execute_and_normalize(
                    workspace=workspace,
                    payload=payload,
                    executable=resolved_exec,
                    rules_path=rules_path_obj,
                )
        except Exception as exc:  # noqa: BLE001 - catch unexpected staging or scanner crash to report failed result
            logger.error("Semgrep scan execution failed unexpectedly: %s", exc)
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_EXECUTION_ERROR",
                error_message=f"Semgrep staging or execution failure: {exc}",
                retryable=False,
                components={"semgrep": "failed"},
            )

    def _execute_and_normalize(
        self,
        *,
        workspace: StagedWorkspace,
        payload: ScanJobPayload,
        executable: str,
        rules_path: Path,
    ) -> ScanExecutionResult:
        """Run Semgrep bounded subprocess and normalize its JSON output."""
        cmd = [
            executable,
            "scan",
            "--config",
            str(rules_path if rules_path.exists() else self.rules_path),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--timeout",
            "10",
            "--max-target-bytes",
            "1000000",
            "--jobs",
            "1",
            "--quiet",
            str(workspace.source_dir),
        ]

        cmd_result = self.runner(
            args=cmd,
            cwd=workspace.path,
            timeout_sec=self.timeout_sec,
            max_output_bytes=self.max_output_bytes,
            check=False,
        )

        return self._interpret_command_result(
            cmd_result=cmd_result,
            workspace=workspace,
            payload=payload,
        )

    def _interpret_command_result(
        self,
        *,
        cmd_result: CommandResult,
        workspace: StagedWorkspace,
        payload: ScanJobPayload,
    ) -> ScanExecutionResult:
        """Interpret bounded CommandResult and map to ScanExecutionResult."""
        if cmd_result.status == CommandStatus.EXECUTABLE_NOT_FOUND:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_BINARY_NOT_FOUND",
                error_message=f"Semgrep executable '{self.executable_path}' not found",
                retryable=False,
                components={"semgrep": "failed"},
            )

        if cmd_result.status == CommandStatus.TIMEOUT:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_TIMEOUT",
                error_message=f"Semgrep execution timed out after {self.timeout_sec}s",
                retryable=False,
                components={"semgrep": "failed"},
            )

        if cmd_result.status == CommandStatus.OUTPUT_LIMIT_EXCEEDED:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_OUTPUT_LIMIT_EXCEEDED",
                error_message=f"Semgrep output exceeded maximum size of {self.max_output_bytes} bytes",
                retryable=False,
                components={"semgrep": "failed"},
            )

        if cmd_result.status == CommandStatus.ERROR:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_EXECUTION_ERROR",
                error_message="Unexpected error during Semgrep execution",
                retryable=False,
                components={"semgrep": "failed"},
            )

        # Parse JSON from stdout
        stdout_text = cmd_result.stdout.decode("utf-8", errors="replace").strip()
        if not stdout_text:
            if cmd_result.exit_code not in (0, None):
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="SEMGREP_EXECUTION_FAILED",
                    error_message=f"Semgrep exited with code {cmd_result.exit_code} and produced no output",
                    retryable=False,
                    components={"semgrep": "failed"},
                )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_INVALID_JSON",
                error_message="Semgrep stdout was empty",
                retryable=False,
                components={"semgrep": "failed"},
            )

        try:
            raw_data = json.loads(stdout_text)
        except json.JSONDecodeError:
            if cmd_result.exit_code not in (0, None):
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="SEMGREP_EXECUTION_FAILED",
                    error_message=f"Semgrep exited with code {cmd_result.exit_code} and produced unparseable output",
                    retryable=False,
                    components={"semgrep": "failed"},
                )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_INVALID_JSON",
                error_message="Failed to parse Semgrep output as JSON",
                retryable=False,
                components={"semgrep": "failed"},
            )

        if not isinstance(raw_data, dict):
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_MALFORMED_OUTPUT",
                error_message="Semgrep output JSON root must be an object dictionary",
                retryable=False,
                components={"semgrep": "failed"},
            )

        if "results" not in raw_data or not isinstance(raw_data["results"], list):
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_MALFORMED_OUTPUT",
                error_message="Semgrep output JSON is missing required 'results' list",
                retryable=False,
                components={"semgrep": "failed"},
            )

        raw_results = raw_data["results"]
        raw_errors = raw_data.get("errors", [])
        has_partial_errors = bool(raw_errors)

        # Check non-zero exit code when no findings were produced
        if cmd_result.exit_code not in (0, None) and not raw_results:
            first_err = (
                raw_errors[0].get("message", "")
                if has_partial_errors and isinstance(raw_errors[0], dict)
                else ""
            )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_EXECUTION_FAILED",
                error_message=f"Semgrep execution failed: {first_err[:200]}"
                if first_err
                else f"Semgrep execution failed with code {cmd_result.exit_code}",
                retryable=False,
                components={"semgrep": "failed"},
            )

        # Normalize raw results
        return self._normalize_results(
            raw_results=raw_results,
            workspace=workspace,
            payload=payload,
            has_partial_errors=has_partial_errors,
        )

    def _normalize_results(
        self,
        *,
        raw_results: list[Any],
        workspace: StagedWorkspace,
        payload: ScanJobPayload,
        has_partial_errors: bool,
    ) -> ScanExecutionResult:
        """Parse raw Semgrep findings and construct CanonicalFinding models."""
        files_by_path: dict[str, ScannedFile] = {f.path: f for f in payload.files}
        intermediate_items: list[dict[str, Any]] = []
        rejected_count = 0

        for idx, item in enumerate(raw_results):
            if not isinstance(item, dict):
                logger.warning("Skipping raw Semgrep result at index %d: not a dictionary", idx)
                rejected_count += 1
                continue

            check_id = item.get("check_id")
            if not isinstance(check_id, str) or not check_id.strip():
                logger.warning(
                    "Skipping raw Semgrep result at index %d: missing or invalid check_id",
                    idx,
                )
                rejected_count += 1
                continue
            rule_id = check_id.strip()[:255]

            staged_path_raw = item.get("path")
            if not isinstance(staged_path_raw, str) or not staged_path_raw.strip():
                logger.warning("Skipping raw Semgrep result '%s': missing or invalid path", rule_id)
                rejected_count += 1
                continue

            try:
                original_path = workspace.get_original_path(staged_path_raw)
            except StagingPathMappingError:
                logger.warning(
                    "Skipping finding '%s': staged path '%s' cannot be mapped to workspace",
                    rule_id,
                    staged_path_raw,
                )
                rejected_count += 1
                continue

            scanned_file = files_by_path.get(original_path)
            if scanned_file is None or not scanned_file.scanned:
                logger.warning(
                    "Skipping finding '%s': path '%s' references an unscanned or unknown file",
                    rule_id,
                    original_path,
                )
                rejected_count += 1
                continue

            start_node = item.get("start")
            end_node = item.get("end")
            if not isinstance(start_node, dict) or not isinstance(end_node, dict):
                logger.warning("Skipping finding '%s': start or end coordinates missing", rule_id)
                rejected_count += 1
                continue

            start_line = start_node.get("line")
            end_line = end_node.get("line")
            if (
                not isinstance(start_line, int)
                or not isinstance(end_line, int)
                or start_line < 1
                or end_line < start_line
            ):
                logger.warning(
                    "Skipping finding '%s': invalid line range [%s, %s]",
                    rule_id,
                    start_line,
                    end_line,
                )
                rejected_count += 1
                continue

            file_lines = scanned_file.content.splitlines()
            file_line_count = len(file_lines)
            if file_line_count == 0 or start_line > file_line_count:
                logger.warning(
                    "Skipping finding '%s': start line %d exceeds file line count %d",
                    rule_id,
                    start_line,
                    file_line_count,
                )
                rejected_count += 1
                continue

            effective_end_line = min(end_line, file_line_count)
            snippet, snippet_start_line = _extract_snippet(
                scanned_file.content, start_line, effective_end_line
            )
            if not snippet or not snippet.strip():
                logger.warning(
                    "Skipping finding '%s': empty code snippet extracted at [%d, %d]",
                    rule_id,
                    start_line,
                    end_line,
                )
                rejected_count += 1
                continue

            try:
                anchor = compute_code_anchor(snippet)
            except ValueError:
                logger.warning(
                    "Skipping finding '%s': failed to compute anchor for snippet",
                    rule_id,
                )
                rejected_count += 1
                continue

            extra = item.get("extra")
            extra_dict = extra if isinstance(extra, dict) else {}
            metadata = extra_dict.get("metadata")
            meta_dict = metadata if isinstance(metadata, dict) else {}

            message = str(extra_dict.get("message", "")).strip()
            first_line = message.splitlines()[0].strip() if message else ""
            title = (first_line or rule_id)[:120]
            description = (message or title)[:1000]

            severity = _map_severity(extra_dict.get("severity"), meta_dict)
            confidence = _map_confidence(meta_dict.get("confidence"))
            category = _map_category(meta_dict.get("category"), rule_id)

            remediation_text = str(
                meta_dict.get("remediation") or meta_dict.get("fix") or ""
            ).strip()
            if not remediation_text:
                remediation_text = (
                    f"Review and remediate {rule_id} finding according to secure coding guidelines."
                )
            remediation = remediation_text[:1000]

            references = _extract_references(meta_dict)

            raw_metadata = _sanitize_metadata(
                {
                    "check_id": rule_id,
                    "extra": {
                        "message": message[:500],
                        "metadata": meta_dict,
                    },
                }
            )

            intermediate_items.append(
                {
                    "rule_id": rule_id,
                    "source": FindingSource.SEMGREP,
                    "category": category,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "confidence": confidence,
                    "verification_status": VerificationStatus.SCANNER_DETECTED,
                    "file_path": original_path,
                    "start_line": start_line,
                    "end_line": effective_end_line,
                    "snippet": snippet,
                    "snippet_start_line": snippet_start_line,
                    "remediation": remediation,
                    "references": references,
                    "anchor": anchor,
                    "raw": raw_metadata,
                }
            )

        # Assign occurrence indices and construct CanonicalFinding instances
        assigned = assign_occurrence_indices(
            intermediate_items,
            key_func=lambda d: (d["rule_id"], d["file_path"], d["anchor"]),
            line_func=lambda d: d["start_line"],
        )

        canonical_findings: list[CanonicalFinding] = []
        for finding_dict, occ in assigned:
            fp = compute_finding_fingerprint(
                rule_id=finding_dict["rule_id"],
                source=finding_dict["source"].value,
                file_path=finding_dict["file_path"],
                anchor=finding_dict["anchor"],
                occ=occ,
                category=finding_dict["category"].value,
            )
            try:
                canonical = CanonicalFinding(
                    rule_id=finding_dict["rule_id"],
                    source=finding_dict["source"],
                    category=finding_dict["category"],
                    title=finding_dict["title"],
                    description=finding_dict["description"],
                    severity=finding_dict["severity"],
                    confidence=finding_dict["confidence"],
                    verification_status=finding_dict["verification_status"],
                    file_path=finding_dict["file_path"],
                    start_line=finding_dict["start_line"],
                    end_line=finding_dict["end_line"],
                    snippet=finding_dict["snippet"],
                    snippet_start_line=finding_dict["snippet_start_line"],
                    remediation=finding_dict["remediation"],
                    references=finding_dict["references"],
                    in_diff=None,
                    fingerprint=fp,
                    raw=finding_dict["raw"],
                )
                canonical_findings.append(canonical)
            except (ValidationError, ValueError) as err:
                logger.warning(
                    "Skipping finding '%s': validation failed: %s",
                    finding_dict["rule_id"],
                    err,
                )
                rejected_count += 1

        total_raw = len(raw_results)
        if total_raw > 0 and not canonical_findings:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SEMGREP_NORMALIZATION_FAILED",
                error_message=f"Failed to normalize {total_raw} Semgrep findings",
                retryable=False,
                components={"semgrep": "failed"},
            )

        status = (
            ScanStatus.PARTIAL
            if (rejected_count > 0 or has_partial_errors)
            else ScanStatus.SUCCEEDED
        )
        component_status = "partial" if status == ScanStatus.PARTIAL else "passed"

        severity_counts = {
            "critical": sum(
                1 for f in canonical_findings if f.severity == FindingSeverity.CRITICAL
            ),
            "high": sum(1 for f in canonical_findings if f.severity == FindingSeverity.HIGH),
            "medium": sum(1 for f in canonical_findings if f.severity == FindingSeverity.MEDIUM),
            "low": sum(1 for f in canonical_findings if f.severity == FindingSeverity.LOW),
            "info": sum(1 for f in canonical_findings if f.severity == FindingSeverity.INFO),
        }
        counts = {"findings": len(canonical_findings), **severity_counts}

        return ScanExecutionResult(
            status=status,
            components={"semgrep": component_status},
            counts=counts,
            findings=canonical_findings,
        )
