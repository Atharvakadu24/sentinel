"""Unified Composite Scanner Engine orchestrating Semgrep and Gitleaks.

Coordinates single-pass repository staging, registered scanner execution,
canonical finding normalization, deterministic deduplication, component status
tracking, cancellation handling, and secret-safe failure aggregation.
Blueprint Section 7 (Worker execution) & Section 10 (Deterministic analysis).
"""

from __future__ import annotations

import inspect
import logging
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.domain.findings import (
    CanonicalFinding,
    FindingReference,
    FindingSeverity,
    FindingSourceRef,
)
from app.services.job_service import sanitize_failure_message
from app.worker.gitleaks import (
    _UNTRUSTED_REPO_CONTROL_FILENAMES,
    GitleaksScannerAdapter,
)
from app.worker.scanner import (
    ScanExecutionResult,
    ScanJobPayload,
    ScannerInterface,
    ScanStatus,
)
from app.worker.semgrep import SemgrepScannerAdapter
from app.worker.staging import StagedWorkspace, StagingCleanupError, StagingError

logger = logging.getLogger(__name__)

DEFAULT_SCANNER_ORDER: tuple[str, ...] = ("semgrep", "gitleaks")
_SEVERITY_KEYS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK: dict[FindingSeverity, int] = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}
_INLINE_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA|AROA)[0-9A-Z]{16}\b"),
    re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    re.compile(r"\bglpat-[0-9a-zA-Z_-]{20,}\b"),
    re.compile(r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\";,]{8,}['\"]?",
        re.IGNORECASE,
    ),
)


def _zero_counts() -> dict[str, int]:
    """Return a clean zero-initialized finding count mapping."""
    counts = {"findings": 0}
    for sev in _SEVERITY_KEYS:
        counts[sev] = 0
    return counts


def _compute_finding_counts(findings: Sequence[CanonicalFinding]) -> dict[str, int]:
    """Recompute severity and total counts over deduplicated canonical findings."""
    counts = _zero_counts()
    counts["findings"] = len(findings)
    for finding in findings:
        sev_key = finding.severity.value
        if sev_key in counts:
            counts[sev_key] += 1
    return counts


def _sanitize_error_message(message: str | None) -> str:
    """Redact potential secret fragments and normalize error message text."""
    if not message:
        return ""
    scrubbed = message
    for pattern in _INLINE_SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return sanitize_failure_message(scrubbed)


def _normalize_scanner_name(name: str) -> str:
    """Validate and normalize a registered scanner component identifier."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Scanner name must be a non-empty string")
    return name.strip().lower()


def _supports_kwarg(scan_fn: Any, kwarg: str) -> bool:
    """Return True if scan_fn accepts `kwarg` as a keyword argument or via **kwargs."""
    try:
        sig = inspect.signature(scan_fn)
    except (TypeError, ValueError):
        return False

    for param in sig.parameters.values():
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if param.name == kwarg and param.kind in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            return True
    return False


def _canonical_sort_key(
    finding: CanonicalFinding,
) -> tuple[str, int, int, str, str, str]:
    """Deterministic ordering key independent of scanner execution timing."""
    return (
        finding.file_path,
        finding.start_line,
        finding.end_line,
        finding.source.value,
        finding.rule_id,
        finding.fingerprint,
    )


def _merge_canonical_pair(
    existing: CanonicalFinding,
    incoming: CanonicalFinding,
) -> CanonicalFinding:
    """Merge two CanonicalFinding objects with an identical fingerprint.

    Preserves all contributing source references without altering distinct
    fields unless merging unique references or selecting higher severity.
    """
    seen_sources: dict[tuple[str, str], FindingSourceRef] = {}
    for item in (existing, incoming):
        primary_key = (item.source.value, item.rule_id)
        if primary_key not in seen_sources:
            seen_sources[primary_key] = FindingSourceRef(
                source=item.source,
                rule_id=item.rule_id,
            )
        for src_ref in item.sources:
            ref_key = (src_ref.source.value, src_ref.rule_id)
            if ref_key not in seen_sources:
                seen_sources[ref_key] = src_ref

    seen_refs: dict[tuple[str, str, str], FindingReference] = {}
    for ref in (*existing.references, *incoming.references):
        key = (ref.type, ref.id, ref.url)
        if key not in seen_refs:
            seen_refs[key] = ref

    merged_severity = (
        incoming.severity
        if _SEVERITY_RANK[incoming.severity] > _SEVERITY_RANK[existing.severity]
        else existing.severity
    )

    return existing.model_copy(
        update={
            "severity": merged_severity,
            "sources": sorted(
                seen_sources.values(),
                key=lambda s: (s.source.value, s.rule_id),
            ),
            "references": sorted(
                seen_refs.values(),
                key=lambda r: (r.type, r.id, r.url),
            ),
        }
    )


def _merge_and_deduplicate_findings(
    raw_findings: Sequence[Any],
) -> tuple[list[CanonicalFinding], int]:
    """Validate canonical findings and deduplicate deterministically by fingerprint.

    Findings at identical file/line locations with distinct rule keys have distinct
    fingerprints and are intentionally preserved as separate canonical findings.

    Returns:
        Tuple of (sorted deduplicated findings, count of invalid findings skipped).
    """
    deduped_by_fingerprint: dict[str, CanonicalFinding] = {}
    invalid_count = 0

    for item in raw_findings:
        try:
            canonical = (
                item
                if isinstance(item, CanonicalFinding)
                else CanonicalFinding.model_validate(item)
            )
        except (ValidationError, TypeError, ValueError) as exc:
            invalid_count += 1
            logger.warning(
                "Composite scanner discarded invalid finding payload (%s)",
                type(exc).__name__,
            )
            continue

        existing = deduped_by_fingerprint.get(canonical.fingerprint)
        if existing is None:
            deduped_by_fingerprint[canonical.fingerprint] = canonical
        else:
            deduped_by_fingerprint[canonical.fingerprint] = _merge_canonical_pair(
                existing,
                canonical,
            )

    sorted_findings = sorted(deduped_by_fingerprint.values(), key=_canonical_sort_key)
    return sorted_findings, invalid_count


@dataclass(frozen=True)
class _ScannerRunOutcome:
    """Captured result and component metadata for a single registered scanner."""

    name: str
    result: ScanExecutionResult
    component_status: str


class CompositeScannerEngine:
    """Unified scanner engine executing registered static & secret analyzers.

    Integrates Semgrep and Gitleaks behind `ScannerInterface`, staging untrusted
    repository files once in a hardened `StagedWorkspace` while excluding untrusted
    repository Gitleaks control files (`.gitleaks.toml`, `.gitleaksignore`).
    """

    def __init__(
        self,
        scanners: (
            Mapping[str, ScannerInterface] | Sequence[tuple[str, ScannerInterface]] | None
        ) = None,
        *,
        semgrep: ScannerInterface | None = None,
        gitleaks: ScannerInterface | None = None,
        workspace_base_dir: str | Path | None = None,
        stop_on_failure: bool = False,
    ) -> None:
        """Initialize the composite scanner engine and its scanner registry.

        Args:
            scanners: Optional ordered mapping or sequence of `(name, scanner)` pairs
                overriding the default `(semgrep, gitleaks)` registry.
            semgrep: Optional custom Semgrep adapter when using default registration.
            gitleaks: Optional custom Gitleaks adapter when using default registration.
            workspace_base_dir: Optional trusted parent directory for shared staging.
            stop_on_failure: If True, abort remaining scanners as soon as one fails.
        """
        if scanners is not None and (semgrep is not None or gitleaks is not None):
            raise ValueError("Pass either 'scanners' or 'semgrep'/'gitleaks' overrides, not both")

        self.workspace_base_dir = (
            Path(workspace_base_dir) if workspace_base_dir is not None else None
        )
        self.stop_on_failure = stop_on_failure
        self._registry: dict[str, ScannerInterface] = {}

        if scanners is not None:
            items = scanners.items() if isinstance(scanners, Mapping) else scanners
            for name, scanner in items:
                self.register(name, scanner)
        else:
            self.register(
                "semgrep",
                semgrep
                if semgrep is not None
                else SemgrepScannerAdapter(workspace_base_dir=self.workspace_base_dir),
            )
            self.register(
                "gitleaks",
                gitleaks
                if gitleaks is not None
                else GitleaksScannerAdapter(workspace_base_dir=self.workspace_base_dir),
            )

    def register(
        self,
        name: str,
        scanner: ScannerInterface,
        *,
        replace: bool = False,
    ) -> None:
        """Register a scanner implementation under `name`."""
        clean_name = _normalize_scanner_name(name)
        if not callable(getattr(scanner, "scan", None)):
            raise TypeError(f"Scanner '{clean_name}' must implement a callable .scan() method")
        if clean_name in self._registry and not replace:
            raise ValueError(f"Scanner '{clean_name}' is already registered")
        self._registry[clean_name] = scanner

    @property
    def registered_scanners(self) -> tuple[str, ...]:
        """Return registered scanner names in configured execution order."""
        return tuple(self._registry.keys())

    def get_scanner(self, name: str) -> ScannerInterface | None:
        """Retrieve a registered scanner by normalized name, if present."""
        return self._registry.get(_normalize_scanner_name(name))

    def _resolve_shared_workspace_base_dir(self) -> Path | None:
        """Resolve a shared base_dir from explicit config or consistent sub-adapters."""
        if self.workspace_base_dir is not None:
            return self.workspace_base_dir

        discovered: dict[Path, Path] = {}
        for scanner in self._registry.values():
            if not _supports_kwarg(scanner.scan, "workspace"):
                continue
            adapter_base = getattr(scanner, "workspace_base_dir", None)
            if adapter_base is not None:
                raw_path = Path(adapter_base)
                discovered.setdefault(raw_path.resolve(), raw_path)

        if len(discovered) == 1:
            return next(iter(discovered.values()))
        if len(discovered) > 1:
            raise StagingError(
                "Conflicting workspace_base_dir configured across registered scanners"
            )
        return None

    def _run_registered_scanners(
        self,
        payload: ScanJobPayload,
        *,
        shared_workspace: StagedWorkspace | None,
        cancel_event: threading.Event | None,
    ) -> tuple[list[_ScannerRunOutcome], bool]:
        """Execute all registered scanners safely in order and capture outcomes."""
        outcomes: list[_ScannerRunOutcome] = []
        canceled = False

        for idx, (name, scanner) in enumerate(self._registry.items()):
            if cancel_event is not None and cancel_event.is_set():
                canceled = True
                for remaining_name in list(self._registry.keys())[idx:]:
                    outcomes.append(
                        _ScannerRunOutcome(
                            name=remaining_name,
                            result=ScanExecutionResult(
                                status=ScanStatus.FAILED,
                                error_code="SCAN_CANCELED",
                                error_message="Scan execution canceled before scanner started",
                                retryable=False,
                                components={remaining_name: "canceled"},
                            ),
                            component_status="canceled",
                        )
                    )
                break

            call_kwargs: dict[str, Any] = {}
            if shared_workspace is not None and _supports_kwarg(scanner.scan, "workspace"):
                call_kwargs["workspace"] = shared_workspace
            if cancel_event is not None and _supports_kwarg(scanner.scan, "cancel_event"):
                call_kwargs["cancel_event"] = cancel_event

            try:
                raw_result = scanner.scan(payload, **call_kwargs)
                if not isinstance(raw_result, ScanExecutionResult):
                    raise TypeError(
                        f"Expected ScanExecutionResult, got {type(raw_result).__name__}"
                    )
                _ = ScanStatus(raw_result.status)
            except Exception as exc:  # noqa: BLE001 - isolate sub-scanner crashes
                exc_name = type(exc).__name__
                logger.error(
                    "Composite scanner: component '%s' raised %s",
                    name,
                    exc_name,
                )
                raw_result = ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code=f"{name.upper()}_UNHANDLED_ERROR",
                    error_message=f"Scanner '{name}' crashed unexpectedly ({exc_name})",
                    retryable=False,
                    components={name: "failed"},
                )

            if raw_result.status == ScanStatus.SUCCEEDED:
                comp_status = "passed"
            elif raw_result.status == ScanStatus.PARTIAL:
                comp_status = "partial"
            else:
                comp_status = "failed"

            outcomes.append(
                _ScannerRunOutcome(
                    name=name,
                    result=raw_result,
                    component_status=comp_status,
                )
            )

            if raw_result.error_code == "SCAN_CANCELED" or (
                cancel_event is not None and cancel_event.is_set()
            ):
                canceled = True
                for remaining_name in list(self._registry.keys())[idx + 1 :]:
                    outcomes.append(
                        _ScannerRunOutcome(
                            name=remaining_name,
                            result=ScanExecutionResult(
                                status=ScanStatus.FAILED,
                                error_code="SCAN_CANCELED",
                                error_message="Scan execution canceled",
                                retryable=False,
                                components={remaining_name: "canceled"},
                            ),
                            component_status="canceled",
                        )
                    )
                break

            if self.stop_on_failure and raw_result.status == ScanStatus.FAILED:
                for remaining_name in list(self._registry.keys())[idx + 1 :]:
                    outcomes.append(
                        _ScannerRunOutcome(
                            name=remaining_name,
                            result=ScanExecutionResult(
                                status=ScanStatus.FAILED,
                                error_code="SCAN_ABORTED_ON_PRIOR_FAILURE",
                                error_message=(f"Skipped after '{name}' scanner failed"),
                                retryable=False,
                                components={remaining_name: "skipped"},
                            ),
                            component_status="skipped",
                        )
                    )
                break

        return outcomes, canceled

    def _aggregate_outcomes(
        self,
        outcomes: Sequence[_ScannerRunOutcome],
        *,
        canceled: bool,
    ) -> ScanExecutionResult:
        """Combine individual scanner outcomes into one canonical ScanExecutionResult."""
        components: dict[str, str] = {}
        validated_findings: list[CanonicalFinding] = []
        invalid_finding_count = 0
        failed_outcomes: list[_ScannerRunOutcome] = []
        partial_outcomes: list[_ScannerRunOutcome] = []
        succeeded_outcomes: list[_ScannerRunOutcome] = []

        for outcome in outcomes:
            if outcome.result.components:
                for comp_key, comp_val in outcome.result.components.items():
                    components[comp_key] = str(comp_val)
            if outcome.name not in components:
                components[outcome.name] = outcome.component_status

            if outcome.result.status in (ScanStatus.SUCCEEDED, ScanStatus.PARTIAL):
                component_findings, comp_invalid = _merge_and_deduplicate_findings(
                    outcome.result.findings
                )
                validated_findings.extend(component_findings)
                invalid_finding_count += comp_invalid
                if comp_invalid > 0 and components.get(outcome.name) == "passed":
                    components[outcome.name] = "partial"

            if outcome.result.status == ScanStatus.SUCCEEDED:
                succeeded_outcomes.append(outcome)
            elif outcome.result.status == ScanStatus.PARTIAL:
                partial_outcomes.append(outcome)
            else:
                failed_outcomes.append(outcome)

        if canceled:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SCAN_CANCELED",
                error_message="Scan execution was canceled before completion",
                retryable=False,
                components=components,
                counts=_zero_counts(),
                findings=[],
            )

        deduped_findings, merge_invalid = _merge_and_deduplicate_findings(validated_findings)
        invalid_finding_count += merge_invalid
        final_counts = _compute_finding_counts(deduped_findings)

        # Case 1: All registered scanners failed -> aggregate terminal failure without partial findings
        if not succeeded_outcomes and not partial_outcomes:
            non_skipped_failures = [
                o for o in failed_outcomes if o.component_status != "skipped"
            ] or failed_outcomes
            retryable = bool(non_skipped_failures) and all(
                o.result.retryable for o in non_skipped_failures
            )
            retry_delays = [
                o.result.retry_delay_sec
                for o in non_skipped_failures
                if o.result.retry_delay_sec is not None and o.result.retry_delay_sec > 0
            ]
            retry_delay_sec = max(retry_delays) if (retryable and retry_delays) else None

            error_codes = [o.result.error_code for o in non_skipped_failures if o.result.error_code]
            unique_codes = set(error_codes)
            if len(unique_codes) == 1:
                agg_error_code = error_codes[0]
            elif error_codes and all(code.endswith("_TIMEOUT") for code in error_codes):
                agg_error_code = "SCANNER_TIMEOUT"
            else:
                agg_error_code = "ALL_SCANNERS_FAILED"

            messages = [
                f"{o.name}: {_sanitize_error_message(o.result.error_message) or 'failed'}"
                for o in failed_outcomes
            ]
            agg_error_message = _sanitize_error_message("; ".join(messages)) or (
                "All registered scanners failed"
            )

            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code=agg_error_code,
                error_message=agg_error_message,
                retryable=retryable,
                retry_delay_sec=retry_delay_sec,
                components=components,
                counts=_zero_counts(),
                findings=[],
            )

        # Case 2: At least one scanner succeeded/partial, with failures or partial/invalid findings
        if failed_outcomes or partial_outcomes or invalid_finding_count > 0:
            issue_outcomes = [*failed_outcomes, *partial_outcomes]
            issue_codes = [o.result.error_code for o in issue_outcomes if o.result.error_code]
            unique_issue_codes = set(issue_codes)

            if len(unique_issue_codes) == 1:
                agg_error_code = issue_codes[0]
            elif failed_outcomes:
                agg_error_code = "COMPOSITE_PARTIAL_FAILURE"
            elif invalid_finding_count > 0 and not issue_codes:
                agg_error_code = "COMPOSITE_INVALID_FINDINGS"
            else:
                agg_error_code = "COMPOSITE_PARTIAL_RESULTS"

            parts: list[str] = []
            for o in issue_outcomes:
                sanitized_msg = _sanitize_error_message(o.result.error_message)
                if sanitized_msg:
                    parts.append(f"{o.name}: {sanitized_msg}")
                else:
                    parts.append(f"{o.name}: {o.component_status}")
            if invalid_finding_count > 0:
                parts.append(f"discarded {invalid_finding_count} invalid finding(s)")

            agg_error_message = _sanitize_error_message("; ".join(parts))

            return ScanExecutionResult(
                status=ScanStatus.PARTIAL,
                error_code=agg_error_code,
                error_message=agg_error_message,
                retryable=False,
                components=components,
                counts=final_counts,
                findings=deduped_findings,
            )

        # Case 3: Every registered scanner succeeded cleanly
        return ScanExecutionResult(
            status=ScanStatus.SUCCEEDED,
            components=components,
            counts=final_counts,
            findings=deduped_findings,
        )

    def scan(
        self,
        payload: ScanJobPayload,
        *,
        workspace: StagedWorkspace | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ScanExecutionResult:
        """Execute all registered scanners over `payload` and aggregate canonical findings."""
        if not self._registry:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="NO_SCANNERS_REGISTERED",
                error_message="CompositeScannerEngine has no registered scanners",
                retryable=False,
                components={},
                counts=_zero_counts(),
                findings=[],
            )

        if cancel_event is not None and cancel_event.is_set():
            canceled_components = {name: "canceled" for name in self._registry}
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SCAN_CANCELED",
                error_message="Scan execution canceled before staging",
                retryable=False,
                components=canceled_components,
                counts=_zero_counts(),
                findings=[],
            )

        scannable_files = [f for f in payload.files if f.scanned]
        needs_shared_workspace = bool(scannable_files) and any(
            _supports_kwarg(scanner.scan, "workspace") for scanner in self._registry.values()
        )

        # Fast-path when payload has no scannable files or no workspace-aware scanners
        if not needs_shared_workspace:
            outcomes, canceled = self._run_registered_scanners(
                payload,
                shared_workspace=workspace,
                cancel_event=cancel_event,
            )
            return self._aggregate_outcomes(outcomes, canceled=canceled)

        # Validate caller-supplied workspace if provided
        if workspace is not None:
            if (
                not isinstance(workspace, StagedWorkspace)
                or workspace._cleaned_up
                or not _UNTRUSTED_REPO_CONTROL_FILENAMES.issubset(workspace._excluded_filenames)
            ):
                return ScanExecutionResult(
                    status=ScanStatus.FAILED,
                    error_code="SCANNER_STAGING_FAILED",
                    error_message=(
                        "Provided staged workspace is invalid or missing Gitleaks control exclusions"
                    ),
                    retryable=False,
                    components={name: "failed" for name in self._registry},
                    counts=_zero_counts(),
                    findings=[],
                )
            outcomes, canceled = self._run_registered_scanners(
                payload,
                shared_workspace=workspace,
                cancel_event=cancel_event,
            )
            return self._aggregate_outcomes(outcomes, canceled=canceled)

        # Stage repository once and share safely across all workspace-aware scanners
        try:
            resolved_base_dir = self._resolve_shared_workspace_base_dir()
            with StagedWorkspace(
                payload.files,
                base_dir=resolved_base_dir,
                exclude_filenames=_UNTRUSTED_REPO_CONTROL_FILENAMES,
            ) as shared_workspace:
                outcomes, canceled = self._run_registered_scanners(
                    payload,
                    shared_workspace=shared_workspace,
                    cancel_event=cancel_event,
                )
            return self._aggregate_outcomes(outcomes, canceled=canceled)
        except StagingCleanupError as exc:
            logger.error(
                "Composite scanner staging workspace cleanup failed: %s",
                type(exc).__name__,
            )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SCANNER_CLEANUP_FAILED",
                error_message="Scanner staging workspace cleanup failed",
                retryable=False,
                components={name: "failed" for name in self._registry},
                counts=_zero_counts(),
                findings=[],
            )
        except StagingError as exc:
            logger.error(
                "Composite scanner repository staging failed: %s",
                type(exc).__name__,
            )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SCANNER_STAGING_FAILED",
                error_message="Scanner repository staging failed",
                retryable=False,
                components={name: "failed" for name in self._registry},
                counts=_zero_counts(),
                findings=[],
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on unexpected orchestrator errors
            logger.error(
                "Composite scanner execution failed unexpectedly: %s",
                type(exc).__name__,
            )
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="SCANNER_EXECUTION_ERROR",
                error_message="Composite scanner execution failed unexpectedly",
                retryable=False,
                components={name: "failed" for name in self._registry},
                counts=_zero_counts(),
                findings=[],
            )
