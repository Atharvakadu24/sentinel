"""Scanner execution interface and isolation boundary.

Defines the contract for static analysis engines (Semgrep, Gitleaks)
without executing unisolated or untrusted host subprocesses.
Blueprint Section 7 (Worker process and queue polling), Section 10
(Deterministic analysis engines), and Threat Mitigation T2 (Isolation).
"""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class ScanStatus(str, Enum):
    """Normalized terminal outcome of a scanner execution batch."""

    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class ScannedFile:
    """Individual file metadata and text content ready for analysis."""

    path: str
    content: str
    scanned: bool = True
    skip_reason: str | None = None


@dataclass(frozen=True)
class ScanJobPayload:
    """Validated in-memory job payload presented to scanner engines."""

    files: list[ScannedFile]
    run_ai: bool = True


@dataclass
class ScanExecutionResult:
    """Structured result returned by a scanner engine execution."""

    status: ScanStatus
    error_code: str | None = None
    error_message: str | None = None
    retryable: bool = False
    retry_delay_sec: int | None = None
    components: dict[str, Any] | None = None
    counts: dict[str, int] | None = None
    findings: list[Any] = field(default_factory=list)


class ScannerInterface(Protocol):
    """Abstract protocol for scanner engine execution."""

    def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
        """Execute analysis over submitted files and return structured results."""
        ...


class DefaultScannerEngine:
    """Default production scanner engine enforcing sandbox isolation verification.

    Threat Mitigation T2: Untrusted source code files must never be scanned directly
    on the host without enforceable, network-disabled, non-root, resource-limited
    container sandbox isolation. If an enforceable sandbox environment is unavailable,
    this engine fails safely and reports the isolation blocker rather than running
    an unsafe host scanner.
    """

    def __init__(
        self,
        *,
        sandbox_available: bool = False,
        scanner: ScannerInterface | None = None,
    ) -> None:
        self.sandbox_available = sandbox_available
        self._delegated_scanner = scanner

    def _get_delegated_scanner(self) -> ScannerInterface:
        if self._delegated_scanner is None:
            from app.worker.composite import CompositeScannerEngine

            self._delegated_scanner = CompositeScannerEngine()
        return self._delegated_scanner

    def scan(
        self,
        payload: ScanJobPayload,
        *,
        cancel_event: threading.Event | None = None,
    ) -> ScanExecutionResult:
        """Scan submitted files only if enforceable isolation is available."""
        if not self.sandbox_available:
            return ScanExecutionResult(
                status=ScanStatus.FAILED,
                error_code="ISOLATION_UNAVAILABLE",
                error_message=(
                    "Host scanner execution is blocked: enforceable network-disabled, "
                    "non-root, resource-limited container sandbox isolation is not available"
                ),
                retryable=False,
            )

        delegated = self._get_delegated_scanner()
        try:
            sig = inspect.signature(delegated.scan)
            accepts_cancel = any(
                p.kind == inspect.Parameter.VAR_KEYWORD
                or (
                    p.name == "cancel_event"
                    and p.kind
                    in (
                        inspect.Parameter.KEYWORD_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                )
                for p in sig.parameters.values()
            )
        except (TypeError, ValueError):
            accepts_cancel = False

        if cancel_event is not None and accepts_cancel:
            return delegated.scan(payload, cancel_event=cancel_event)  # type: ignore[call-arg]
        return delegated.scan(payload)


class CallableScannerEngine:
    """Test adapter wrapping a custom callable function into a ScannerInterface."""

    def __init__(self, func: Callable[[ScanJobPayload], ScanExecutionResult]) -> None:
        self._func = func

    def scan(self, payload: ScanJobPayload) -> ScanExecutionResult:
        return self._func(payload)
