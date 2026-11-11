"""Sentinel background execution worker package.

Implements Blueprint Section 7 (Worker process and queue polling),
Section 8.1 (Job queue mechanics), and Threat Mitigations T2 & T13.
"""

from app.worker.gitleaks import (
    GitleaksError,
    GitleaksExecutionError,
    GitleaksNormalizationError,
    GitleaksScannerAdapter,
)
from app.worker.payload import PayloadValidationError, validate_scan_payload
from app.worker.runner import JobWorker, main
from app.worker.scanner import (
    CallableScannerEngine,
    DefaultScannerEngine,
    ScanExecutionResult,
    ScanJobPayload,
    ScannedFile,
    ScannerInterface,
    ScanStatus,
)
from app.worker.semgrep import (
    SemgrepError,
    SemgrepExecutionError,
    SemgrepNormalizationError,
    SemgrepScannerAdapter,
)
from app.worker.staging import (
    StagedWorkspace,
    StagingCleanupError,
    StagingDuplicatePathError,
    StagingError,
    StagingPathMappingError,
    StagingPathTraversalError,
    StagingSymlinkError,
)
from app.worker.subprocess_runner import (
    CommandNotFoundError,
    CommandResult,
    CommandStatus,
    CommandTimeoutError,
    NonzeroExitCodeError,
    OutputLimitExceededError,
    SubprocessRunnerError,
    build_sanitized_env,
    run_command_bounded,
)

__all__ = [
    "CallableScannerEngine",
    "CommandNotFoundError",
    "CommandResult",
    "CommandStatus",
    "CommandTimeoutError",
    "DefaultScannerEngine",
    "GitleaksError",
    "GitleaksExecutionError",
    "GitleaksNormalizationError",
    "GitleaksScannerAdapter",
    "JobWorker",
    "NonzeroExitCodeError",
    "OutputLimitExceededError",
    "PayloadValidationError",
    "ScanExecutionResult",
    "ScanJobPayload",
    "ScanStatus",
    "ScannedFile",
    "ScannerInterface",
    "SemgrepError",
    "SemgrepExecutionError",
    "SemgrepNormalizationError",
    "SemgrepScannerAdapter",
    "StagedWorkspace",
    "StagingCleanupError",
    "StagingDuplicatePathError",
    "StagingError",
    "StagingPathMappingError",
    "StagingPathTraversalError",
    "StagingSymlinkError",
    "SubprocessRunnerError",
    "build_sanitized_env",
    "main",
    "run_command_bounded",
    "validate_scan_payload",
]
