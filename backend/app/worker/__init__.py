"""Sentinel background execution worker package.

Implements Blueprint Section 7 (Worker process and queue polling),
Section 8.1 (Job queue mechanics), and Threat Mitigations T2 & T13.
"""

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

__all__ = [
    "CallableScannerEngine",
    "DefaultScannerEngine",
    "JobWorker",
    "PayloadValidationError",
    "ScanExecutionResult",
    "ScanJobPayload",
    "ScanStatus",
    "ScannedFile",
    "ScannerInterface",
    "main",
    "validate_scan_payload",
]
