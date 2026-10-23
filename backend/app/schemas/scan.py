"""Pydantic schemas for Scan requests and responses.

Implements Blueprint Section 9.3 (Scans API contracts) and Section 9.6
(Response safety rules: explicit schemas with extra='forbid', no raw ORM leaks,
no full source code returned).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from app.db.models.scan import Scan


class ManualFileInput(BaseModel):
    """A single submitted file for manual analysis (Workflow A)."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        ...,
        description="Relative file path (e.g., 'src/main.py'). Must be forward-slash delimited.",
    )
    content: str = Field(
        ...,
        description="UTF-8 text content of the file.",
    )


class ManualScanCreateRequest(BaseModel):
    """Payload for POST /projects/{id}/scans/manual (Section 9.3)."""

    model_config = ConfigDict(extra="forbid")

    files: list[ManualFileInput] = Field(
        ...,
        description="List of files to analyze (1 to 20 files, each <= 200 KB, total <= 1 MB).",
    )
    run_ai: bool = Field(
        default=True,
        description="Whether to run the AI secondary reviewer if deterministic engines find issues.",
    )
    trigger_key: str | None = Field(
        default=None,
        description="Optional idempotency/trigger key. Defaults to auto-generated UUID key.",
    )


class ScanCreateResponse(BaseModel):
    """202 Accepted response for scan enqueue (Section 9.3)."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Unique scan run identifier.")
    status: str = Field(
        default="queued",
        description="Initial scan status, always 'queued' upon acceptance.",
    )
    status_url: str = Field(
        ...,
        description="URL for polling scan progress (e.g., '/api/v1/scans/{id}').",
    )


class FileSummaryItem(BaseModel):
    """Per-file metadata summary recorded in Scan.files_summary (Workflow A)."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="Normalized relative file path.")
    byte_size: int = Field(..., ge=0, description="Size of file content in bytes.")
    scanned: bool = Field(
        ...,
        description="Whether the file was included in scanning or skipped.",
    )
    skip_reason: str | None = Field(
        default=None,
        description="Reason file was skipped ('unsupported_extension' or 'minified_or_generated').",
    )


class ScanPRDetail(BaseModel):
    """Pull request context for GitHub-triggered scans."""

    model_config = ConfigDict(extra="forbid")

    number: int = Field(..., description="Pull request number.")
    head_sha: str | None = Field(default=None, description="40-character commit SHA.")
    title: str | None = Field(default=None, description="Pull request title.")


class ScanErrorDetail(BaseModel):
    """Error information for failed scans."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., description="Machine-readable error code.")
    message: str = Field(..., description="Human-readable error description.")


class ScanDetailResponse(BaseModel):
    """Full scan detail schema returned by GET /scans/{id} (Section 9.3)."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Unique scan run identifier.")
    project_id: uuid.UUID = Field(..., description="Associated project ID.")
    trigger: str = Field(..., description="Scan trigger type ('manual', 'pull_request', 'rerun').")
    status: str = Field(
        ...,
        description="Current scan status ('queued', 'running', 'succeeded', 'failed', etc.).",
    )
    pr: ScanPRDetail | None = Field(
        default=None,
        description="Pull request details if triggered by a GitHub PR, else null.",
    )
    components: dict[str, Any] | None = Field(
        default=None,
        description="Per-engine component execution status and timing.",
    )
    files_summary: list[FileSummaryItem] | None = Field(
        default=None,
        description="List of files submitted with scanning status and skip reasons.",
    )
    counts: dict[str, int] | None = Field(
        default=None,
        description="Finding counts breakdown by severity.",
    )
    report_status: str = Field(
        default="not_applicable",
        description="GitHub PR comment reporting status.",
    )
    error: ScanErrorDetail | None = Field(
        default=None,
        description="Scan failure details if status is failed, else null.",
    )
    queued_at: datetime = Field(..., description="Timestamp when scan was enqueued.")
    started_at: datetime | None = Field(
        default=None, description="Timestamp when scan execution started."
    )
    finished_at: datetime | None = Field(
        default=None, description="Timestamp when scan execution completed."
    )
    duration_ms: int | None = Field(
        default=None, description="Total scan execution duration in milliseconds."
    )

    @classmethod
    def from_orm_model(cls, scan: Scan) -> ScanDetailResponse:
        """Construct ScanDetailResponse from an ORM Scan instance."""
        pr_detail: ScanPRDetail | None = None
        if scan.pr_number is not None:
            pr_detail = ScanPRDetail(
                number=scan.pr_number,
                head_sha=scan.head_sha,
                title=scan.pr_title,
            )

        error_detail: ScanErrorDetail | None = None
        if scan.error_code or scan.error_message:
            error_detail = ScanErrorDetail(
                code=scan.error_code or "UNKNOWN_ERROR",
                message=scan.error_message or "",
            )

        files_summary_items: list[FileSummaryItem] | None = None
        if scan.files_summary is not None:
            files_summary_items = [
                FileSummaryItem(
                    path=item["path"],
                    byte_size=item["byte_size"],
                    scanned=item["scanned"],
                    skip_reason=item.get("skip_reason"),
                )
                for item in scan.files_summary
            ]

        return cls(
            id=scan.id,
            project_id=scan.project_id,
            trigger=scan.trigger,
            status=scan.status,
            pr=pr_detail,
            components=scan.components,
            files_summary=files_summary_items,
            counts=scan.counts,
            report_status=scan.report_status,
            error=error_detail,
            queued_at=scan.queued_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            duration_ms=scan.duration_ms,
        )
