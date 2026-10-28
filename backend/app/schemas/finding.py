"""Pydantic schemas for Finding queries, detail inspections, and status reviews.

Implements Blueprint Section 9.4 (Findings API contracts) and Section 9.6
(Response safety rules: explicit schemas with extra='forbid', no raw ORM leaks,
never expose raw secrets or credentials).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.domain.findings import (
    AIAssessment,
    FindingCategory,
    FindingConfidence,
    FindingReference,
    FindingSeverity,
    FindingSource,
    FindingSourceRef,
    FindingStatus,
    VerificationStatus,
)


class FindingListItem(BaseModel):
    """Compact summary of a persistent finding for project finding listings."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Unique finding identifier.")
    project_id: uuid.UUID = Field(..., description="Associated project identifier.")
    fingerprint: str = Field(..., description="Deterministic v1 SHA-256 fingerprint.")
    rule_id: str = Field(..., description="Detector rule identifier.")
    source: FindingSource = Field(..., description="Originating detector source.")
    category: FindingCategory = Field(..., description="Vulnerability category.")
    title: str = Field(..., description="Human-readable issue title.")
    file_path: str = Field(..., description="Normalized repository-relative file path.")
    status: FindingStatus = Field(..., description="Persistent lifecycle status.")
    status_reason: str | None = Field(default=None, description="Reason for current status.")
    status_updated_at: datetime | None = Field(
        default=None, description="Timestamp of last status transition."
    )
    status_updated_by: uuid.UUID | None = Field(
        default=None, description="User who performed the last status transition."
    )
    severity: FindingSeverity | None = Field(
        default=None, description="Observed severity from latest scan occurrence."
    )
    confidence: FindingConfidence | None = Field(
        default=None, description="Observed confidence from latest scan occurrence."
    )
    first_seen_scan_id: uuid.UUID | None = Field(
        default=None, description="Scan run where finding was first detected."
    )
    last_seen_scan_id: uuid.UUID | None = Field(
        default=None, description="Scan run where finding was most recently observed."
    )
    first_seen_at: datetime = Field(..., description="Timestamp when first observed.")
    last_seen_at: datetime = Field(..., description="Timestamp when most recently observed.")
    created_at: datetime = Field(..., description="Record creation timestamp.")


class PaginatedFindingsResponse(BaseModel):
    """Paginated list of findings with deterministic pagination metadata."""

    model_config = ConfigDict(extra="forbid")

    items: list[FindingListItem] = Field(..., description="Findings for the requested page.")
    total: int = Field(..., ge=0, description="Total matching findings count across all pages.")
    limit: int = Field(..., ge=1, description="Page size limit applied.")
    offset: int = Field(..., ge=0, description="Pagination offset applied.")


class FindingDetailResponse(BaseModel):
    """Detailed finding view with latest scan-occurrence evidence and safe fields."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Unique finding identifier.")
    project_id: uuid.UUID = Field(..., description="Associated project identifier.")
    fingerprint: str = Field(..., description="Deterministic v1 SHA-256 fingerprint.")
    rule_id: str = Field(..., description="Detector rule identifier.")
    source: FindingSource = Field(..., description="Originating detector source.")
    category: FindingCategory = Field(..., description="Vulnerability category.")
    title: str = Field(..., description="Human-readable issue title.")
    file_path: str = Field(..., description="Normalized repository-relative file path.")
    status: FindingStatus = Field(..., description="Persistent lifecycle status.")
    status_reason: str | None = Field(default=None, description="Reason for current status.")
    status_updated_at: datetime | None = Field(
        default=None, description="Timestamp of last status transition."
    )
    status_updated_by: uuid.UUID | None = Field(
        default=None, description="User who performed the last status transition."
    )
    first_seen_scan_id: uuid.UUID | None = Field(
        default=None, description="Scan run where finding was first detected."
    )
    last_seen_scan_id: uuid.UUID | None = Field(
        default=None, description="Scan run where finding was most recently observed."
    )
    first_seen_at: datetime = Field(..., description="Timestamp when first observed.")
    last_seen_at: datetime = Field(..., description="Timestamp when most recently observed.")
    created_at: datetime = Field(..., description="Record creation timestamp.")

    # Occurrence evidence from the most recent scan observation (raw secret values excluded)
    severity: FindingSeverity | None = Field(
        default=None, description="Observed severity from latest scan."
    )
    confidence: FindingConfidence | None = Field(
        default=None, description="Observed confidence from latest scan."
    )
    verification_status: VerificationStatus | None = Field(
        default=None, description="Verification state of the finding."
    )
    start_line: int | None = Field(default=None, ge=1, description="Starting line in file.")
    end_line: int | None = Field(default=None, ge=1, description="Ending line in file.")
    snippet: str | None = Field(
        default=None, description="Sanitized source snippet (secrets redacted)."
    )
    snippet_start_line: int | None = Field(
        default=None, ge=1, description="First line of the snippet window."
    )
    in_diff: bool | None = Field(
        default=None, description="Whether finding touches changed pull request lines."
    )
    description: str | None = Field(default=None, description="Detailed vulnerability description.")
    remediation: str | None = Field(default=None, description="Actionable remediation guidance.")
    references: list[FindingReference] | None = Field(
        default=None, description="CWE, OWASP, and advisory references."
    )
    sources: list[FindingSourceRef] | None = Field(
        default=None, description="Detector sources contributing to this finding."
    )
    ai_assessment: AIAssessment | None = Field(
        default=None, description="AI triage verdict and rationale if available."
    )


class FindingStatusUpdateRequest(BaseModel):
    """Payload for PATCH /findings/{finding_id}/status review transitions."""

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus = Field(..., description="Target lifecycle status.")
    expected_status: FindingStatus = Field(
        ...,
        description="Expected current status for optimistic concurrency verification.",
    )
    reason: str | None = Field(
        default=None,
        description="Justification for the status review transition (3 to 500 characters when required).",
    )


class FindingStatusHistoryItem(BaseModel):
    """An append-only audit trail entry of a status change."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Unique history record identifier.")
    finding_id: uuid.UUID = Field(..., description="Associated finding identifier.")
    from_status: str = Field(..., description="Previous lifecycle status.")
    to_status: str = Field(..., description="New lifecycle status.")
    actor_type: str = Field(..., description="Actor category ('user' or 'system').")
    actor_user_id: uuid.UUID | None = Field(
        default=None, description="User ID of the actor if actor_type is 'user'."
    )
    reason: str | None = Field(default=None, description="Justification for the change.")
    scan_id: uuid.UUID | None = Field(
        default=None, description="Scan ID if change was system-driven during scan."
    )
    created_at: datetime = Field(..., description="Timestamp of the transition.")


class PaginatedFindingHistoryResponse(BaseModel):
    """Paginated list of status history audit entries with deterministic pagination."""

    model_config = ConfigDict(extra="forbid")

    items: list[FindingStatusHistoryItem] = Field(
        ..., description="History entries for the requested page."
    )
    total: int = Field(..., ge=0, description="Total history records count.")
    limit: int = Field(..., ge=1, description="Page size limit applied.")
    offset: int = Field(..., ge=0, description="Pagination offset applied.")
