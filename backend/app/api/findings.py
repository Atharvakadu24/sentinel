"""API routes for finding queries, detail inspections, and status reviews.

Implements Blueprint Section 9.4 (Findings API contracts):
- GET /projects/{project_id}/findings: List persistent findings with filters & pagination
- GET /findings/{finding_id}: Get finding details and latest scan-occurrence evidence
- PATCH /findings/{finding_id}/status: Triage or update status with optimistic concurrency & audit trail
- GET /findings/{finding_id}/history: View paginated status transition history
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import CurrentUser, DbSession, verify_finding_access, verify_project_access
from app.domain.findings import FindingSeverity, FindingSource, FindingStatus
from app.schemas.finding import (
    FindingDetailResponse,
    FindingListItem,
    FindingStatusHistoryItem,
    FindingStatusUpdateRequest,
    PaginatedFindingHistoryResponse,
    PaginatedFindingsResponse,
)
from app.services.finding_service import (
    FindingNotFoundError,
    FindingStatusConflictError,
    InvalidStatusReasonError,
    InvalidStatusTransitionError,
    get_finding_detail,
    list_finding_history,
    list_project_findings,
    update_finding_status,
)

router = APIRouter(tags=["findings"])


@router.get(
    "/projects/{project_id}/findings",
    response_model=PaginatedFindingsResponse,
    status_code=status.HTTP_200_OK,
    summary="List project findings",
    description="Retrieve paginated persistent findings for a project with filters, text search, and deterministic ordering.",
)
def list_findings_endpoint(
    project_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
    status_filter: Annotated[
        list[FindingStatus] | None,
        Query(
            alias="status",
            description="Filter by persistent status ('open', 'fixed', 'accepted', 'dismissed', 'false_positive').",
        ),
    ] = None,
    severity: Annotated[
        list[FindingSeverity] | None,
        Query(
            description="Filter by latest observed severity ('critical', 'high', 'medium', 'low', 'info')."
        ),
    ] = None,
    source: Annotated[
        list[FindingSource] | None,
        Query(description="Filter by detector source ('semgrep', 'gitleaks', 'ai')."),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=100,
            description="Case-insensitive substring search across title, file path, and rule ID.",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Maximum number of findings to return per page."),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Number of findings to skip for pagination."),
    ] = 0,
) -> PaginatedFindingsResponse:
    """List persistent findings with filters and deterministic pagination."""
    verify_project_access(project_id, user, session)

    items, total = list_project_findings(
        session,
        project_id=project_id,
        status=status_filter,
        severity=severity,
        source=source,
        q=q,
        limit=limit,
        offset=offset,
    )

    return PaginatedFindingsResponse(
        items=[FindingListItem.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get finding details",
    description="Retrieve finding details and latest scan-occurrence evidence with zero secret exposure.",
)
def get_finding_endpoint(
    finding_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
) -> FindingDetailResponse:
    """Retrieve details and safe occurrence evidence for a persistent finding."""
    verify_finding_access(finding_id, user, session)

    detail = get_finding_detail(session, finding_id)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found",
        )

    return FindingDetailResponse.model_validate(detail)


@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Update finding status",
    description="Review or transition finding status with optimistic concurrency guard and audit trail recording.",
)
def update_finding_status_endpoint(
    finding_id: uuid.UUID,
    body: FindingStatusUpdateRequest,
    session: DbSession,
    user: CurrentUser,
) -> FindingDetailResponse:
    """Update finding status with domain transition checks and atomic history insertion."""
    verify_finding_access(finding_id, user, session)

    try:
        update_finding_status(
            session,
            finding_id=finding_id,
            new_status=body.status,
            expected_status=body.expected_status,
            reason=body.reason,
            user_id=user.id,
            auto_commit=True,
        )
    except FindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except FindingStatusConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except (InvalidStatusTransitionError, InvalidStatusReasonError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    detail = get_finding_detail(session, finding_id)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found",
        )

    return FindingDetailResponse.model_validate(detail)


@router.get(
    "/findings/{finding_id}/history",
    response_model=PaginatedFindingHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get finding status history",
    description="Retrieve paginated, deterministically ordered append-only status transition history.",
)
def get_finding_history_endpoint(
    finding_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Maximum number of history records to return per page."),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Number of history records to skip for pagination."),
    ] = 0,
) -> PaginatedFindingHistoryResponse:
    """Retrieve paginated status history in deterministic reverse chronological order."""
    verify_finding_access(finding_id, user, session)

    try:
        items, total = list_finding_history(
            session,
            finding_id=finding_id,
            limit=limit,
            offset=offset,
        )
    except FindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    history_items = [
        FindingStatusHistoryItem(
            id=item.id,
            finding_id=item.finding_id,
            from_status=item.from_status,
            to_status=item.to_status,
            actor_type=item.actor_type,
            actor_user_id=item.actor_user_id,
            reason=item.reason,
            scan_id=item.scan_id,
            created_at=item.created_at,
        )
        for item in items
    ]

    return PaginatedFindingHistoryResponse(
        items=history_items,
        total=total,
        limit=limit,
        offset=offset,
    )
