"""API routes for scan creation, status inspection, scan listings, and scan findings.

Implements Blueprint Section 9.3 (Scans API contracts):
- POST /projects/{id}/scans/manual: Enqueue manual analysis batch (202 Accepted)
- GET /projects/{id}/scans: List scans for a project with filters & pagination (200 OK)
- GET /scans: List scans across projects owned by user with filters & pagination (200 OK)
- GET /scans/{id}: Get scan status and summary details (200 OK)
- GET /scans/{id}/findings: List findings for a scan with filters & pagination (200 OK)
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import (
    CurrentUser,
    DbSession,
    verify_project_access,
    verify_scan_access,
)
from app.domain.findings import FindingSeverity, FindingSource, FindingStatus
from app.schemas.finding import FindingListItem, PaginatedFindingsResponse
from app.schemas.scan import (
    ManualScanCreateRequest,
    PaginatedScansResponse,
    ScanCreateResponse,
    ScanDetailResponse,
    ScanListItem,
    ScanStatus,
    ScanTrigger,
)
from app.services.finding_service import list_scan_findings_paginated
from app.services.scan_service import (
    ProjectNotFoundError,
    ScanConflictError,
    ScanPayloadTooLargeError,
    ScanServiceError,
    ScanValidationError,
    UserNotFoundError,
    create_manual_scan,
    list_scans,
)

router = APIRouter(tags=["scans"])


@router.post(
    "/projects/{project_id}/scans/manual",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue manual scan batch",
    description="Synchronously validates submitted files and atomically enqueues a scan and background job.",
)
def create_manual_scan_endpoint(
    project_id: uuid.UUID,
    body: ManualScanCreateRequest,
    session: DbSession,
    user: CurrentUser,
) -> ScanCreateResponse:
    """Validate files and enqueue a manual scan for background processing."""
    verify_project_access(project_id, user, session)

    try:
        scan, _ = create_manual_scan(
            session=session,
            project_id=project_id,
            files=body.files,
            run_ai=body.run_ai,
            trigger_key=body.trigger_key,
            created_by_user_id=user.id,
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ScanPayloadTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(exc),
        ) from exc
    except ScanValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except ScanConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ScanServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while creating the scan and job.",
        ) from exc

    return ScanCreateResponse(
        id=scan.id,
        status=scan.status,
        status_url=f"/api/v1/scans/{scan.id}",
    )


@router.get(
    "/projects/{project_id}/scans",
    response_model=PaginatedScansResponse,
    status_code=status.HTTP_200_OK,
    summary="List project scans",
    description="Retrieve paginated scans for a project with filters and deterministic ordering.",
)
def list_project_scans_endpoint(
    project_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
    status_filter: Annotated[
        list[ScanStatus] | None,
        Query(
            alias="status",
            description="Filter by scan status ('queued', 'running', 'succeeded', 'partial', 'failed', 'canceled', 'superseded', 'skipped').",
        ),
    ] = None,
    trigger: Annotated[
        list[ScanTrigger] | None,
        Query(
            description="Filter by scan trigger type ('manual', 'pull_request', 'rerun').",
        ),
    ] = None,
    pr_number: Annotated[
        int | None,
        Query(
            ge=1,
            description="Filter by pull request number.",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=100,
            description="Maximum number of scans to return per page.",
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Number of scans to skip for pagination.",
        ),
    ] = 0,
) -> PaginatedScansResponse:
    """List scans belonging to a project owned by the authenticated user."""
    verify_project_access(project_id, user, session)

    items, total = list_scans(
        session,
        user_id=user.id,
        project_id=project_id,
        status=status_filter,
        trigger=trigger,
        pr_number=pr_number,
        limit=limit,
        offset=offset,
    )

    return PaginatedScansResponse(
        items=[ScanListItem.from_orm_model(scan) for scan in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/scans",
    response_model=PaginatedScansResponse,
    status_code=status.HTTP_200_OK,
    summary="List scans across projects",
    description="Retrieve paginated scans belonging to the authenticated user across projects.",
)
def list_user_scans_endpoint(
    session: DbSession,
    user: CurrentUser,
    project_id: Annotated[
        uuid.UUID | None,
        Query(description="Optional filter by project ID."),
    ] = None,
    status_filter: Annotated[
        list[ScanStatus] | None,
        Query(
            alias="status",
            description="Filter by scan status ('queued', 'running', 'succeeded', 'partial', 'failed', 'canceled', 'superseded', 'skipped').",
        ),
    ] = None,
    trigger: Annotated[
        list[ScanTrigger] | None,
        Query(
            description="Filter by scan trigger type ('manual', 'pull_request', 'rerun').",
        ),
    ] = None,
    pr_number: Annotated[
        int | None,
        Query(
            ge=1,
            description="Filter by pull request number.",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=100,
            description="Maximum number of scans to return per page.",
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Number of scans to skip for pagination.",
        ),
    ] = 0,
) -> PaginatedScansResponse:
    """List all scans belonging to projects owned by the authenticated user."""
    if project_id is not None:
        verify_project_access(project_id, user, session)

    items, total = list_scans(
        session,
        user_id=user.id,
        project_id=project_id,
        status=status_filter,
        trigger=trigger,
        pr_number=pr_number,
        limit=limit,
        offset=offset,
    )

    return PaginatedScansResponse(
        items=[ScanListItem.from_orm_model(scan) for scan in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/scans/{scan_id}/findings",
    response_model=PaginatedFindingsResponse,
    status_code=status.HTTP_200_OK,
    summary="List scan findings",
    description="Retrieve paginated findings observed in a specific scan with filters, text search, and deterministic ordering.",
    tags=["scans", "findings"],
)
def list_scan_findings_endpoint(
    scan_id: uuid.UUID,
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
            description="Filter by observed scan severity ('critical', 'high', 'medium', 'low', 'info').",
        ),
    ] = None,
    source: Annotated[
        list[FindingSource] | None,
        Query(
            description="Filter by detector source ('semgrep', 'gitleaks', 'ai').",
        ),
    ] = None,
    in_diff: Annotated[
        bool | None,
        Query(
            description="Filter by whether finding is located within git diff.",
        ),
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
        Query(
            ge=1,
            le=100,
            description="Maximum number of findings to return per page.",
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Number of findings to skip for pagination.",
        ),
    ] = 0,
) -> PaginatedFindingsResponse:
    """List findings observed in a specific scan belonging to the authenticated user."""
    scan = verify_scan_access(scan_id, user, session)

    items, total = list_scan_findings_paginated(
        session,
        scan_id=scan.id,
        user_id=user.id,
        status=status_filter,
        severity=severity,
        source=source,
        in_diff=in_diff,
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
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get scan details",
    description="Retrieve current scan status, execution timing, skipped files, and finding counts.",
)
def get_scan_endpoint(
    scan_id: uuid.UUID,
    session: DbSession,
    user: CurrentUser,
) -> ScanDetailResponse:
    """Retrieve full scan summary and status details."""
    scan = verify_scan_access(scan_id, user, session)
    return ScanDetailResponse.from_orm_model(scan)
