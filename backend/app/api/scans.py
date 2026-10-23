"""API routes for scan creation and status inspection.

Implements Blueprint Section 9.3 (Scans API contracts):
- POST /projects/{id}/scans/manual: Enqueue manual analysis batch (202 Accepted)
- GET /scans/{id}: Get scan status and summary details (200 OK)
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.schemas.scan import (
    ManualScanCreateRequest,
    ScanCreateResponse,
    ScanDetailResponse,
)
from app.services.scan_service import (
    ProjectNotFoundError,
    ScanConflictError,
    ScanPayloadTooLargeError,
    ScanServiceError,
    ScanValidationError,
    UserNotFoundError,
    create_manual_scan,
    get_scan,
)

router = APIRouter(tags=["scans"])

DbSession = Annotated[Session, Depends(get_db_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]


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
    settings: AppSettings,
) -> ScanCreateResponse:
    """Validate files and enqueue a manual scan for background processing."""
    if (
        settings.APP_ENV not in ("development", "test")
        or not settings.ENABLE_DEV_UNAUTHENTICATED_SCANS
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Authentication required. Scan creation is disabled until session "
                "authentication is active. In development or test environments, set "
                "ENABLE_DEV_UNAUTHENTICATED_SCANS=true to enable unauthenticated testing."
            ),
        )

    try:
        scan, _ = create_manual_scan(
            session=session,
            project_id=project_id,
            files=body.files,
            run_ai=body.run_ai,
            trigger_key=body.trigger_key,
            created_by_user_id=None,  # Never trust client-supplied user identity
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
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get scan details",
    description="Retrieve current scan status, execution timing, skipped files, and finding counts.",
)
def get_scan_endpoint(
    scan_id: uuid.UUID,
    session: DbSession,
) -> ScanDetailResponse:
    """Retrieve full scan summary and status details."""
    scan = get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )
    return ScanDetailResponse.from_orm_model(scan)
