"""API routes for project listings and management.

Implements Blueprint Section 8.1 (Projects API contracts) and Section 12
(Threat Mitigation T4: Tenant Isolation).
- GET /projects: List projects owned by the authenticated user with filters & pagination (200 OK)
- GET /projects/{project_id}: Get project details and configuration settings (200 OK)
- POST /projects: Create a new manual project for the authenticated user (201 Created)
- PATCH /projects/{project_id}: Update supported fields of an existing project (200 OK)
- DELETE /projects/{project_id}: Soft-delete an existing project (204 No Content)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.api.deps import CurrentUser, DbSession, verify_project_access
from app.db.models.project import Project
from app.schemas.project import (
    ManualProjectCreateRequest,
    PaginatedProjectsResponse,
    ProjectDetailResponse,
    ProjectKind,
    ProjectListItem,
    ProjectStatus,
    ProjectUpdateRequest,
)
from app.services.project_service import (
    ProjectConflictError,
    ProjectServiceError,
    ProjectValidationError,
    create_manual_project,
    list_projects,
    soft_delete_project,
    update_project,
)

router = APIRouter(tags=["projects"])


@router.get(
    "/projects",
    response_model=PaginatedProjectsResponse,
    status_code=status.HTTP_200_OK,
    summary="List projects",
    description="Retrieve paginated projects owned by the authenticated user with filters and deterministic ordering.",
)
def list_projects_endpoint(
    session: DbSession,
    user: CurrentUser,
    kind: Annotated[
        list[ProjectKind] | None,
        Query(description="Filter by project kind ('github', 'manual')."),
    ] = None,
    status_filter: Annotated[
        list[ProjectStatus] | None,
        Query(
            alias="status",
            description="Filter by project status ('active', 'access_lost', 'archived').",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=100,
            description="Maximum number of projects to return per page.",
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Number of projects to skip for pagination.",
        ),
    ] = 0,
) -> PaginatedProjectsResponse:
    """List all projects belonging to the authenticated user."""
    items, total = list_projects(
        session,
        user_id=user.id,
        kind=kind,
        status=status_filter,
        limit=limit,
        offset=offset,
    )

    return PaginatedProjectsResponse(
        items=[ProjectListItem.from_orm_model(p) for p in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/projects/{project_id}",
    response_model=ProjectDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get project details",
    description="Retrieve full project details and settings for a project owned by the authenticated user.",
)
def get_project_endpoint(
    project: Annotated[Project, Depends(verify_project_access)],
) -> ProjectDetailResponse:
    """Retrieve full project details by ID for the authenticated owner."""
    return ProjectDetailResponse.from_orm_model(project)


@router.post(
    "/projects",
    response_model=ProjectDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create manual project",
    description="Create a new manual project owned by the authenticated user.",
)
def create_project_endpoint(
    body: ManualProjectCreateRequest,
    session: DbSession,
    user: CurrentUser,
) -> ProjectDetailResponse:
    """Create a manual project for the authenticated user."""
    try:
        project = create_manual_project(
            session,
            user_id=user.id,
            name=body.name,
            default_branch=body.default_branch,
            settings=body.settings,
        )
    except ProjectConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ProjectValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except ProjectServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while creating the project.",
        ) from exc

    return ProjectDetailResponse.from_orm_model(project)


@router.patch(
    "/projects/{project_id}",
    response_model=ProjectDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Update project",
    description="Update supported fields of an existing project owned by the authenticated user.",
)
def update_project_endpoint(
    project: Annotated[Project, Depends(verify_project_access)],
    body: ProjectUpdateRequest,
    session: DbSession,
) -> ProjectDetailResponse:
    """Update supported fields of an existing project for the authenticated owner."""
    try:
        updated = update_project(
            session,
            project=project,
            name=body.name,
            default_branch=body.default_branch,
            settings=body.settings,
            fields_set=body.model_fields_set,
        )
    except ProjectConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ProjectValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except ProjectServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while updating the project.",
        ) from exc

    return ProjectDetailResponse.from_orm_model(updated)


@router.delete(
    "/projects/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete project",
    description="Soft-delete a project owned by the authenticated user.",
)
def delete_project_endpoint(
    project: Annotated[Project, Depends(verify_project_access)],
    session: DbSession,
) -> Response:
    """Soft-delete an existing project for the authenticated owner."""
    try:
        soft_delete_project(session, project=project)
    except ProjectServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred while deleting the project.",
        ) from exc

    return Response(status_code=status.HTTP_204_NO_CONTENT)
