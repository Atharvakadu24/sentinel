"""API routes for project listings and management.

Implements Blueprint Section 8.1 (Projects API contracts) and Section 12
(Threat Mitigation T4: Tenant Isolation).
- GET /projects: List projects owned by the authenticated user with filters & pagination (200 OK)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.deps import CurrentUser, DbSession
from app.schemas.project import (
    PaginatedProjectsResponse,
    ProjectKind,
    ProjectListItem,
    ProjectStatus,
)
from app.services.project_service import list_projects

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

