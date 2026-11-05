"""Pydantic schemas for Project listing and queries.

Implements Blueprint Section 8.1 (Projects model contracts) and Section 9.6
(Response safety rules: explicit schemas with extra='forbid', no raw ORM leaks,
no sensitive settings or token exposure).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from app.db.models.project import Project


class ProjectKind(str, Enum):
    """Project kinds matching ck_projects_kind."""

    GITHUB = "github"
    MANUAL = "manual"


class ProjectStatus(str, Enum):
    """Project lifecycle statuses matching ck_projects_status."""

    ACTIVE = "active"
    ACCESS_LOST = "access_lost"
    ARCHIVED = "archived"


class ProjectListItem(BaseModel):
    """Compact summary of a project for project listings."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Unique project identifier.")
    name: str = Field(..., description="Project display or repository name.")
    kind: ProjectKind = Field(..., description="Project kind ('github', 'manual').")
    status: ProjectStatus = Field(
        ..., description="Current project status ('active', 'access_lost', 'archived')."
    )
    installation_id: uuid.UUID | None = Field(
        default=None, description="Associated GitHub App installation ID, if linked."
    )
    github_repo_id: int | None = Field(default=None, description="GitHub repository ID, if linked.")
    full_name: str | None = Field(
        default=None, description="GitHub repository full name (e.g., 'owner/repo')."
    )
    default_branch: str | None = Field(
        default=None, description="Default repository branch (e.g., 'main')."
    )
    created_at: datetime = Field(..., description="Timestamp when project was created.")
    updated_at: datetime = Field(..., description="Timestamp when project was last updated.")

    @classmethod
    def from_orm_model(cls, project: Project) -> ProjectListItem:
        """Construct ProjectListItem from an ORM Project instance."""
        return cls(
            id=project.id,
            name=project.name,
            kind=ProjectKind(project.kind),
            status=ProjectStatus(project.status),
            installation_id=project.installation_id,
            github_repo_id=project.github_repo_id,
            full_name=project.full_name,
            default_branch=project.default_branch,
            created_at=project.created_at,
            updated_at=project.updated_at,
        )


class PaginatedProjectsResponse(BaseModel):
    """Paginated project list response."""

    model_config = ConfigDict(extra="forbid")

    items: list[ProjectListItem] = Field(..., description="Projects for the requested page.")
    total: int = Field(..., ge=0, description="Total projects matching filters.")
    limit: int = Field(..., ge=1, description="Page size limit applied.")
    offset: int = Field(..., ge=0, description="Pagination offset applied.")


ProjectListResponse = PaginatedProjectsResponse
