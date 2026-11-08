"""Pydantic schemas for Project listing and queries.

Implements Blueprint Section 8.1 (Projects model contracts) and Section 9.6
(Response safety rules: explicit schemas with extra='forbid', no raw ORM leaks,
no sensitive settings or token exposure).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class ProjectDetailResponse(ProjectListItem):
    """Full details of a project, including configuration settings."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    settings: dict[str, Any] | None = Field(
        default=None,
        description="Optional project-level scan settings and configuration.",
    )

    @classmethod
    def from_orm_model(cls, project: Project) -> ProjectDetailResponse:
        """Construct ProjectDetailResponse from an ORM Project instance."""
        return cls(
            id=project.id,
            name=project.name,
            kind=ProjectKind(project.kind),
            status=ProjectStatus(project.status),
            installation_id=project.installation_id,
            github_repo_id=project.github_repo_id,
            full_name=project.full_name,
            default_branch=project.default_branch,
            settings=project.settings,
            created_at=project.created_at,
            updated_at=project.updated_at,
        )


class ManualProjectCreateRequest(BaseModel):
    """Request payload for manual project creation (Section 9.2)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Display name of the manual project.",
        examples=["backend-service"],
    )
    kind: Literal["manual"] | None = Field(
        default="manual",
        description="Project kind. Must be 'manual' if provided.",
    )
    default_branch: str | None = Field(
        default="main",
        min_length=1,
        max_length=100,
        description="Default branch for scan references (defaults to 'main').",
        examples=["main"],
    )
    settings: dict[str, Any] | None = Field(
        default=None,
        description="Optional project configuration and scan exclusion settings.",
        examples=[{"ignore_paths": ["vendor/", "dist/"]}],
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Project name cannot be empty or whitespace only.")
        if any(c in trimmed for c in "\r\n\t\0"):
            raise ValueError(
                "Project name cannot contain newline, carriage return, tab, or null characters."
            )
        return trimmed

    @field_validator("default_branch")
    @classmethod
    def validate_default_branch(cls, v: str | None) -> str | None:
        if v is None:
            return "main"
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Default branch cannot be empty or whitespace only.")
        if any(c.isspace() or c == "\0" for c in trimmed):
            raise ValueError("Default branch cannot contain whitespace or null characters.")
        return trimmed


class ProjectUpdateRequest(BaseModel):
    """Request payload for updating an existing project (PATCH /projects/{id})."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Updated project display name.",
        examples=["new-project-name"],
    )
    default_branch: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Updated default Git branch (e.g., 'main').",
        examples=["main"],
    )
    settings: dict[str, Any] | None = Field(
        default=None,
        description="Updated project configuration settings (explicit null clears settings).",
        examples=[{"ignore_paths": ["vendor/"]}],
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is None:
            raise ValueError("Project name cannot be null.")
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Project name cannot be empty or whitespace only.")
        if any(c in trimmed for c in "\r\n\t\0"):
            raise ValueError(
                "Project name cannot contain newline, carriage return, tab, or null characters."
            )
        return trimmed

    @field_validator("default_branch")
    @classmethod
    def validate_default_branch(cls, v: str | None) -> str | None:
        if v is None:
            raise ValueError("Default branch cannot be null.")
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Default branch cannot be empty or whitespace only.")
        if any(c.isspace() or c == "\0" for c in trimmed):
            raise ValueError("Default branch cannot contain whitespace or null characters.")
        return trimmed
