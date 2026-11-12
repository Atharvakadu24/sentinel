"""Pydantic schemas for GitHub App onboarding, installations, repositories, and webhooks."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from app.db.models.project import GitHubInstallation


class GitHubInstallUrlResponse(BaseModel):
    """Response containing a CSRF-protected GitHub App installation initiation URL."""

    model_config = ConfigDict(extra="forbid")

    install_url: str = Field(
        ..., description="GitHub App installation URL with single-use state token."
    )
    expires_at: datetime = Field(..., description="UTC timestamp when the state token expires.")


class GitHubInstallationResponse(BaseModel):
    """Sanitized representation of a connected GitHub App installation."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Internal installation record UUID.")
    installation_id: int = Field(..., ge=1, description="GitHub App installation identifier.")
    account_login: str = Field(..., description="GitHub user or organization login.")
    account_type: Literal["User", "Organization"] = Field(..., description="GitHub account type.")
    status: Literal["active", "suspended", "deleted"] = Field(
        ..., description="Synchronized installation lifecycle status."
    )
    permissions: dict[str, Any] | None = Field(
        default=None, description="Granted GitHub App permissions."
    )
    created_at: datetime = Field(..., description="Record creation timestamp.")
    updated_at: datetime = Field(..., description="Last synchronization timestamp.")

    @classmethod
    def from_orm_model(cls, installation: GitHubInstallation) -> GitHubInstallationResponse:
        return cls(
            id=installation.id,
            installation_id=installation.installation_id,
            account_login=installation.account_login,
            account_type=installation.account_type,
            status=installation.status,
            permissions=installation.permissions,
            created_at=installation.created_at,
            updated_at=installation.updated_at,
        )


class GitHubInstallationListResponse(BaseModel):
    """List of connected GitHub App installations for the authenticated user."""

    model_config = ConfigDict(extra="forbid")

    items: list[GitHubInstallationResponse] = Field(..., description="Owned GitHub installations.")
    total: int = Field(..., ge=0, description="Total number of owned installations.")


class GitHubRepositoryItem(BaseModel):
    """GitHub repository accessible to an installation with Sentinel link status."""

    model_config = ConfigDict(extra="forbid")

    id: int = Field(..., ge=1, description="GitHub numeric repository ID.")
    name: str = Field(..., description="Repository short name.")
    full_name: str = Field(..., description="Repository 'owner/name' identifier.")
    default_branch: str = Field(..., description="Default repository branch name.")
    private: bool = Field(..., description="Whether the GitHub repository is private.")
    archived: bool = Field(..., description="Whether the GitHub repository is archived.")
    html_url: str | None = Field(default=None, description="GitHub repository web URL.")
    connected: bool = Field(
        default=False, description="True if currently connected to an active Sentinel project."
    )
    project_id: uuid.UUID | None = Field(
        default=None, description="Linked Sentinel project UUID if connected."
    )


class GitHubRepositoryListResponse(BaseModel):
    """List of repositories accessible through a specific GitHub installation."""

    model_config = ConfigDict(extra="forbid")

    installation_id: int = Field(..., ge=1, description="GitHub installation ID queried.")
    items: list[GitHubRepositoryItem] = Field(..., description="Accessible repositories.")
    total: int = Field(..., ge=0, description="Total accessible repositories returned.")


class GitHubRepoConnectRequest(BaseModel):
    """Request body to connect an accessible GitHub repository to a Sentinel project."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    github_repo_id: int = Field(..., ge=1, description="Numeric GitHub repository ID to connect.")
    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Optional display name override for the Sentinel project.",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Project name cannot be empty or whitespace only.")
        if any(c in trimmed for c in "\r\n\t\0"):
            raise ValueError(
                "Project name cannot contain newline, carriage return, tab, or null characters."
            )
        return trimmed


class GitHubWebhookResponse(BaseModel):
    """Sanitized acknowledgment response returned by POST /webhooks/github."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["processed", "duplicate"] = Field(
        ..., description="Whether the delivery was newly processed or deduplicated."
    )
    delivery_id: str = Field(..., description="GitHub X-GitHub-Delivery identifier.")
    event_type: str = Field(..., description="GitHub X-GitHub-Event name.")
    outcome: str = Field(..., description="Recorded webhook event processing outcome.")
    scan_id: uuid.UUID | None = Field(
        default=None, description="Enqueued or linked scan ID when applicable."
    )
