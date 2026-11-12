"""Pydantic schemas for User profile and identity representations.

Implements Blueprint Section 8.1 (users model contracts).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.user import User


class UserResponse(BaseModel):
    """User profile response representation for the authenticated user."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID = Field(
        ...,
        description="Unique identifier for the user account (tenant identity).",
    )
    github_user_id: int = Field(
        ...,
        description="Unique numeric GitHub user ID.",
    )
    github_login: str = Field(
        ...,
        description="GitHub username/login handle.",
    )
    display_name: str | None = Field(
        default=None,
        description="User display name if provided by GitHub.",
    )
    avatar_url: str | None = Field(
        default=None,
        description="URL to the user's GitHub avatar image.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp of when the user account was created.",
    )
    last_login_at: datetime | None = Field(
        default=None,
        description="UTC timestamp of the user's most recent login.",
    )

    @classmethod
    def from_orm_model(cls, user: User) -> UserResponse:
        """Construct UserResponse from an ORM User instance."""
        return cls(
            id=user.id,
            github_user_id=user.github_user_id,
            github_login=user.github_login,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )


class GitHubAuthUrlResponse(BaseModel):
    """Response containing the single-use GitHub OAuth authorize URL and expiration."""

    model_config = ConfigDict(extra="forbid")

    authorize_url: str = Field(
        ...,
        description="GitHub OAuth authorize URL containing a single-use CSRF state token.",
    )
    expires_at: datetime = Field(
        ...,
        description="UTC timestamp when the login OAuth state expires.",
    )


class GitHubAuthSessionResponse(BaseModel):
    """Safe session confirmation returned on OAuth login callback completion (no raw token)."""

    model_config = ConfigDict(extra="forbid")

    user: UserResponse = Field(
        ...,
        description="Authenticated user profile.",
    )
    expires_at: datetime = Field(
        ...,
        description="UTC timestamp when the newly issued session expires.",
    )
