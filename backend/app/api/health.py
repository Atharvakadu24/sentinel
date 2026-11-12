"""Health, liveness, and readiness probe router.

Matches Blueprint Section 9.5 (Webhook and health endpoints):
- GET /healthz: Public liveness check returning {"status": "ok"}
- GET /readyz: Readiness check verifying DB connectivity and GitHub App readiness
"""

from typing import Literal

import sqlalchemy as sa
from fastapi import APIRouter, Response, status
from pydantic import BaseModel, ConfigDict

from app.api.deps import AppSettings, DbSession

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Liveness probe response schema."""

    model_config = ConfigDict(extra="forbid")

    status: str = "ok"


class GitHubReadinessStatus(BaseModel):
    """Sanitized GitHub App integration configuration status (zero secrets)."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["configured", "partial", "unconfigured"]
    configured: bool
    app_configured: bool
    webhook_configured: bool


class ReadinessResponse(BaseModel):
    """Readiness probe response schema."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ready", "unavailable"]
    database: Literal["ok", "unavailable"]
    github: GitHubReadinessStatus


@router.get("/healthz", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Basic liveness probe. Returns 200 with status 'ok'."""
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=ReadinessResponse)
def readiness_check(
    response: Response,
    session: DbSession,
    settings: AppSettings,
) -> ReadinessResponse:
    """Verify database connectivity and report sanitized GitHub integration readiness."""
    db_ok = True
    try:
        session.execute(sa.text("SELECT 1"))
    except Exception:  # noqa: BLE001 - fail closed without leaking DB details
        db_ok = False

    app_configured = settings.is_github_app_configured()
    webhook_configured = settings.is_github_webhook_configured()
    both_configured = app_configured and webhook_configured
    if both_configured:
        gh_status: Literal["configured", "partial", "unconfigured"] = "configured"
    elif app_configured or webhook_configured or settings.has_partial_github_config():
        gh_status = "partial"
    else:
        gh_status = "unconfigured"

    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ready" if db_ok else "unavailable",
        database="ok" if db_ok else "unavailable",
        github=GitHubReadinessStatus(
            status=gh_status,
            configured=both_configured,
            app_configured=app_configured,
            webhook_configured=webhook_configured,
        ),
    )
