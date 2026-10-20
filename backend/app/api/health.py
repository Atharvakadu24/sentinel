"""Health and liveness probe router.

Matches Blueprint Section 9.5 (Webhook and health endpoints):
- GET /healthz: Public liveness check returning {"status": "ok"}
"""

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Liveness probe response schema."""

    model_config = ConfigDict(extra="forbid")

    status: str = "ok"


@router.get("/healthz", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Basic liveness probe. Returns 200 with status 'ok'."""
    return HealthResponse(status="ok")
