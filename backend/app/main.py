"""Sentinel FastAPI application entrypoint.

Provides a minimal, importable application instance (app.main:app)
with public liveness endpoints for the initial backend milestone.
"""

from fastapi import FastAPI

from app.api.findings import router as findings_router
from app.api.health import router as health_router
from app.api.scans import router as scans_router

app = FastAPI(
    title="Sentinel API",
    version="0.1.0",
    description="Sentinel — AI-Powered Code Review & Security Platform Backend",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Root-level routes for probes and direct access
app.include_router(health_router)
app.include_router(scans_router)
app.include_router(findings_router)

# Versioned API routes
app.include_router(health_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
