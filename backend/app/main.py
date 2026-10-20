"""Sentinel FastAPI application entrypoint.

Provides a minimal, importable application instance (app.main:app)
with public liveness endpoints for the initial backend milestone.
"""

from fastapi import FastAPI

from app.api.health import router as health_router

app = FastAPI(
    title="Sentinel API",
    version="0.1.0",
    description="Sentinel — AI-Powered Code Review & Security Platform Backend",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Root-level health check for container/load-balancer liveness probes
app.include_router(health_router)

# Versioned API route
app.include_router(health_router, prefix="/api/v1")
