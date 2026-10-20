"""Unit tests for Sentinel FastAPI health and liveness probe (Blueprint Section 9.5)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


def test_root_healthz(client: TestClient) -> None:
    """Verify root /healthz liveness probe returns 200 and status ok."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["content-type"] == "application/json"


def test_versioned_api_healthz(client: TestClient) -> None:
    """Verify versioned /api/v1/healthz endpoint returns 200 and status ok."""
    response = client.get("/api/v1/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
