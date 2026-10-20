"""Shared pytest fixtures and path configuration."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on sys.path for direct imports
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest


@pytest.fixture
def sample_fingerprint_key() -> str:
    """Deterministic, synthetic mock key for fingerprint tests. Never a real secret."""
    return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def sample_sql_injection_code() -> str:
    """Sample vulnerable python code snippet for testing."""
    return """def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = '{user_id}'"\n    return db.execute(query)\n"""


@pytest.fixture
def sample_secret_value() -> str:
    """Synthetic dummy credential string for testing secret anchor hashing."""
    return "mock_api_token_prefix_synthetic_test_token_12345"
