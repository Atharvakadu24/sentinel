"""Unit tests for Alembic offline migration SQL generation."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

from alembic.config import Config

from alembic import command


def test_offline_migration_sql_generation() -> None:
    """Verify Alembic offline migration generates valid PostgreSQL DDL for all 11 tables."""
    backend_dir = Path(__file__).resolve().parent.parent
    ini_path = backend_dir / "alembic.ini"
    assert ini_path.is_file(), f"alembic.ini not found at {ini_path}"

    cfg = Config(str(ini_path))
    # Ensure alembic resolves relative to backend directory
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        command.upgrade(cfg, "head", sql=True)

    generated_sql = buffer.getvalue()
    assert len(generated_sql) > 0

    expected_tables = [
        "CREATE TABLE users",
        "CREATE TABLE user_sessions",
        "CREATE TABLE github_installations",
        "CREATE TABLE projects",
        "CREATE TABLE scans",
        "CREATE TABLE jobs",
        "CREATE TABLE findings",
        "CREATE TABLE scan_findings",
        "CREATE TABLE finding_status_history",
        "CREATE TABLE webhook_events",
        "CREATE TABLE ai_reviews",
    ]

    for expected in expected_tables:
        assert expected in generated_sql, f"Expected '{expected}' in generated SQL"
