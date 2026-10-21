"""Unit tests for Alembic offline and disposable test migration infrastructure."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import alembic.autogenerate as autogen
import sqlalchemy as sa
from alembic.config import Config
from alembic.migration import MigrationContext

from alembic import command
from app.db.base import Base


def _get_alembic_config() -> Config:
    backend_dir = Path(__file__).resolve().parent.parent
    ini_path = backend_dir / "alembic.ini"
    assert ini_path.is_file(), f"alembic.ini not found at {ini_path}"

    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    return cfg


def test_offline_migration_sql_generation() -> None:
    """Verify Alembic offline migration generates valid PostgreSQL DDL for all 11 tables."""
    cfg = _get_alembic_config()

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


def test_offline_downgrade_sql_generation() -> None:
    """Verify Alembic offline downgrade generates valid DROP TABLE statements in dependency order."""
    cfg = _get_alembic_config()

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        command.downgrade(cfg, "head:base", sql=True)

    generated_sql = buffer.getvalue()
    assert len(generated_sql) > 0

    expected_drops = [
        "DROP TABLE ai_reviews;",
        "DROP TABLE webhook_events;",
        "DROP TABLE finding_status_history;",
        "DROP TABLE scan_findings;",
        "DROP TABLE findings;",
        "DROP TABLE jobs;",
        "DROP TABLE scans;",
        "DROP TABLE projects;",
        "DROP TABLE github_installations;",
        "DROP TABLE user_sessions;",
        "DROP TABLE users;",
    ]

    for expected in expected_drops:
        assert expected in generated_sql, f"Expected '{expected}' in downgrade SQL"

    # Verify reverse dependency ordering (dependents dropped before dependencies)
    scans_drop_idx = generated_sql.index("DROP TABLE scans;")
    projects_drop_idx = generated_sql.index("DROP TABLE projects;")
    findings_drop_idx = generated_sql.index("DROP TABLE findings;")
    scan_findings_drop_idx = generated_sql.index("DROP TABLE scan_findings;")

    assert scan_findings_drop_idx < scans_drop_idx
    assert scan_findings_drop_idx < findings_drop_idx
    assert scans_drop_idx < projects_drop_idx
    assert findings_drop_idx < projects_drop_idx


def test_disposable_infrastructure_migration_lifecycle() -> None:
    """Test full upgrade, autogenerate drift check, and downgrade against disposable SQLite."""
    cfg = _get_alembic_config()
    engine = sa.create_engine("sqlite:///:memory:")

    @sa.event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    with engine.connect() as conn:
        cfg.attributes["connection"] = conn

        # 1. Upgrade to head
        command.upgrade(cfg, "head")

        inspector = sa.inspect(conn)
        tables = set(inspector.get_table_names())
        expected_tables = {
            "users",
            "user_sessions",
            "github_installations",
            "projects",
            "scans",
            "jobs",
            "findings",
            "scan_findings",
            "finding_status_history",
            "webhook_events",
            "ai_reviews",
            "alembic_version",
        }
        assert expected_tables.issubset(tables)

        # 2. Check schema drift between Base.metadata and migrated schema
        mc = MigrationContext.configure(conn)
        diff = autogen.compare_metadata(mc, Base.metadata)
        assert diff == [], f"Detected unexpected schema drift between migration and Base: {diff}"

        # 3. Downgrade to base
        command.downgrade(cfg, "base")

        inspector_after = sa.inspect(conn)
        remaining = set(inspector_after.get_table_names()) - {"alembic_version"}
        assert len(remaining) == 0, f"Tables still remaining after downgrade: {remaining}"


def test_injected_connection_is_used_without_network() -> None:
    """Verify that when config.attributes['connection'] is provided, no network/engine creation occurs."""
    cfg = _get_alembic_config()
    # Set an intentionally unreachable URL to prove it is NOT contacted when connection is injected
    cfg.set_main_option("sqlalchemy.url", "postgresql://unreachable-host:9999/dummy")
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.connect() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
        inspector = sa.inspect(conn)
        assert "scans" in inspector.get_table_names()
        command.downgrade(cfg, "base")


def test_drift_detection_identifies_deliberate_schema_mismatch() -> None:
    """Demonstrate that autogen.compare_metadata meaningfully detects discrepancies."""
    cfg = _get_alembic_config()
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.connect() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")

        mc = MigrationContext.configure(conn)
        assert autogen.compare_metadata(mc, Base.metadata) == []

        # Create a clone of Base.metadata with an unmigrated table
        mismatched_metadata = sa.MetaData()
        for table in Base.metadata.tables.values():
            table.to_metadata(mismatched_metadata)
        sa.Table(
            "unmigrated_audit_log",
            mismatched_metadata,
            sa.Column("id", sa.Integer, primary_key=True),
        )

        diff = autogen.compare_metadata(mc, mismatched_metadata)
        assert len(diff) > 0, "compare_metadata failed to detect unmigrated table mismatch!"
        assert any(d[0] == "add_table" and d[1].name == "unmigrated_audit_log" for d in diff)
