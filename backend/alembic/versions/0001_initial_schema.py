"""Initial Sentinel database schema baseline.

Revision ID: 0001
Revises: None
Create Date: 2026-10-21 00:00:00.000000

Implements Blueprint Section 8.1 (11 core tables):
1. users
2. user_sessions
3. github_installations
4. projects
5. scans
6. jobs
7. findings
8. scan_findings
9. finding_status_history
10. webhook_events
11. ai_reviews
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("github_user_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("github_login", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 2. user_sessions
    op.create_table(
        "user_sessions",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.LargeBinary(32), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])

    # 3. github_installations
    op.create_table(
        "github_installations",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("installation_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column(
            "owner_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("account_login", sa.Text(), nullable=False),
        sa.Column("account_type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("permissions", json_type, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "account_type IN ('User', 'Organization')",
            name="ck_github_installations_account_type",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'deleted')",
            name="ck_github_installations_status",
        ),
    )
    op.create_index(
        "ix_github_installations_owner_user_id", "github_installations", ["owner_user_id"]
    )

    # 4. projects
    op.create_table(
        "projects",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "owner_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "installation_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("github_installations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=True),
        sa.Column("full_name", sa.Text(), nullable=True),
        sa.Column("default_branch", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("settings", json_type, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('github', 'manual')",
            name="ck_projects_kind",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'access_lost', 'archived')",
            name="ck_projects_status",
        ),
        sa.CheckConstraint(
            "kind <> 'github' OR (installation_id IS NOT NULL AND github_repo_id IS NOT NULL)",
            name="ck_projects_github_fields",
        ),
    )
    op.create_index("ix_projects_owner_user_id", "projects", ["owner_user_id"])
    op.create_index("ix_projects_installation_id", "projects", ["installation_id"])
    op.create_index("ix_projects_owner_created", "projects", ["owner_user_id", "created_at"])
    op.create_index(
        "uq_projects_installation_repo",
        "projects",
        ["installation_id", "github_repo_id"],
        unique=True,
        postgresql_where=sa.text("kind = 'github'"),
    )

    # 5. scans
    op.create_table(
        "scans",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "project_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("trigger", sa.Text(), nullable=False),
        sa.Column("trigger_key", sa.Text(), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("head_sha", sa.Text(), nullable=True),
        sa.Column("base_sha", sa.Text(), nullable=True),
        sa.Column("pr_title", sa.String(200), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="queued"),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("components", json_type, nullable=True),
        sa.Column("files_summary", json_type, nullable=True),
        sa.Column("counts", json_type, nullable=True),
        sa.Column("report_status", sa.Text(), nullable=False, server_default="not_applicable"),
        sa.Column("report_error", sa.Text(), nullable=True),
        sa.Column(
            "rerun_of",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "queued_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("project_id", "trigger_key", name="uq_scans_project_trigger"),
        sa.CheckConstraint(
            "trigger IN ('manual', 'pull_request', 'rerun')",
            name="ck_scans_trigger",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'partial', 'failed', "
            "'canceled', 'superseded', 'skipped')",
            name="ck_scans_status",
        ),
        sa.CheckConstraint(
            "report_status IN ('not_applicable', 'pending', 'published', 'failed')",
            name="ck_scans_report_status",
        ),
        sa.CheckConstraint(
            "head_sha IS NULL OR length(head_sha) = 40",
            name="ck_scans_head_sha_length",
        ),
    )
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_scans_project_created", "scans", ["project_id", "created_at"])
    op.create_index(
        "ix_scans_project_pr_sha", "scans", ["project_id", "pr_number", "head_sha"]
    )
    op.create_index(
        "ix_scans_active_status",
        "scans",
        ["status"],
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    # 6. jobs
    op.create_table(
        "jobs",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column("type", sa.Text(), nullable=False, server_default="scan"),
        sa.Column("status", sa.Text(), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column(
            "run_after",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("locked_by", sa.Text(), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", json_type, nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'dead')",
            name="ck_jobs_status",
        ),
    )
    op.create_index("ix_jobs_status_run_after", "jobs", ["status", "run_after"])

    # 7. findings
    op.create_table(
        "findings",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "project_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("fingerprint", sa.CHAR(64), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="open"),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status_updated_by",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "first_seen_scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "last_seen_scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "project_id", "fingerprint", name="uq_findings_project_fingerprint"
        ),
        sa.CheckConstraint(
            "source IN ('semgrep', 'gitleaks', 'ai')",
            name="ck_findings_source",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'fixed', 'accepted', 'dismissed', 'false_positive')",
            name="ck_findings_status",
        ),
    )
    op.create_index("ix_findings_project_id", "findings", ["project_id"])
    op.create_index("ix_findings_project_status", "findings", ["project_id", "status"])
    op.create_index(
        "ix_findings_project_last_seen", "findings", ["project_id", "last_seen_at"]
    )
    op.create_index(
        "ix_findings_project_file_path", "findings", ["project_id", "file_path"]
    )

    # 8. scan_findings
    op.create_table(
        "scan_findings",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Text(), nullable=False),
        sa.Column("verification_status", sa.Text(), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("end_line", sa.Integer(), nullable=False),
        sa.Column("snippet", sa.Text(), nullable=False),
        sa.Column("snippet_start_line", sa.Integer(), nullable=True),
        sa.Column("in_diff", sa.Boolean(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("references", json_type, nullable=True),
        sa.Column("sources", json_type, nullable=True),
        sa.Column("ai_assessment", json_type, nullable=True),
        sa.Column("raw", json_type, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("scan_id", "finding_id", name="uq_scan_findings_scan_finding"),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_scan_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_scan_findings_confidence",
        ),
        sa.CheckConstraint(
            "verification_status IN ('scanner_detected', 'ai_corroborated', "
            "'ai_grounded', 'ai_unverified')",
            name="ck_scan_findings_verification_status",
        ),
    )
    op.create_index("ix_scan_findings_scan_id", "scan_findings", ["scan_id"])
    op.create_index("ix_scan_findings_finding_id", "scan_findings", ["finding_id"])
    op.create_index(
        "ix_scan_findings_scan_severity", "scan_findings", ["scan_id", "severity"]
    )

    # 9. finding_status_history
    op.create_table(
        "finding_status_history",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "finding_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("from_status", sa.Text(), nullable=False),
        sa.Column("to_status", sa.Text(), nullable=False),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'system')",
            name="ck_finding_status_history_actor_type",
        ),
    )
    op.create_index(
        "ix_finding_status_history_finding_id", "finding_status_history", ["finding_id"]
    )
    op.create_index(
        "ix_finding_status_history_created",
        "finding_status_history",
        ["finding_id", "created_at"],
    )

    # 10. webhook_events
    op.create_table(
        "webhook_events",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("delivery_id", sa.Text(), nullable=False, unique=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=True),
        sa.Column("github_installation_id", sa.BigInteger(), nullable=True),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=True),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("head_sha", sa.Text(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('accepted', 'ignored_event', 'ignored_draft', 'no_project', 'error')",
            name="ck_webhook_events_outcome",
        ),
    )

    # 11. ai_reviews
    op.create_table(
        "ai_reviews",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column(
            "owner_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("prompt_version", sa.Text(), nullable=False),
        sa.Column("calls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("retries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("est_cost_usd", sa.Numeric(10, 6), nullable=True),
        sa.Column("claims_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claims_valid", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claims_rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("schema_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejections", json_type, nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_ai_reviews_owner_user_id", "ai_reviews", ["owner_user_id"])
    op.create_index(
        "ix_ai_reviews_owner_created", "ai_reviews", ["owner_user_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("ai_reviews")
    op.drop_table("webhook_events")
    op.drop_table("finding_status_history")
    op.drop_table("scan_findings")
    op.drop_table("findings")
    op.drop_table("jobs")
    op.drop_table("scans")
    op.drop_table("projects")
    op.drop_table("github_installations")
    op.drop_table("user_sessions")
    op.drop_table("users")
