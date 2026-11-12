"""Add auth_login_states table for GitHub OAuth login flow.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create auth_login_states table and index."""
    op.create_table(
        "auth_login_states",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("state_hash", sa.Text(), nullable=False),
        sa.Column("tx_nonce_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column(
            "purpose",
            sa.Text(),
            server_default="github_oauth_login",
            nullable=False,
        ),
        sa.Column("redirect_uri", sa.Text(), nullable=True),
        sa.Column("next_path", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "purpose = 'github_oauth_login'",
            name="ck_auth_login_states_purpose",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("state_hash"),
    )
    op.create_index(
        "ix_auth_login_states_expires_at",
        "auth_login_states",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop auth_login_states index and table."""
    op.drop_index("ix_auth_login_states_expires_at", table_name="auth_login_states")
    op.drop_table("auth_login_states")
