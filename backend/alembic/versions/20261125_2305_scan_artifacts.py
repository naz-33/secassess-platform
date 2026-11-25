"""Add scan_artifacts table for immutable per-invocation raw tool output.

Revision ID: 20261125_scan_artifacts
Revises: 20261116_ai_api_calls
Create Date: 2026-11-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20261125_scan_artifacts"
down_revision: Union[str, None] = "20261116_ai_api_calls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("target_url", sa.String(length=1024), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("file_path", sa.String(length=1024), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_scan_artifacts_scan_id", "scan_artifacts", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_artifacts_scan_id", table_name="scan_artifacts")
    op.drop_table("scan_artifacts")
