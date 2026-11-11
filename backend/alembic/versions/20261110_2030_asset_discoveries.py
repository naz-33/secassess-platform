"""Preserve multiple scan discoveries for canonical assets.

Revision ID: 20261110_asset_discoveries
Revises: d4e5f6a7b8c9
Create Date: 2026-11-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20261110_asset_discoveries"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_assets_assessment_type_value",
        "assets",
        ["assessment_id", "type", "value"],
        unique=False,
    )
    op.create_table(
        "asset_discoveries",
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_asset_discoveries_asset_id_assets",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name="fk_asset_discoveries_scan_id_scans",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("asset_id", "scan_id", name="pk_asset_discoveries"),
    )
    op.create_index(
        "ix_asset_discoveries_scan_id",
        "asset_discoveries",
        ["scan_id"],
        unique=False,
    )
    op.execute(
        """
        INSERT INTO asset_discoveries (asset_id, scan_id, details)
        SELECT id, scan_id, details
        FROM assets
        WHERE scan_id IS NOT NULL
        ON CONFLICT (asset_id, scan_id) DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_index("ix_asset_discoveries_scan_id", table_name="asset_discoveries")
    op.drop_table("asset_discoveries")
    op.drop_index("ix_assets_assessment_type_value", table_name="assets")
