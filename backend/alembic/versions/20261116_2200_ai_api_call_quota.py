"""Track actual outbound AI API calls for quota enforcement.

Revision ID: 20261116_ai_api_calls
Revises: 20261110_asset_discoveries
Create Date: 2026-11-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20261116_ai_api_calls"
down_revision: Union[str, None] = "20261110_asset_discoveries"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ai_analyses",
        sa.Column("api_call_count", sa.Integer(), server_default="0", nullable=False),
    )
    op.execute(
        "UPDATE ai_analyses SET api_call_count = 1 WHERE status = 'COMPLETED'"
    )


def downgrade() -> None:
    op.drop_column("ai_analyses", "api_call_count")
