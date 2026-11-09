"""phase2_recon_schema

Revision ID: ee459127cdd8
Revises: 785f3772620e
Create Date: 2026-11-08 13:30:13.505958

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ee459127cdd8'
down_revision: Union[str, None] = '785f3772620e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Scans: add error and created_at columns, expand status length to 32
    op.add_column('scans', sa.Column('error', sa.Text(), nullable=True))
    op.add_column(
        'scans',
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.alter_column('scans', 'status', existing_type=sa.String(length=9), type_=sa.String(length=32), nullable=False)

    # 2. Assets: add scan_id column and foreign key
    op.add_column('assets', sa.Column('scan_id', sa.UUID(), nullable=True))
    op.create_foreign_key('fk_assets_scan_id_scans', 'assets', 'scans', ['scan_id'], ['id'], ondelete='CASCADE')
    op.create_index(op.f('ix_assets_scan_id'), 'assets', ['scan_id'], unique=False)

    # 3. Assessments: make created_by nullable to support API without auth session
    op.alter_column('assessments', 'created_by', existing_type=sa.UUID(), nullable=True)
    op.alter_column('assessments', 'status', existing_type=sa.String(length=11), type_=sa.String(length=32), nullable=False)


def downgrade() -> None:
    op.alter_column('assessments', 'status', existing_type=sa.String(length=32), type_=sa.String(length=11), nullable=False)
    op.alter_column('assessments', 'created_by', existing_type=sa.UUID(), nullable=False)
    op.drop_index(op.f('ix_assets_scan_id'), table_name='assets')
    op.drop_constraint('fk_assets_scan_id_scans', 'assets', type_='foreignkey')
    op.drop_column('assets', 'scan_id')
    op.alter_column('scans', 'status', existing_type=sa.String(length=32), type_=sa.String(length=9), nullable=False)
    op.drop_column('scans', 'created_at')
    op.drop_column('scans', 'error')
