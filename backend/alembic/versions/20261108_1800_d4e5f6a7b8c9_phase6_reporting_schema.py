"""Phase 6 reporting and export schema additions

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-11-08 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('reports', sa.Column('version', sa.Integer(), nullable=False, server_default='1'))
    op.add_column(
        'reports',
        sa.Column(
            'format',
            sa.Enum('DOCX', 'PDF', name='reportformat', native_enum=False),
            nullable=False,
            server_default='docx',
        )
    )
    op.add_column(
        'reports',
        sa.Column(
            'status',
            sa.Enum('PENDING', 'COMPLETED', 'FAILED', name='reportstatus', native_enum=False),
            nullable=False,
            server_default='completed',
        )
    )
    op.alter_column('reports', 'file_path', existing_type=sa.String(1024), nullable=True)
    op.add_column('reports', sa.Column('filename', sa.String(255), nullable=True))
    op.add_column('reports', sa.Column('sha256', sa.String(64), nullable=True))
    op.add_column('reports', sa.Column('size_bytes', sa.BigInteger(), nullable=True))
    op.add_column('reports', sa.Column('generated_by', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'fk_reports_generated_by_users',
        'reports', 'users',
        ['generated_by'], ['id'],
        ondelete='SET NULL'
    )
    op.alter_column('reports', 'generated_at', existing_type=sa.DateTime(timezone=True), nullable=True)
    op.add_column('reports', sa.Column('template_version', sa.String(50), nullable=False, server_default='1.0.0'))
    op.add_column('reports', sa.Column('generator_version', sa.String(50), nullable=False, server_default='1.0.0'))
    op.add_column('reports', sa.Column('snapshot_json', sa.JSON(), nullable=False, server_default='{}'))
    op.add_column('reports', sa.Column('unverified_count_at_generation', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('reports', sa.Column('confirmed_count_at_generation', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('reports', sa.Column('error', sa.Text(), nullable=True))
    op.add_column('reports', sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False))
    op.create_index(op.f('ix_reports_status'), 'reports', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_reports_status'), table_name='reports')
    op.drop_constraint('fk_reports_generated_by_users', 'reports', type_='foreignkey')
    op.drop_column('reports', 'created_at')
    op.drop_column('reports', 'error')
    op.drop_column('reports', 'confirmed_count_at_generation')
    op.drop_column('reports', 'unverified_count_at_generation')
    op.drop_column('reports', 'snapshot_json')
    op.drop_column('reports', 'generator_version')
    op.drop_column('reports', 'template_version')
    op.drop_column('reports', 'generated_by')
    op.drop_column('reports', 'size_bytes')
    op.drop_column('reports', 'sha256')
    op.drop_column('reports', 'filename')
    op.drop_column('reports', 'status')
    op.drop_column('reports', 'format')
    op.drop_column('reports', 'version')

