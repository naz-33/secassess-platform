"""Phase 5 AI integration schema additions

Revision ID: c3d4e5f6a7b8
Revises: 0cc3e53dba6a
Create Date: 2026-11-08 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = '0cc3e53dba6a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update ai_analyses table columns
    op.add_column('ai_analyses', sa.Column('assessment_id', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'fk_ai_analyses_assessment_id_assessments',
        'ai_analyses', 'assessments',
        ['assessment_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_index(op.f('ix_ai_analyses_assessment_id'), 'ai_analyses', ['assessment_id'], unique=False)

    op.add_column('ai_analyses', sa.Column('status', sa.Enum('PENDING', 'COMPLETED', 'FAILED', name='aianalysisstatus', native_enum=False), server_default='PENDING', nullable=False))
    op.create_index(op.f('ix_ai_analyses_status'), 'ai_analyses', ['status'], unique=False)

    op.add_column('ai_analyses', sa.Column('requested_by', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'fk_ai_analyses_requested_by_users',
        'ai_analyses', 'users',
        ['requested_by'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index(op.f('ix_ai_analyses_requested_by'), 'ai_analyses', ['requested_by'], unique=False)

    op.add_column('ai_analyses', sa.Column('prompt_version', sa.String(length=50), server_default='v1', nullable=False))
    op.add_column('ai_analyses', sa.Column('input_hash', sa.String(length=64), server_default='', nullable=False))
    op.create_index(op.f('ix_ai_analyses_input_hash'), 'ai_analyses', ['input_hash'], unique=False)

    op.add_column('ai_analyses', sa.Column('redaction_report', sa.JSON(), server_default='{}', nullable=False))
    op.add_column('ai_analyses', sa.Column('error', sa.Text(), nullable=True))
    op.add_column('ai_analyses', sa.Column('input_tokens', sa.Integer(), nullable=True))
    op.add_column('ai_analyses', sa.Column('output_tokens', sa.Integer(), nullable=True))
    op.add_column('ai_analyses', sa.Column('latency_ms', sa.Integer(), nullable=True))

    op.add_column('ai_analyses', sa.Column('review_status', sa.Enum('NOT_REVIEWED', 'APPROVED', 'REJECTED', name='aireviewstatus', native_enum=False), server_default='NOT_REVIEWED', nullable=False))
    op.create_index(op.f('ix_ai_analyses_review_status'), 'ai_analyses', ['review_status'], unique=False)

    op.add_column('ai_analyses', sa.Column('reviewed_by', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'fk_ai_analyses_reviewed_by_users',
        'ai_analyses', 'users',
        ['reviewed_by'], ['id'],
        ondelete='SET NULL'
    )
    op.add_column('ai_analyses', sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('ai_analyses', sa.Column('edited_text', sa.Text(), nullable=True))
    op.add_column('ai_analyses', sa.Column('review_notes', sa.Text(), nullable=True))

    # 2. Add ai_analysis_id to findings
    op.add_column('findings', sa.Column('ai_analysis_id', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'fk_findings_ai_analysis_id_ai_analyses',
        'findings', 'ai_analyses',
        ['ai_analysis_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index(op.f('ix_findings_ai_analysis_id'), 'findings', ['ai_analysis_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_findings_ai_analysis_id'), table_name='findings')
    op.drop_constraint('fk_findings_ai_analysis_id_ai_analyses', 'findings', type_='foreignkey')
    op.drop_column('findings', 'ai_analysis_id')

    op.drop_column('ai_analyses', 'review_notes')
    op.drop_column('ai_analyses', 'edited_text')
    op.drop_column('ai_analyses', 'reviewed_at')
    op.drop_constraint('fk_ai_analyses_reviewed_by_users', 'ai_analyses', type_='foreignkey')
    op.drop_column('ai_analyses', 'reviewed_by')
    op.drop_index(op.f('ix_ai_analyses_review_status'), table_name='ai_analyses')
    op.drop_column('ai_analyses', 'review_status')
    op.drop_column('ai_analyses', 'latency_ms')
    op.drop_column('ai_analyses', 'output_tokens')
    op.drop_column('ai_analyses', 'input_tokens')
    op.drop_column('ai_analyses', 'error')
    op.drop_column('ai_analyses', 'redaction_report')
    op.drop_index(op.f('ix_ai_analyses_input_hash'), table_name='ai_analyses')
    op.drop_column('ai_analyses', 'input_hash')
    op.drop_column('ai_analyses', 'prompt_version')
    op.drop_index(op.f('ix_ai_analyses_requested_by'), table_name='ai_analyses')
    op.drop_constraint('fk_ai_analyses_requested_by_users', 'ai_analyses', type_='foreignkey')
    op.drop_column('ai_analyses', 'requested_by')
    op.drop_index(op.f('ix_ai_analyses_status'), table_name='ai_analyses')
    op.drop_column('ai_analyses', 'status')
    op.drop_index(op.f('ix_ai_analyses_assessment_id'), table_name='ai_analyses')
    op.drop_constraint('fk_ai_analyses_assessment_id_assessments', 'ai_analyses', type_='foreignkey')
    op.drop_column('ai_analyses', 'assessment_id')

