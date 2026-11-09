"""phase3_findings_schema

Revision ID: cc89e812d8a1
Revises: ee459127cdd8
Create Date: 2026-11-08 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cc89e812d8a1'
down_revision: Union[str, None] = 'ee459127cdd8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update findings table
    op.add_column('findings', sa.Column('cvss_score', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('cvss_vector', sa.String(length=100), nullable=True))
    op.add_column('findings', sa.Column('wstg_id', sa.String(length=50), nullable=True))
    op.add_column('findings', sa.Column('owasp_top10', sa.String(length=100), nullable=True))
    op.add_column('findings', sa.Column('cwe', sa.String(length=50), nullable=True))
    op.add_column('findings', sa.Column('affected_url', sa.String(length=1024), nullable=True))
    op.add_column('findings', sa.Column('fingerprint', sa.String(length=64), nullable=True))
    op.add_column(
        'findings',
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    )
    op.create_index(op.f('ix_findings_fingerprint'), 'findings', ['fingerprint'], unique=False)
    op.create_index('ix_findings_assessment_fingerprint', 'findings', ['assessment_id', 'fingerprint'], unique=False)

    # 2. Update evidence table
    op.add_column('evidence', sa.Column('scan_id', sa.UUID(), nullable=True))
    op.add_column('evidence', sa.Column('label', sa.String(length=255), nullable=True))
    op.create_foreign_key('fk_evidence_scan_id_scans', 'evidence', 'scans', ['scan_id'], ['id'], ondelete='SET NULL')
    op.create_index(op.f('ix_evidence_scan_id'), 'evidence', ['scan_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_evidence_scan_id'), table_name='evidence')
    op.drop_constraint('fk_evidence_scan_id_scans', 'evidence', type_='foreignkey')
    op.drop_column('evidence', 'label')
    op.drop_column('evidence', 'scan_id')

    op.drop_index('ix_findings_assessment_fingerprint', table_name='findings')
    op.drop_index(op.f('ix_findings_fingerprint'), table_name='findings')
    op.drop_column('findings', 'updated_at')
    op.drop_column('findings', 'fingerprint')
    op.drop_column('findings', 'affected_url')
    op.drop_column('findings', 'cwe')
    op.drop_column('findings', 'owasp_top10')
    op.drop_column('findings', 'wstg_id')
    op.drop_column('findings', 'cvss_vector')
    op.drop_column('findings', 'cvss_score')

