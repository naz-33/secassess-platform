"""phase4_auth_verification_schema

Revision ID: a1b2c3d4e5f6
Revises: cc89e812d8a1
Create Date: 2026-11-08 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'cc89e812d8a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update users table
    op.add_column('users', sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False))
    op.add_column('users', sa.Column('failed_login_count', sa.Integer(), server_default='0', nullable=False))
    op.add_column('users', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))

    # 2. Update findings table
    op.add_column('findings', sa.Column('original_severity', sa.String(length=50), nullable=True))
    op.execute("UPDATE findings SET original_severity = severity WHERE original_severity IS NULL")
    op.alter_column('findings', 'original_severity', nullable=False)
    op.add_column('findings', sa.Column('final_severity', sa.String(length=50), nullable=True))
    op.add_column('findings', sa.Column('severity_justification', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('verified_by', sa.UUID(), nullable=True))
    op.add_column('findings', sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key('fk_findings_verified_by_users', 'findings', 'users', ['verified_by'], ['id'], ondelete='SET NULL')
    op.create_index(op.f('ix_findings_verified_by'), 'findings', ['verified_by'], unique=False)

    # 3. Update verifications table
    op.add_column('verifications', sa.Column('evidence_reviewed', sa.Boolean(), server_default='false', nullable=False))

    # 4. Update evidence table
    op.add_column('evidence', sa.Column('uploaded_by', sa.UUID(), nullable=True))
    op.add_column('evidence', sa.Column('sha256', sa.String(length=64), nullable=True))
    op.add_column('evidence', sa.Column('original_filename', sa.String(length=255), nullable=True))
    op.create_foreign_key('fk_evidence_uploaded_by_users', 'evidence', 'users', ['uploaded_by'], ['id'], ondelete='SET NULL')
    op.create_index(op.f('ix_evidence_uploaded_by'), 'evidence', ['uploaded_by'], unique=False)

    # 5. Create severity_changes table
    op.create_table(
        'severity_changes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('finding_id', sa.UUID(), nullable=False),
        sa.Column('old_severity', sa.String(length=50), nullable=False),
        sa.Column('new_severity', sa.String(length=50), nullable=False),
        sa.Column('old_cvss', sa.Float(), nullable=True),
        sa.Column('new_cvss', sa.Float(), nullable=True),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('changed_by', sa.UUID(), nullable=False),
        sa.Column('changed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['changed_by'], ['users.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_severity_changes_finding_id'), 'severity_changes', ['finding_id'], unique=False)
    op.create_index(op.f('ix_severity_changes_changed_by'), 'severity_changes', ['changed_by'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_severity_changes_changed_by'), table_name='severity_changes')
    op.drop_index(op.f('ix_severity_changes_finding_id'), table_name='severity_changes')
    op.drop_table('severity_changes')

    op.drop_index(op.f('ix_evidence_uploaded_by'), table_name='evidence')
    op.drop_constraint('fk_evidence_uploaded_by_users', 'evidence', type_='foreignkey')
    op.drop_column('evidence', 'original_filename')
    op.drop_column('evidence', 'sha256')
    op.drop_column('evidence', 'uploaded_by')

    op.drop_column('verifications', 'evidence_reviewed')

    op.drop_index(op.f('ix_findings_verified_by'), table_name='findings')
    op.drop_constraint('fk_findings_verified_by_users', 'findings', type_='foreignkey')
    op.drop_column('findings', 'verified_at')
    op.drop_column('findings', 'verified_by')
    op.drop_column('findings', 'severity_justification')
    op.drop_column('findings', 'final_severity')
    op.drop_column('findings', 'original_severity')

    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'failed_login_count')
    op.drop_column('users', 'is_active')

