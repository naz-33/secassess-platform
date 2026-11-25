"""Add uniqueness constraints for report versions, pending reports, and finding fingerprints.

Revision ID: 20261125_unique_constraints
Revises: 20261125_scan_artifacts
Create Date: 2026-11-25 23:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20261125_unique_constraints"
down_revision: Union[str, None] = "20261125_scan_artifacts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Reports: unique (assessment_id, version) and at most one pending report per assessment
    op.create_unique_constraint(
        "uq_reports_assessment_version",
        "reports",
        ["assessment_id", "version"],
    )
    op.create_index(
        "uq_reports_one_pending_per_assessment",
        "reports",
        ["assessment_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('PENDING', 'pending')"),
        sqlite_where=sa.text("status IN ('PENDING', 'pending')"),
    )

    # 2. Findings: replace non-unique (assessment_id, fingerprint) index with unique partial index
    op.drop_index("ix_findings_assessment_fingerprint", table_name="findings")
    op.create_index(
        "uq_findings_assessment_fingerprint",
        "findings",
        ["assessment_id", "fingerprint"],
        unique=True,
        postgresql_where=sa.text("fingerprint IS NOT NULL"),
        sqlite_where=sa.text("fingerprint IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_findings_assessment_fingerprint", table_name="findings")
    op.create_index(
        "ix_findings_assessment_fingerprint",
        "findings",
        ["assessment_id", "fingerprint"],
        unique=False,
    )

    op.drop_index("uq_reports_one_pending_per_assessment", table_name="reports")
    op.drop_constraint("uq_reports_assessment_version", "reports", type_="unique")
