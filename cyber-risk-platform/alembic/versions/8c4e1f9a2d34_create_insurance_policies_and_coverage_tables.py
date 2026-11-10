"""create_insurance_policies_and_coverage_tables

Revision ID: 8c4e1f9a2d34
Revises: 6b3c9f7a8e12
Create Date: 2026-11-11 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8c4e1f9a2d34'
down_revision: Union[str, Sequence[str], None] = '6b3c9f7a8e12'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add insurance_policies, policy_coverage_sections, and coverage_evaluations tables."""
    # 1. insurance_policies table
    op.create_table(
        'insurance_policies',
        sa.Column('policy_id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=True),
        sa.Column('organization_ref', sa.String(length=64), nullable=False),
        sa.Column('policy_number', sa.String(length=64), nullable=False),
        sa.Column('insurer_name', sa.String(length=128), nullable=False),
        sa.Column('policy_status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('start_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expiry_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('overall_limit', sa.Float(), nullable=False, server_default='5000000.0'),
        sa.Column('currency', sa.String(length=16), nullable=False, server_default='USD'),
        sa.Column('retention_deductible', sa.Float(), nullable=False, server_default='50000.0'),
        sa.Column('coinsurance_pct', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('waiting_period_hours', sa.Integer(), nullable=False, server_default='12'),
        sa.Column('policy_document_ref', sa.String(length=255), nullable=True),
        sa.Column('data_source', sa.String(length=64), nullable=False, server_default='MANUAL_ENTRY'),
        sa.Column('conditions_and_endorsements', sa.JSON(), nullable=False),
        sa.Column('exclusions', sa.JSON(), nullable=False),
        sa.Column('raw_metadata', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.organization_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_id'),
        sa.UniqueConstraint('organization_ref', 'policy_number', name='uq_org_policy_number')
    )
    op.create_index(op.f('ix_insurance_policies_organization_ref'), 'insurance_policies', ['organization_ref'], unique=False)
    op.create_index(op.f('ix_insurance_policies_policy_number'), 'insurance_policies', ['policy_number'], unique=False)
    op.create_index(op.f('ix_insurance_policies_organization_id'), 'insurance_policies', ['organization_id'], unique=False)

    # 2. policy_coverage_sections table
    op.create_table(
        'policy_coverage_sections',
        sa.Column('section_id', sa.Uuid(), nullable=False),
        sa.Column('policy_id', sa.Uuid(), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('coverage_name', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='COVERED'),
        sa.Column('limit_amount', sa.Float(), nullable=True),
        sa.Column('is_sublimit', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('deductible_amount', sa.Float(), nullable=True),
        sa.Column('waiting_period_hours', sa.Integer(), nullable=True),
        sa.Column('coinsurance_pct', sa.Float(), nullable=True),
        sa.Column('wording_clarity', sa.String(length=32), nullable=False, server_default='EXPLICIT'),
        sa.Column('applicable_exclusions', sa.JSON(), nullable=False),
        sa.Column('section_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['insurance_policies.policy_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('section_id')
    )
    op.create_index(op.f('ix_policy_coverage_sections_policy_id'), 'policy_coverage_sections', ['policy_id'], unique=False)
    op.create_index(op.f('ix_policy_coverage_sections_category'), 'policy_coverage_sections', ['category'], unique=False)

    # 3. coverage_evaluations table
    op.create_table(
        'coverage_evaluations',
        sa.Column('evaluation_id', sa.String(length=64), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=True),
        sa.Column('organization_ref', sa.String(length=64), nullable=False),
        sa.Column('policy_id', sa.Uuid(), nullable=True),
        sa.Column('policy_number', sa.String(length=64), nullable=False),
        sa.Column('assessment_id', sa.String(length=64), nullable=True),
        sa.Column('evaluation_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='COMPLETED'),
        sa.Column('total_categories_evaluated', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('covered_categories_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('gaps_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('critical_gaps_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('summary', sa.JSON(), nullable=False),
        sa.Column('policy_snapshot', sa.JSON(), nullable=False),
        sa.Column('risk_assessment_snapshot', sa.JSON(), nullable=False),
        sa.Column('category_evaluations', sa.JSON(), nullable=False),
        sa.Column('coverage_gaps', sa.JSON(), nullable=False),
        sa.Column('hypothetical_loss_scenarios', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.organization_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['policy_id'], ['insurance_policies.policy_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('evaluation_id')
    )
    op.create_index(op.f('ix_coverage_evaluations_organization_ref'), 'coverage_evaluations', ['organization_ref'], unique=False)
    op.create_index(op.f('ix_coverage_evaluations_policy_number'), 'coverage_evaluations', ['policy_number'], unique=False)
    op.create_index(op.f('ix_coverage_evaluations_organization_id'), 'coverage_evaluations', ['organization_id'], unique=False)
    op.create_index(op.f('ix_coverage_evaluations_evaluation_timestamp'), 'coverage_evaluations', ['evaluation_timestamp'], unique=False)
    op.create_index(op.f('ix_coverage_evaluations_assessment_id'), 'coverage_evaluations', ['assessment_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema: drop coverage_evaluations, policy_coverage_sections, and insurance_policies tables."""
    op.drop_table('coverage_evaluations')
    op.drop_table('policy_coverage_sections')
    op.drop_table('insurance_policies')
