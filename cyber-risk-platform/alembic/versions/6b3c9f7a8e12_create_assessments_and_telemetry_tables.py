"""create_assessments_and_telemetry_tables

Revision ID: 6b3c9f7a8e12
Revises: 58291a1d0f2a
Create Date: 2026-11-11 00:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6b3c9f7a8e12'
down_revision: Union[str, Sequence[str], None] = '58291a1d0f2a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add telemetry_snapshots, risk_assessments, assessment_factors, and assessment_evidence tables."""
    # 1. telemetry_snapshots table
    op.create_table(
        'telemetry_snapshots',
        sa.Column('telemetry_id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=True),
        sa.Column('organization_ref', sa.String(length=64), nullable=False),
        sa.Column('policy_number', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=True),
        sa.Column('company_name', sa.String(length=255), nullable=True),
        sa.Column('mfa_enforcement_rate', sa.Float(), nullable=False),
        sa.Column('exposed_rdp_port', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('open_ports', sa.JSON(), nullable=False),
        sa.Column('critical_cves', sa.JSON(), nullable=False),
        sa.Column('critical_cve_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('edr_agent_coverage', sa.Float(), nullable=False),
        sa.Column('immutable_backups_verified', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('security_awareness_training_rate', sa.Float(), nullable=False, server_default='0.90'),
        sa.Column('source', sa.String(length=64), nullable=False, server_default='EDGE_ASM'),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.organization_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('telemetry_id')
    )
    op.create_index(op.f('ix_telemetry_snapshots_organization_ref'), 'telemetry_snapshots', ['organization_ref'], unique=False)
    op.create_index(op.f('ix_telemetry_snapshots_policy_number'), 'telemetry_snapshots', ['policy_number'], unique=False)
    op.create_index(op.f('ix_telemetry_snapshots_organization_id'), 'telemetry_snapshots', ['organization_id'], unique=False)
    op.create_index(op.f('ix_telemetry_snapshots_observed_at'), 'telemetry_snapshots', ['observed_at'], unique=False)

    # 2. risk_assessments table
    op.create_table(
        'risk_assessments',
        sa.Column('assessment_id', sa.String(length=64), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=True),
        sa.Column('organization_ref', sa.String(length=64), nullable=False),
        sa.Column('policy_number', sa.String(length=64), nullable=False),
        sa.Column('company_name', sa.String(length=255), nullable=True),
        sa.Column('assessment_type', sa.String(length=32), nullable=False, server_default='ON_DEMAND'),
        sa.Column('assessment_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('base_score', sa.Float(), nullable=False, server_default='5.0'),
        sa.Column('aggregate_risk_score', sa.Float(), nullable=False),
        sa.Column('risk_tier', sa.String(length=32), nullable=False),
        sa.Column('policy_action', sa.String(length=32), nullable=False),
        sa.Column('calculation_formula', sa.String(length=128), nullable=False, server_default='clamp(5 + MFA + RDP + CVE + EDR, 0, 100) v1.0'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='COMPLETED'),
        sa.Column('previous_assessment_id', sa.String(length=64), nullable=True),
        sa.Column('guidewire_activity_created', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('guidewire_activity_id', sa.String(length=64), nullable=True),
        sa.Column('guidewire_note_id', sa.String(length=64), nullable=True),
        sa.Column('telemetry_id', sa.Uuid(), nullable=True),
        sa.Column('telemetry_summary', sa.JSON(), nullable=False),
        sa.Column('coverage_recommendations', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.organization_id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['telemetry_id'], ['telemetry_snapshots.telemetry_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('assessment_id')
    )
    op.create_index(op.f('ix_risk_assessments_organization_ref'), 'risk_assessments', ['organization_ref'], unique=False)
    op.create_index(op.f('ix_risk_assessments_policy_number'), 'risk_assessments', ['policy_number'], unique=False)
    op.create_index(op.f('ix_risk_assessments_organization_id'), 'risk_assessments', ['organization_id'], unique=False)
    op.create_index(op.f('ix_risk_assessments_assessment_timestamp'), 'risk_assessments', ['assessment_timestamp'], unique=False)

    # 3. assessment_factors table
    op.create_table(
        'assessment_factors',
        sa.Column('factor_id', sa.Uuid(), nullable=False),
        sa.Column('assessment_id', sa.String(length=64), nullable=False),
        sa.Column('factor_identifier', sa.String(length=64), nullable=False),
        sa.Column('factor_name', sa.String(length=128), nullable=False),
        sa.Column('penalty_points', sa.Float(), nullable=False),
        sa.Column('observed_value', sa.String(length=255), nullable=False),
        sa.Column('benchmark_threshold', sa.String(length=255), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('actuarial_rationale', sa.Text(), nullable=False),
        sa.Column('evidence_source', sa.String(length=128), nullable=True),
        sa.Column('evidence_timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assessment_id'], ['risk_assessments.assessment_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('factor_id')
    )
    op.create_index(op.f('ix_assessment_factors_assessment_id'), 'assessment_factors', ['assessment_id'], unique=False)
    op.create_index(op.f('ix_assessment_factors_factor_identifier'), 'assessment_factors', ['factor_identifier'], unique=False)

    # 4. assessment_evidence table
    op.create_table(
        'assessment_evidence',
        sa.Column('evidence_id', sa.Uuid(), nullable=False),
        sa.Column('assessment_id', sa.String(length=64), nullable=False),
        sa.Column('cve_id', sa.String(length=32), nullable=False),
        sa.Column('external_asset_ref', sa.String(length=128), nullable=False),
        sa.Column('asset_hostname', sa.String(length=255), nullable=True),
        sa.Column('asset_criticality', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('evidence_classification', sa.String(length=32), nullable=False),
        sa.Column('matching_method', sa.String(length=64), nullable=False),
        sa.Column('matching_reason', sa.Text(), nullable=True),
        sa.Column('observation_status', sa.String(length=32), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_severity', sa.String(length=32), nullable=True),
        sa.Column('kev_status', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('is_active_exposure', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('aging_days', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('source_scanner', sa.String(length=64), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assessment_id'], ['risk_assessments.assessment_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('evidence_id')
    )
    op.create_index(op.f('ix_assessment_evidence_assessment_id'), 'assessment_evidence', ['assessment_id'], unique=False)
    op.create_index(op.f('ix_assessment_evidence_cve_id'), 'assessment_evidence', ['cve_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema: drop assessment_evidence, assessment_factors, risk_assessments, telemetry_snapshots."""
    op.drop_index(op.f('ix_assessment_evidence_cve_id'), table_name='assessment_evidence')
    op.drop_index(op.f('ix_assessment_evidence_assessment_id'), table_name='assessment_evidence')
    op.drop_table('assessment_evidence')

    op.drop_index(op.f('ix_assessment_factors_factor_identifier'), table_name='assessment_factors')
    op.drop_index(op.f('ix_assessment_factors_assessment_id'), table_name='assessment_factors')
    op.drop_table('assessment_factors')

    op.drop_index(op.f('ix_risk_assessments_assessment_timestamp'), table_name='risk_assessments')
    op.drop_index(op.f('ix_risk_assessments_organization_id'), table_name='risk_assessments')
    op.drop_index(op.f('ix_risk_assessments_policy_number'), table_name='risk_assessments')
    op.drop_index(op.f('ix_risk_assessments_organization_ref'), table_name='risk_assessments')
    op.drop_table('risk_assessments')

    op.drop_index(op.f('ix_telemetry_snapshots_observed_at'), table_name='telemetry_snapshots')
    op.drop_index(op.f('ix_telemetry_snapshots_organization_id'), table_name='telemetry_snapshots')
    op.drop_index(op.f('ix_telemetry_snapshots_policy_number'), table_name='telemetry_snapshots')
    op.drop_index(op.f('ix_telemetry_snapshots_organization_ref'), table_name='telemetry_snapshots')
    op.drop_table('telemetry_snapshots')
