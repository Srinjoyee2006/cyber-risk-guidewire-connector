"""create_organizations_assets_observations_tables

Revision ID: 58291a1d0f2a
Revises: 435693ec8051
Create Date: 2026-10-12 02:28:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '58291a1d0f2a'
down_revision: Union[str, Sequence[str], None] = '435693ec8051'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add organizations, assets, and vulnerability_observations tables."""
    # 1. organizations table
    op.create_table(
        'organizations',
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('organization_ref', sa.String(length=64), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=False),
        sa.Column('data_authorization_status', sa.String(length=32), nullable=False),
        sa.Column('authorization_scope', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('organization_id')
    )
    op.create_index(op.f('ix_organizations_organization_ref'), 'organizations', ['organization_ref'], unique=True)
    op.create_index(op.f('ix_organizations_data_authorization_status'), 'organizations', ['data_authorization_status'], unique=False)

    # 2. assets table
    op.create_table(
        'assets',
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('external_asset_ref', sa.String(length=128), nullable=False),
        sa.Column('asset_type', sa.String(length=64), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('vendor', sa.String(length=128), nullable=True),
        sa.Column('product', sa.String(length=128), nullable=True),
        sa.Column('version', sa.String(length=64), nullable=True),
        sa.Column('cpe_name', sa.String(length=255), nullable=True),
        sa.Column('criticality', sa.String(length=32), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('raw_payload', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.organization_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('asset_id'),
        sa.UniqueConstraint('organization_id', 'external_asset_ref', name='uq_org_external_asset_ref')
    )
    op.create_index(op.f('ix_assets_organization_id'), 'assets', ['organization_id'], unique=False)

    # 3. vulnerability_observations table
    op.create_table(
        'vulnerability_observations',
        sa.Column('observation_id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('cve_id', sa.String(length=32), nullable=False),
        sa.Column('scanner_source', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('scanner_severity', sa.String(length=32), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('source_record_id', sa.String(length=128), nullable=True),
        sa.Column('dedup_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.organization_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.asset_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('observation_id'),
        sa.UniqueConstraint('organization_id', 'dedup_hash', name='uq_org_observation_dedup')
    )
    op.create_index(op.f('ix_vulnerability_observations_organization_id'), 'vulnerability_observations', ['organization_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_observations_asset_id'), 'vulnerability_observations', ['asset_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_observations_cve_id'), 'vulnerability_observations', ['cve_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_observations_dedup_hash'), 'vulnerability_observations', ['dedup_hash'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_vulnerability_observations_dedup_hash'), table_name='vulnerability_observations')
    op.drop_index(op.f('ix_vulnerability_observations_cve_id'), table_name='vulnerability_observations')
    op.drop_index(op.f('ix_vulnerability_observations_asset_id'), table_name='vulnerability_observations')
    op.drop_index(op.f('ix_vulnerability_observations_organization_id'), table_name='vulnerability_observations')
    op.drop_table('vulnerability_observations')

    op.drop_index(op.f('ix_assets_organization_id'), table_name='assets')
    op.drop_table('assets')

    op.drop_index(op.f('ix_organizations_data_authorization_status'), table_name='organizations')
    op.drop_index(op.f('ix_organizations_organization_ref'), table_name='organizations')
    op.drop_table('organizations')
