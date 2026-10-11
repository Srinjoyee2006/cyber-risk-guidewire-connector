"""
CyberRisk-Guidewire-Connector (CRGC)
Asset Repository
"""

from typing import Optional, Sequence
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset


class AssetRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, asset_id: uuid.UUID) -> Optional[Asset]:
        return self.db.execute(
            select(Asset).where(Asset.asset_id == asset_id)
        ).scalar_one_or_none()

    def get_by_external_ref(self, organization_id: uuid.UUID, external_asset_ref: str) -> Optional[Asset]:
        return self.db.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.external_asset_ref == external_asset_ref.strip(),
            )
        ).scalar_one_or_none()

    def list_by_organization(self, organization_id: uuid.UUID, limit: int = 100, offset: int = 0) -> Sequence[Asset]:
        return self.db.execute(
            select(Asset)
            .where(Asset.organization_id == organization_id)
            .order_by(Asset.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    def create(self, asset: Asset) -> Asset:
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def upsert_asset(self, asset_data: dict) -> tuple[Asset, bool]:
        """
        Idempotent upsert by (organization_id, external_asset_ref).
        Returns (asset, created_boolean).
        """
        existing = self.get_by_external_ref(
            asset_data["organization_id"],
            asset_data["external_asset_ref"]
        )
        if existing:
            # Update fields
            for key, val in asset_data.items():
                if key not in ("asset_id", "organization_id", "created_at") and val is not None:
                    setattr(existing, key, val)
            self.db.commit()
            self.db.refresh(existing)
            return existing, False
        else:
            new_asset = Asset(**asset_data)
            self.db.add(new_asset)
            self.db.commit()
            self.db.refresh(new_asset)
            return new_asset, True
