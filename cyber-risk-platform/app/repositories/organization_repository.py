"""
CyberRisk-Guidewire-Connector (CRGC)
Organization Repository
"""

from typing import Optional, Sequence
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.organization import Organization


class OrganizationRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, organization_id: uuid.UUID) -> Optional[Organization]:
        return self.db.execute(
            select(Organization).where(Organization.organization_id == organization_id)
        ).scalar_one_or_none()

    def get_by_ref(self, organization_ref: str) -> Optional[Organization]:
        return self.db.execute(
            select(Organization).where(Organization.organization_ref == organization_ref.strip())
        ).scalar_one_or_none()

    def list_all(self, limit: int = 100, offset: int = 0) -> Sequence[Organization]:
        return self.db.execute(
            select(Organization)
            .order_by(Organization.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    def create(self, organization: Organization) -> Organization:
        self.db.add(organization)
        self.db.commit()
        self.db.refresh(organization)
        return organization

    def update(self, organization: Organization) -> Organization:
        self.db.commit()
        self.db.refresh(organization)
        return organization
