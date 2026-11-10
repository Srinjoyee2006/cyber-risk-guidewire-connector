"""
CyberRisk-Guidewire-Connector (CRGC)
Policy Repository - CRUD and query operations for InsurancePolicyModel and PolicyCoverageSectionModel
"""

from typing import Optional, Sequence
import uuid
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select, desc

from app.models.policy import InsurancePolicyModel, PolicyCoverageSectionModel


class PolicyRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, policy: InsurancePolicyModel) -> InsurancePolicyModel:
        self.db.add(policy)
        self.db.commit()
        self.db.refresh(policy)
        return policy

    def get_by_id(self, policy_id: uuid.UUID) -> Optional[InsurancePolicyModel]:
        stmt = (
            select(InsurancePolicyModel)
            .options(selectinload(InsurancePolicyModel.sections))
            .where(InsurancePolicyModel.policy_id == policy_id)
        )
        return self.db.scalars(stmt).first()

    def get_by_number(self, policy_number: str) -> Optional[InsurancePolicyModel]:
        stmt = (
            select(InsurancePolicyModel)
            .options(selectinload(InsurancePolicyModel.sections))
            .where(InsurancePolicyModel.policy_number == policy_number)
            .order_by(desc(InsurancePolicyModel.created_at))
        )
        return self.db.scalars(stmt).first()

    def get_by_org_and_number(self, org_ref: str, policy_number: str) -> Optional[InsurancePolicyModel]:
        stmt = (
            select(InsurancePolicyModel)
            .options(selectinload(InsurancePolicyModel.sections))
            .where(
                InsurancePolicyModel.organization_ref == org_ref,
                InsurancePolicyModel.policy_number == policy_number,
            )
        )
        return self.db.scalars(stmt).first()

    def get_latest_for_org(self, org_ref: str) -> Optional[InsurancePolicyModel]:
        stmt = (
            select(InsurancePolicyModel)
            .options(selectinload(InsurancePolicyModel.sections))
            .where(InsurancePolicyModel.organization_ref == org_ref)
            .order_by(desc(InsurancePolicyModel.created_at))
        )
        return self.db.scalars(stmt).first()

    def list_for_org(self, org_ref: str, limit: int = 50, offset: int = 0) -> Sequence[InsurancePolicyModel]:
        stmt = (
            select(InsurancePolicyModel)
            .options(selectinload(InsurancePolicyModel.sections))
            .where(InsurancePolicyModel.organization_ref == org_ref)
            .order_by(desc(InsurancePolicyModel.created_at))
            .limit(limit)
            .offset(offset)
        )
        return self.db.scalars(stmt).all()

    def list_all(self, limit: int = 100, offset: int = 0) -> Sequence[InsurancePolicyModel]:
        stmt = (
            select(InsurancePolicyModel)
            .options(selectinload(InsurancePolicyModel.sections))
            .order_by(desc(InsurancePolicyModel.created_at))
            .limit(limit)
            .offset(offset)
        )
        return self.db.scalars(stmt).all()

    def update(self, policy: InsurancePolicyModel) -> InsurancePolicyModel:
        self.db.add(policy)
        self.db.commit()
        self.db.refresh(policy)
        return policy

    def delete(self, policy: InsurancePolicyModel) -> None:
        self.db.delete(policy)
        self.db.commit()

    def add_section(self, section: PolicyCoverageSectionModel) -> PolicyCoverageSectionModel:
        self.db.add(section)
        self.db.commit()
        self.db.refresh(section)
        return section

    def remove_section(self, section_id: uuid.UUID) -> bool:
        stmt = select(PolicyCoverageSectionModel).where(PolicyCoverageSectionModel.section_id == section_id)
        section = self.db.scalars(stmt).first()
        if section:
            self.db.delete(section)
            self.db.commit()
            return True
        return False
