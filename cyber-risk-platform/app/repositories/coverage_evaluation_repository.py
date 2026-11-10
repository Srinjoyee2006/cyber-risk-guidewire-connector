"""
CyberRisk-Guidewire-Connector (CRGC)
Coverage Evaluation Repository - Storage and retrieval of persistent coverage gap evaluations
"""

from typing import Optional, Sequence
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.models.policy import CoverageEvaluationModel


class CoverageEvaluationRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, eval_model: CoverageEvaluationModel) -> CoverageEvaluationModel:
        self.db.add(eval_model)
        self.db.commit()
        self.db.refresh(eval_model)
        return eval_model

    def get_by_id(self, evaluation_id: str) -> Optional[CoverageEvaluationModel]:
        stmt = select(CoverageEvaluationModel).where(CoverageEvaluationModel.evaluation_id == evaluation_id)
        return self.db.scalars(stmt).first()

    def get_latest_for_org(self, org_ref: str) -> Optional[CoverageEvaluationModel]:
        stmt = (
            select(CoverageEvaluationModel)
            .where(CoverageEvaluationModel.organization_ref == org_ref)
            .order_by(desc(CoverageEvaluationModel.evaluation_timestamp))
        )
        return self.db.scalars(stmt).first()

    def get_latest_for_policy(self, policy_number: str) -> Optional[CoverageEvaluationModel]:
        stmt = (
            select(CoverageEvaluationModel)
            .where(CoverageEvaluationModel.policy_number == policy_number)
            .order_by(desc(CoverageEvaluationModel.evaluation_timestamp))
        )
        return self.db.scalars(stmt).first()

    def list_for_org(self, org_ref: str, limit: int = 50, offset: int = 0) -> Sequence[CoverageEvaluationModel]:
        stmt = (
            select(CoverageEvaluationModel)
            .where(CoverageEvaluationModel.organization_ref == org_ref)
            .order_by(desc(CoverageEvaluationModel.evaluation_timestamp))
            .limit(limit)
            .offset(offset)
        )
        return self.db.scalars(stmt).all()

    def list_for_policy(self, policy_number: str, limit: int = 50, offset: int = 0) -> Sequence[CoverageEvaluationModel]:
        stmt = (
            select(CoverageEvaluationModel)
            .where(CoverageEvaluationModel.policy_number == policy_number)
            .order_by(desc(CoverageEvaluationModel.evaluation_timestamp))
            .limit(limit)
            .offset(offset)
        )
        return self.db.scalars(stmt).all()

    def list_all(self, limit: int = 100, offset: int = 0) -> Sequence[CoverageEvaluationModel]:
        stmt = (
            select(CoverageEvaluationModel)
            .order_by(desc(CoverageEvaluationModel.evaluation_timestamp))
            .limit(limit)
            .offset(offset)
        )
        return self.db.scalars(stmt).all()
