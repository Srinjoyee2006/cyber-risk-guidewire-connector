"""
CyberRisk-Guidewire-Connector (CRGC)
Assessment Repository - Database persistence for risk assessment results, factor breakdowns, and evidence
"""

from typing import Optional, Sequence
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from app.models.assessment import (
    RiskAssessmentModel,
    AssessmentFactorBreakdownModel,
    AssessmentEvidenceSnapshotModel,
)


class AssessmentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, assessment_id: str) -> Optional[RiskAssessmentModel]:
        return self.db.execute(
            select(RiskAssessmentModel).where(
                RiskAssessmentModel.assessment_id == assessment_id.strip()
            )
        ).scalar_one_or_none()

    def get_latest_for_org(self, organization_ref: str) -> Optional[RiskAssessmentModel]:
        return self.db.execute(
            select(RiskAssessmentModel)
            .where(
                func.upper(RiskAssessmentModel.organization_ref) == organization_ref.strip().upper()
            )
            .order_by(
                desc(RiskAssessmentModel.assessment_timestamp),
                desc(RiskAssessmentModel.created_at),
            )
            .limit(1)
        ).scalar_one_or_none()

    def get_latest_for_policy(self, policy_number: str) -> Optional[RiskAssessmentModel]:
        norm_policy = policy_number.strip().upper()
        return self.db.execute(
            select(RiskAssessmentModel)
            .where(
                (func.upper(RiskAssessmentModel.policy_number) == norm_policy)
                | (func.upper(RiskAssessmentModel.organization_ref) == norm_policy)
            )
            .order_by(
                desc(RiskAssessmentModel.assessment_timestamp),
                desc(RiskAssessmentModel.created_at),
            )
            .limit(1)
        ).scalar_one_or_none()

    def list_for_org(
        self, organization_ref: str, limit: int = 100, offset: int = 0
    ) -> Sequence[RiskAssessmentModel]:
        return self.db.execute(
            select(RiskAssessmentModel)
            .where(
                func.upper(RiskAssessmentModel.organization_ref) == organization_ref.strip().upper()
            )
            .order_by(
                desc(RiskAssessmentModel.assessment_timestamp),
                desc(RiskAssessmentModel.created_at),
            )
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    def list_all(self, limit: int = 100, offset: int = 0) -> Sequence[RiskAssessmentModel]:
        return self.db.execute(
            select(RiskAssessmentModel)
            .order_by(
                desc(RiskAssessmentModel.assessment_timestamp),
                desc(RiskAssessmentModel.created_at),
            )
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    def create(self, assessment: RiskAssessmentModel) -> RiskAssessmentModel:
        self.db.add(assessment)
        self.db.commit()
        self.db.refresh(assessment)
        return assessment

    def delete(self, assessment: RiskAssessmentModel) -> None:
        self.db.delete(assessment)
        self.db.commit()
