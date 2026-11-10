"""
CyberRisk-Guidewire-Connector (CRGC)
Telemetry Repository - Database persistence for cybersecurity posture snapshots
"""

from typing import Optional, Sequence
import uuid
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from app.models.assessment import TelemetrySnapshotModel


class TelemetryRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, telemetry_id: uuid.UUID) -> Optional[TelemetrySnapshotModel]:
        return self.db.execute(
            select(TelemetrySnapshotModel).where(TelemetrySnapshotModel.telemetry_id == telemetry_id)
        ).scalar_one_or_none()

    def get_latest_for_org(self, organization_ref: str) -> Optional[TelemetrySnapshotModel]:
        return self.db.execute(
            select(TelemetrySnapshotModel)
            .where(
                func.upper(TelemetrySnapshotModel.organization_ref) == organization_ref.strip().upper()
            )
            .order_by(
                desc(TelemetrySnapshotModel.created_at),
                desc(TelemetrySnapshotModel.observed_at),
            )
            .limit(1)
        ).scalar_one_or_none()

    def get_latest_for_policy(self, policy_number: str) -> Optional[TelemetrySnapshotModel]:
        # Match by policy_number or fallback to organization_ref
        norm_policy = policy_number.strip().upper()
        return self.db.execute(
            select(TelemetrySnapshotModel)
            .where(
                (func.upper(TelemetrySnapshotModel.policy_number) == norm_policy)
                | (func.upper(TelemetrySnapshotModel.organization_ref) == norm_policy)
            )
            .order_by(
                desc(TelemetrySnapshotModel.created_at),
                desc(TelemetrySnapshotModel.observed_at),
            )
            .limit(1)
        ).scalar_one_or_none()

    def list_for_org(
        self, organization_ref: str, limit: int = 100, offset: int = 0
    ) -> Sequence[TelemetrySnapshotModel]:
        return self.db.execute(
            select(TelemetrySnapshotModel)
            .where(
                func.upper(TelemetrySnapshotModel.organization_ref) == organization_ref.strip().upper()
            )
            .order_by(
                desc(TelemetrySnapshotModel.created_at),
                desc(TelemetrySnapshotModel.observed_at),
            )
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    def list_all_policies(self) -> Sequence[TelemetrySnapshotModel]:
        """
        Returns latest telemetry for all distinct policies based on most recent creation.
        """
        subq = (
            select(
                TelemetrySnapshotModel.policy_number,
                func.max(TelemetrySnapshotModel.created_at).label("max_created"),
            )
            .group_by(TelemetrySnapshotModel.policy_number)
            .subquery()
        )

        return self.db.execute(
            select(TelemetrySnapshotModel)
            .join(
                subq,
                (TelemetrySnapshotModel.policy_number == subq.c.policy_number)
                & (TelemetrySnapshotModel.created_at == subq.c.max_created),
            )
            .order_by(desc(TelemetrySnapshotModel.created_at))
        ).scalars().all()

    def create(self, telemetry: TelemetrySnapshotModel) -> TelemetrySnapshotModel:
        self.db.add(telemetry)
        self.db.commit()
        self.db.refresh(telemetry)
        return telemetry
