"""
CyberRisk-Guidewire-Connector (CRGC)
Observation Repository
"""

from typing import Optional, Sequence
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.observation import VulnerabilityObservation, generate_observation_dedup_hash


class ObservationRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, observation_id: uuid.UUID) -> Optional[VulnerabilityObservation]:
        return self.db.execute(
            select(VulnerabilityObservation).where(VulnerabilityObservation.observation_id == observation_id)
        ).scalar_one_or_none()

    def get_by_dedup_hash(self, organization_id: uuid.UUID, dedup_hash: str) -> Optional[VulnerabilityObservation]:
        return self.db.execute(
            select(VulnerabilityObservation).where(
                VulnerabilityObservation.organization_id == organization_id,
                VulnerabilityObservation.dedup_hash == dedup_hash,
            )
        ).scalar_one_or_none()

    def list_by_organization(
        self,
        organization_id: uuid.UUID,
        limit: int = 100,
        offset: int = 0
    ) -> Sequence[VulnerabilityObservation]:
        return self.db.execute(
            select(VulnerabilityObservation)
            .where(VulnerabilityObservation.organization_id == organization_id)
            .order_by(VulnerabilityObservation.observed_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    def list_by_asset(
        self,
        asset_id: uuid.UUID,
        limit: int = 100,
        offset: int = 0
    ) -> Sequence[VulnerabilityObservation]:
        return self.db.execute(
            select(VulnerabilityObservation)
            .where(VulnerabilityObservation.asset_id == asset_id)
            .order_by(VulnerabilityObservation.observed_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    def upsert_observation(self, observation_data: dict) -> tuple[VulnerabilityObservation, bool]:
        """
        Idempotent upsert by (organization_id, dedup_hash).
        Returns (observation, created_boolean).
        """
        dedup_hash = observation_data.get("dedup_hash")
        if not dedup_hash:
            dedup_hash = generate_observation_dedup_hash(
                observation_data["organization_id"],
                observation_data["asset_id"],
                observation_data["cve_id"],
                observation_data["scanner_source"],
                observation_data.get("source_record_id"),
            )
            observation_data["dedup_hash"] = dedup_hash

        existing = self.get_by_dedup_hash(observation_data["organization_id"], dedup_hash)
        if existing:
            # Update observation status/evidence/severity if newer
            for key in ("status", "scanner_severity", "evidence", "observed_at"):
                if key in observation_data and observation_data[key] is not None:
                    setattr(existing, key, observation_data[key])
            self.db.commit()
            self.db.refresh(existing)
            return existing, False
        else:
            new_obs = VulnerabilityObservation(**observation_data)
            self.db.add(new_obs)
            self.db.commit()
            self.db.refresh(new_obs)
            return new_obs, True
