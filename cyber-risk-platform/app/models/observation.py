"""
CyberRisk-Guidewire-Connector (CRGC)
VulnerabilityObservation SQLAlchemy Model (Authorized Scanner Observations)
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Optional, TYPE_CHECKING
import uuid
from sqlalchemy import String, DateTime, Uuid, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.asset import Asset


def generate_observation_dedup_hash(
    organization_id: uuid.UUID | str,
    asset_id: uuid.UUID | str,
    cve_id: str,
    scanner_source: str,
    source_record_id: Optional[str] = None,
) -> str:
    """
    Computes deterministic SHA-256 hash for observation deduplication.
    Uses organization_id, asset_id, normalized cve_id, scanner_source, and source_record_id (if available).
    """
    normalized_cve = (cve_id or "").strip().upper()
    normalized_source = (scanner_source or "").strip().lower()
    normalized_rec_id = (source_record_id or "").strip()
    key_str = f"{str(organization_id)}:{str(asset_id)}:{normalized_cve}:{normalized_source}:{normalized_rec_id}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()


class VulnerabilityObservation(Base):
    """
    Stores authorized vulnerability observations detected on an organization's asset.
    Status can be: OBSERVED, CONFIRMED, FIXED, FALSE_POSITIVE, UNKNOWN.
    Note: Public CVE intelligence does not prove an asset is affected; only scanner observations create this record.
    Observations are never called CONFIRMED unless the scanner explicitly reports that status.
    """
    __tablename__ = "vulnerability_observations"

    observation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.organization_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    scanner_source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,  # e.g., TENABLE, QUALYS, SNYK, DEFENDER
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="OBSERVED",  # OBSERVED, CONFIRMED, FIXED, FALSE_POSITIVE, UNKNOWN
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    scanner_severity: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,  # e.g., Low, Medium, High, Critical
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    source_record_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    dedup_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="observations",
    )
    asset: Mapped["Asset"] = relationship(
        "Asset",
        back_populates="observations",
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "dedup_hash", name="uq_org_observation_dedup"),
    )

    def __repr__(self) -> str:
        return f"<VulnerabilityObservation(id={self.observation_id}, cve={self.cve_id}, status={self.status})>"
