"""
CyberRisk-Guidewire-Connector (CRGC)
Asset SQLAlchemy Model (Authorized Organization Assets)
"""

from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING
import uuid
from sqlalchemy import String, DateTime, Uuid, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.observation import VulnerabilityObservation


class Asset(Base):
    """
    Stores authorized asset inventory items belonging to an organization.
    Uniqueness/Idempotency constraint: (organization_id, external_asset_ref)
    """
    __tablename__ = "assets"

    asset_id: Mapped[uuid.UUID] = mapped_column(
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
    external_asset_ref: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    asset_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,  # e.g., SERVER, WORKSTATION, CLOUD_INSTANCE, APPLICATION
    )
    hostname: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    vendor: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    product: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    cpe_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    criticality: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="MEDIUM",  # LOW, MEDIUM, HIGH, CRITICAL
    )
    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,  # e.g., CMDB, INVENTORY_CSV, AWS_API
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="assets",
    )
    observations: Mapped[list["VulnerabilityObservation"]] = relationship(
        "VulnerabilityObservation",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "external_asset_ref", name="uq_org_external_asset_ref"),
    )

    def __repr__(self) -> str:
        return f"<Asset(id={self.asset_id}, org={self.organization_id}, ref={self.external_asset_ref})>"
