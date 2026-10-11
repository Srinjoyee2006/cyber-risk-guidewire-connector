"""
CyberRisk-Guidewire-Connector (CRGC)
Organization SQLAlchemy Model (Authorized Inventory & Scanners)
"""

from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING
import uuid
from sqlalchemy import String, DateTime, Uuid, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.observation import VulnerabilityObservation


class Organization(Base):
    """
    Stores insured organization records and explicit data authorization scopes.
    Ingestion of assets and vulnerability observations is strictly gated by data_authorization_status == 'GRANTED'.
    """
    __tablename__ = "organizations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_ref: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    data_authorization_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PENDING",  # GRANTED, REVOKED, PENDING
        index=True,
    )
    authorization_scope: Mapped[dict[str, Any]] = mapped_column(
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
    assets: Mapped[list["Asset"]] = relationship(
        "Asset",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    observations: Mapped[list["VulnerabilityObservation"]] = relationship(
        "VulnerabilityObservation",
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    def is_authorized(self) -> bool:
        """Returns True only when data authorization status is explicitly GRANTED."""
        return self.data_authorization_status.upper() == "GRANTED"

    def __repr__(self) -> str:
        return f"<Organization(ref={self.organization_ref}, status={self.data_authorization_status})>"
