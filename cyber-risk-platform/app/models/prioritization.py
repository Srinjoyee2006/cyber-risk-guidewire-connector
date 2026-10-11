"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Prioritization Result SQLAlchemy Model
"""

from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING
import uuid
from sqlalchemy import String, Float, DateTime, Uuid, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability


class VulnerabilityPrioritization(Base):
    """
    Stores versioned, explainable vulnerability prioritization assessments.

    Business Boundary Guarantee:
    Prioritization evaluates public vulnerability threat intelligence factors only.
    It does NOT evaluate an insured organization's asset inventory or installation posture.
    insured_impact is permanently recorded as UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED.
    """
    __tablename__ = "vulnerability_prioritizations"

    prioritization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    vulnerability_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("vulnerabilities.vulnerability_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    cve_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        String(8),
        nullable=False,
        index=True,
    )  # P1, P2, P3, P4
    priority_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        index=True,
    )  # 0.0 - 100.0
    reason_codes: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
    )
    factor_results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
    )
    ruleset_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    insured_impact: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED",
    )
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
    )
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
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
    vulnerability: Mapped[Optional["Vulnerability"]] = relationship(
        "Vulnerability",
        foreign_keys=[vulnerability_id],
    )

    def __repr__(self) -> str:
        return (
            f"<VulnerabilityPrioritization(cve_id={self.cve_id}, "
            f"priority={self.priority}, score={self.priority_score}, version={self.ruleset_version})>"
        )
