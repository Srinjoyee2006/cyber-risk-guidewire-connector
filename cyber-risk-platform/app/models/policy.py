"""
CyberRisk-Guidewire-Connector (CRGC)
Insurance Policy & Coverage Evaluation SQLAlchemy Models
"""

from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING
import uuid
from sqlalchemy import (
    String,
    Float,
    Integer,
    Boolean,
    DateTime,
    Uuid,
    JSON,
    Text,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.organization import Organization


class InsurancePolicyModel(Base):
    """
    Stores structured insurance policy documentation for an organization.
    Connects cyber posture to underwriting policy terms, limits, sublimits, and deductibles.
    """
    __tablename__ = "insurance_policies"
    __table_args__ = (
        UniqueConstraint("organization_ref", "policy_number", name="uq_org_policy_number"),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.organization_id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    organization_ref: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    policy_number: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    insurer_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    policy_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",  # ACTIVE, EXPIRED, PENDING, CANCELLED
    )
    start_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expiry_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    overall_limit: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=5_000_000.0,
    )
    currency: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="USD",
    )
    retention_deductible: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=50_000.0,
    )
    coinsurance_pct: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    waiting_period_hours: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=12,
    )
    policy_document_ref: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    data_source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="MANUAL_ENTRY",  # MANUAL_ENTRY, DEMO_PORTFOLIO, GUIDEWIRE_POLICYCENTER
    )
    conditions_and_endorsements: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    exclusions: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(
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
    sections: Mapped[list["PolicyCoverageSectionModel"]] = relationship(
        "PolicyCoverageSectionModel",
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="PolicyCoverageSectionModel.created_at",
    )
    evaluations: Mapped[list["CoverageEvaluationModel"]] = relationship(
        "CoverageEvaluationModel",
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="CoverageEvaluationModel.evaluation_timestamp.desc()",
    )


class PolicyCoverageSectionModel(Base):
    """
    Itemized coverage sections and sublimit endorsements belonging to an insurance policy.
    """
    __tablename__ = "policy_coverage_sections"

    section_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("insurance_policies.policy_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,  # e.g., RANSOMWARE_EXTORTION, DATA_BREACH_PRIVACY, BUSINESS_INTERRUPTION
    )
    coverage_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="COVERED",  # COVERED, PARTIALLY_COVERED, EXCLUDED, NOT_DOCUMENTED, REVIEW_REQUIRED
    )
    limit_amount: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    is_sublimit: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    deductible_amount: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    waiting_period_hours: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    coinsurance_pct: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    wording_clarity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="EXPLICIT",  # EXPLICIT, AMBIGUOUS, INCOMPLETE
    )
    applicable_exclusions: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    section_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    policy: Mapped["InsurancePolicyModel"] = relationship(
        "InsurancePolicyModel",
        back_populates="sections",
    )


class CoverageEvaluationModel(Base):
    """
    Persistent snapshot of a coverage gap evaluation connecting risk assessment evidence to policy terms.
    Preserves exact inputs at evaluation time to guarantee auditability and historical comparability.
    """
    __tablename__ = "coverage_evaluations"

    evaluation_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.organization_id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    organization_ref: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("insurance_policies.policy_id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    policy_number: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    assessment_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    evaluation_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="COMPLETED",  # COMPLETED, INCOMPLETE_POLICY, REVIEW_REQUIRED, EXPIRED_POLICY
    )
    total_categories_evaluated: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    covered_categories_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    gaps_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    critical_gaps_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    risk_assessment_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    category_evaluations: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    coverage_gaps: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    hypothetical_loss_scenarios: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    policy: Mapped[Optional["InsurancePolicyModel"]] = relationship(
        "InsurancePolicyModel",
        back_populates="evaluations",
    )
