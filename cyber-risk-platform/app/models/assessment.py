"""
CyberRisk-Guidewire-Connector (CRGC)
Assessment & Telemetry SQLAlchemy Models (Persistent Underwriting History)
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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.organization import Organization


class TelemetrySnapshotModel(Base):
    """
    Persistent cybersecurity posture telemetry snapshot for an insured organization.
    Ingested from external attack surface management (ASM), EDR, or identity governance agents.
    """
    __tablename__ = "telemetry_snapshots"

    telemetry_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.organization_id", ondelete="SET NULL"),
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
    tenant_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    company_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    mfa_enforcement_rate: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    exposed_rdp_port: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    open_ports: Mapped[list[int]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    critical_cves: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    critical_cve_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    edr_agent_coverage: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    immutable_backups_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    security_awareness_training_rate: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.90,
    )
    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="EDGE_ASM",
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization",
        foreign_keys=[organization_id],
        lazy="selectin",
    )


class RiskAssessmentModel(Base):
    """
    Persistent actuarial cyber risk assessment record.
    Links telemetry, actuarial factor penalties, organization vulnerability evidence, and Guidewire dispatch.
    """
    __tablename__ = "risk_assessments"

    assessment_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.organization_id", ondelete="SET NULL"),
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
    company_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    assessment_type: Mapped[str] = mapped_column(
        String(32),
        default="ON_DEMAND",  # ON_DEMAND, SCHEDULED, SCENARIO
    )
    assessment_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    base_score: Mapped[float] = mapped_column(
        Float,
        default=5.0,
    )
    aggregate_risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    risk_tier: Mapped[str] = mapped_column(
        String(32),
        nullable=False,  # LOW, MEDIUM, HIGH, CRITICAL
    )
    policy_action: Mapped[str] = mapped_column(
        String(32),
        nullable=False,  # NOMINAL, MONITOR, REVIEW_REQUIRED
    )
    calculation_formula: Mapped[str] = mapped_column(
        String(128),
        default="clamp(5 + MFA + RDP + CVE + EDR, 0, 100) v1.0",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="COMPLETED",  # COMPLETED, INCOMPLETE_EVIDENCE
    )
    previous_assessment_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    guidewire_activity_created: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    guidewire_activity_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    guidewire_note_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    telemetry_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("telemetry_snapshots.telemetry_id", ondelete="SET NULL"),
        nullable=True,
    )
    telemetry_summary: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    coverage_recommendations: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization",
        foreign_keys=[organization_id],
        lazy="selectin",
    )
    telemetry: Mapped[Optional[TelemetrySnapshotModel]] = relationship(
        "TelemetrySnapshotModel",
        foreign_keys=[telemetry_id],
        lazy="selectin",
    )
    factors: Mapped[list["AssessmentFactorBreakdownModel"]] = relationship(
        "AssessmentFactorBreakdownModel",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    evidence_items: Mapped[list["AssessmentEvidenceSnapshotModel"]] = relationship(
        "AssessmentEvidenceSnapshotModel",
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class AssessmentFactorBreakdownModel(Base):
    """
    Individual actuarial factor penalty breakdown persisted for an assessment.
    Provides complete mathematical explainability without black-box ML.
    """
    __tablename__ = "assessment_factors"

    factor_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("risk_assessments.assessment_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    factor_identifier: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    factor_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    penalty_points: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    observed_value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    benchmark_threshold: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    actuarial_rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    evidence_source: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    evidence_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationship
    assessment: Mapped["RiskAssessmentModel"] = relationship(
        "RiskAssessmentModel",
        back_populates="factors",
    )


class AssessmentEvidenceSnapshotModel(Base):
    """
    Vulnerability evidence snapshot linking organization assets and matched CVEs to a specific assessment run.
    """
    __tablename__ = "assessment_evidence"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("risk_assessments.assessment_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
    )
    external_asset_ref: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    asset_hostname: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    asset_criticality: Mapped[str] = mapped_column(
        String(32),
        default="MEDIUM",
    )
    evidence_classification: Mapped[str] = mapped_column(
        String(32),
        nullable=False,  # CONFIRMED, POTENTIAL, UNVERIFIED
    )
    matching_method: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    matching_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    observation_status: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,  # CONFIRMED, OBSERVED, FIXED, FALSE_POSITIVE, UNKNOWN
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    cvss_severity: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    kev_status: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    is_active_exposure: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    aging_days: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )
    source_scanner: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationship
    assessment: Mapped["RiskAssessmentModel"] = relationship(
        "RiskAssessmentModel",
        back_populates="evidence_items",
    )
