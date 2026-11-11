"""
CyberRisk-Guidewire-Connector (CRGC)
Underwriting Review & PolicyCenter Workflow SQLAlchemy Models
"""

from datetime import datetime, timezone
from typing import Any, Optional
import uuid
from sqlalchemy import (
    String,
    Float,
    DateTime,
    Uuid,
    JSON,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class UnderwritingReviewModel(Base):
    """
    Persistent Underwriting Review model connecting risk and coverage engine evidence
    to a simulated Guidewire PolicyCenter underwriting review lifecycle.
    """
    __tablename__ = "underwriting_reviews"

    review_id: Mapped[str] = mapped_column(
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
        nullable=False,
        index=True,
    )
    organization_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("insurance_policies.policy_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    policy_number: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    assessment_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("risk_assessments.assessment_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    coverage_evaluation_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("coverage_evaluations.evaluation_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Workflow Status
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PENDING",
        index=True,
    )

    # Risk Metrics & Scoring
    previous_risk_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    current_risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    score_change: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    risk_tier: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    policy_action: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    # Trigger & Recommendations
    trigger_category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    trigger_reason: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    recommended_action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    recommendation_explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Guidewire Activity Tracking (Simulated)
    guidewire_activity_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    guidewire_activity_priority: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="urgent",
    )

    # Immutable frozen evidence snapshot
    evidence_snapshot_json: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    dispatch_attempts: Mapped[list["UnderwritingDispatchAttemptModel"]] = relationship(
        back_populates="review",
        cascade="all, delete-orphan",
        order_by="UnderwritingDispatchAttemptModel.created_at.desc()",
    )
    status_history: Mapped[list["UnderwritingStatusHistoryModel"]] = relationship(
        back_populates="review",
        cascade="all, delete-orphan",
        order_by="UnderwritingStatusHistoryModel.created_at.asc()",
    )


class UnderwritingDispatchAttemptModel(Base):
    """
    Audit log of all dispatch transmissions sent to the simulated Guidewire PolicyCenter.
    Preserves raw request payloads, simulated responses, and failure reasons.
    """
    __tablename__ = "underwriting_dispatch_attempts"

    attempt_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    review_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("underwriting_reviews.review_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dispatch_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    dispatch_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    simulated_policycenter_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    request_payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    response_payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    review: Mapped["UnderwritingReviewModel"] = relationship(
        back_populates="dispatch_attempts",
    )


class UnderwritingStatusHistoryModel(Base):
    """
    Immutable audit trail of all lifecycle status transitions for an underwriting review.
    Tracks previous status, new status, actor, and optional underwriter notes.
    """
    __tablename__ = "underwriting_status_history"

    history_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    review_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("underwriting_reviews.review_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    new_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    comment: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    review: Mapped["UnderwritingReviewModel"] = relationship(
        back_populates="status_history",
    )

