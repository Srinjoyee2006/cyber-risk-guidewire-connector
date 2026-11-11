"""
CyberRisk-Guidewire-Connector (CRGC)
Underwriting Review & PolicyCenter Workflow Schemas
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
import uuid
from pydantic import BaseModel, Field


class UnderwritingReviewStatus(str, Enum):
    """Lifecycle statuses for an underwriting review."""
    PENDING = "PENDING"
    DISPATCHED = "DISPATCHED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_REVIEW = "IN_REVIEW"
    INFORMATION_REQUESTED = "INFORMATION_REQUESTED"
    APPROVED = "APPROVED"
    DECLINED = "DECLINED"
    CLOSED = "CLOSED"
    FAILED = "FAILED"


class RecommendedUnderwritingAction(str, Enum):
    """Structured underwriting recommendation generated from risk & coverage evidence."""
    NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"
    MONITOR = "MONITOR"
    REQUEST_INFORMATION = "REQUEST_INFORMATION"
    UNDERWRITER_REVIEW = "UNDERWRITER_REVIEW"
    URGENT_UNDERWRITER_REVIEW = "URGENT_UNDERWRITER_REVIEW"


class ReviewTriggerCategory(str, Enum):
    """Event category that caused the underwriting review to be generated."""
    RISK_INCREASE = "RISK_INCREASE"
    TIER_CHANGE = "TIER_CHANGE"
    CRITICAL_VULNERABILITY = "CRITICAL_VULNERABILITY"
    UNRESOLVED_KEV = "UNRESOLVED_KEV"
    CRITICAL_COVERAGE_GAP = "CRITICAL_COVERAGE_GAP"
    POLICY_EXPIRY = "POLICY_EXPIRY"
    MANUAL_REQUEST = "MANUAL_REQUEST"


# =============================================================================
# Request Schemas
# =============================================================================

class UnderwritingReviewCreateRequest(BaseModel):
    """Request payload to initiate or evaluate an underwriting review for an organization."""
    organization_ref: Annotated[str, Field(description="Organization reference code (e.g. DEMO-ACME-001)")]
    policy_id: Annotated[Optional[uuid.UUID], Field(default=None, description="Optional specific policy UUID")]
    trigger_reason: Annotated[Optional[str], Field(default=None, description="Optional manual trigger explanation")]
    notes: Annotated[Optional[str], Field(default=None, description="Optional initial underwriter notes")]
    force_new: Annotated[
        bool,
        Field(
            default=False,
            description="If True, generates a new review even if an unresolved review already exists for this org",
        ),
    ]


class UnderwritingStatusTransitionRequest(BaseModel):
    """Request payload to transition an underwriting review lifecycle status."""
    new_status: Annotated[UnderwritingReviewStatus, Field(description="Target lifecycle status")]
    actor: Annotated[str, Field(default="Simulated Underwriter", description="Name/title of underwriter or system initiating transition")]
    comment: Annotated[Optional[str], Field(default=None, description="Audit reason or underwriter decision notes")]


class UnderwritingDispatchRequest(BaseModel):
    """Request payload to trigger mock dispatch to PolicyCenter."""
    simulate_failure: Annotated[
        bool,
        Field(default=False, description="Simulate a connector transmission error for testing failure & retry handling"),
    ]
    custom_notes: Annotated[Optional[str], Field(default=None, description="Optional underwriter dispatch instructions")]


# =============================================================================
# Response Schemas
# =============================================================================

class UnderwritingDispatchAttemptSchema(BaseModel):
    """Record of a dispatch attempt to simulated PolicyCenter."""
    attempt_id: uuid.UUID
    review_id: str
    dispatch_timestamp: datetime
    dispatch_status: str
    simulated_policycenter_id: Optional[str] = None
    request_payload_json: dict[str, Any] = Field(default_factory=dict)
    response_payload_json: dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


class UnderwritingStatusHistorySchema(BaseModel):
    """Audit entry recording a status change."""
    history_id: uuid.UUID
    review_id: str
    previous_status: str
    new_status: str
    actor: str
    comment: Optional[str] = None
    created_at: datetime


class UnderwritingReviewResponse(BaseModel):
    """Complete representation of an Underwriting Review with evidence snapshot and audit logs."""
    review_id: str
    organization_id: Optional[uuid.UUID] = None
    organization_ref: str
    organization_name: str
    policy_id: Optional[uuid.UUID] = None
    policy_number: str
    assessment_id: Optional[str] = None
    coverage_evaluation_id: Optional[str] = None
    status: UnderwritingReviewStatus
    previous_risk_score: Optional[float] = None
    current_risk_score: float
    score_change: float
    risk_tier: str
    policy_action: str
    trigger_category: ReviewTriggerCategory
    trigger_reason: str
    recommended_action: RecommendedUnderwritingAction
    recommendation_explanation: str
    guidewire_activity_id: Optional[str] = None
    guidewire_activity_priority: str
    evidence_snapshot: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    dispatch_attempts: list[UnderwritingDispatchAttemptSchema] = Field(default_factory=list)
    status_history: list[UnderwritingStatusHistorySchema] = Field(default_factory=list)
    governance_notice: str = (
        "SIMULATED GUIDEWIRE POLICYCENTER WORKFLOW - No live Guidewire instance is connected. "
        "No real policy, premium, or coverage is modified."
    )


class UnderwritingDashboardMetricsResponse(BaseModel):
    """Aggregated KPI counts for underwriting reviews."""
    total_reviews: int
    pending_reviews: int
    dispatched_reviews: int
    in_progress_reviews: int
    completed_reviews: int
    failed_dispatches: int
    critical_reviews: int
    governance_notice: str = "SIMULATED GUIDEWIRE INTEGRATION - NO LIVE POLICY MODIFICATION"


class SimulatedPolicyCenterActivityResponse(BaseModel):
    """Structured response detailing a simulated Guidewire PolicyCenter Activity."""
    activity_id: str
    activity_pattern: str
    subject: str
    priority: str
    status: str
    target_date: str
    policy_number: str
    insured_name: str
    is_simulated: bool = True
    simulated_policycenter_url: str
    governance_notice: str = "SIMULATED GUIDEWIRE INTEGRATION - NO LIVE POLICY MODIFICATION"

