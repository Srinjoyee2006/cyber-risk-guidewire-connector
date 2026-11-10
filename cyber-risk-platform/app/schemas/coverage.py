"""
CyberRisk-Guidewire-Connector (CRGC)
Coverage Engine & Cyber Insurance Schemas
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
import uuid
from pydantic import BaseModel, Field


class CoverageCategoryEnum(str, Enum):
    """Structured cyber insurance coverage taxonomy."""
    RANSOMWARE_EXTORTION = "RANSOMWARE_EXTORTION"
    DATA_BREACH_PRIVACY = "DATA_BREACH_PRIVACY"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    BUSINESS_INTERRUPTION = "BUSINESS_INTERRUPTION"
    CYBER_CRIME = "CYBER_CRIME"
    DATA_RESTORATION = "DATA_RESTORATION"
    REGULATORY_LEGAL = "REGULATORY_LEGAL"
    THIRD_PARTY_LIABILITY = "THIRD_PARTY_LIABILITY"


class CoverageStatusEnum(str, Enum):
    """Categorical evaluation status for policy coverage terms."""
    COVERED = "COVERED"
    PARTIALLY_COVERED = "PARTIALLY_COVERED"
    EXCLUDED = "EXCLUDED"
    NOT_DOCUMENTED = "NOT_DOCUMENTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class WordingClarityEnum(str, Enum):
    """Clarity of policy documentation and contractual wording."""
    EXPLICIT = "EXPLICIT"
    AMBIGUOUS = "AMBIGUOUS"
    INCOMPLETE = "INCOMPLETE"
    CONFLICTING = "CONFLICTING"


class PolicyStatusEnum(str, Enum):
    """Underwriting status of the insurance policy."""
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    PENDING = "PENDING"
    CANCELLED = "CANCELLED"


# =============================================================================
# Coverage Section Schemas
# =============================================================================

class CoverageSectionSchema(BaseModel):
    """Detailed definition of an individual coverage section or sublimit endorsement."""
    section_id: Optional[uuid.UUID] = None
    category: CoverageCategoryEnum
    coverage_name: str
    status: CoverageStatusEnum = CoverageStatusEnum.COVERED
    limit_amount: Optional[float] = None
    is_sublimit: bool = False
    deductible_amount: Optional[float] = None
    waiting_period_hours: Optional[int] = None
    coinsurance_pct: Optional[float] = None
    wording_clarity: WordingClarityEnum = WordingClarityEnum.EXPLICIT
    applicable_exclusions: list[str] = Field(default_factory=list)
    section_notes: Optional[str] = None


class CoverageSectionCreateRequest(BaseModel):
    category: CoverageCategoryEnum
    coverage_name: str
    status: CoverageStatusEnum = CoverageStatusEnum.COVERED
    limit_amount: Optional[float] = None
    is_sublimit: bool = False
    deductible_amount: Optional[float] = None
    waiting_period_hours: Optional[int] = None
    coinsurance_pct: Optional[float] = None
    wording_clarity: WordingClarityEnum = WordingClarityEnum.EXPLICIT
    applicable_exclusions: list[str] = Field(default_factory=list)
    section_notes: Optional[str] = None


# =============================================================================
# Policy Schemas
# =============================================================================

class InsurancePolicyCreateRequest(BaseModel):
    """Request model for provisioning or supplying an organization's insurance policy."""
    organization_ref: str
    policy_number: str
    insurer_name: str
    policy_status: PolicyStatusEnum = PolicyStatusEnum.ACTIVE
    start_date: datetime
    expiry_date: datetime
    overall_limit: float = 5_000_000.0
    currency: str = "USD"
    retention_deductible: float = 50_000.0
    coinsurance_pct: float = 0.0
    waiting_period_hours: int = 12
    policy_document_ref: Optional[str] = None
    data_source: str = "MANUAL_ENTRY"
    conditions_and_endorsements: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    sections: list[CoverageSectionCreateRequest] = Field(default_factory=list)


class InsurancePolicyUpdateRequest(BaseModel):
    """Request model for updating an existing policy's terms."""
    insurer_name: Optional[str] = None
    policy_status: Optional[PolicyStatusEnum] = None
    start_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    overall_limit: Optional[float] = None
    currency: Optional[str] = None
    retention_deductible: Optional[float] = None
    coinsurance_pct: Optional[float] = None
    waiting_period_hours: Optional[int] = None
    policy_document_ref: Optional[str] = None
    data_source: Optional[str] = None
    conditions_and_endorsements: Optional[list[str]] = None
    exclusions: Optional[list[str]] = None


class InsurancePolicyResponse(BaseModel):
    """Response model representing an organization's persisted insurance policy."""
    policy_id: uuid.UUID
    organization_id: Optional[uuid.UUID] = None
    organization_ref: str
    policy_number: str
    insurer_name: str
    policy_status: str
    start_date: datetime
    expiry_date: datetime
    overall_limit: float
    currency: str
    retention_deductible: float
    coinsurance_pct: float
    waiting_period_hours: int
    policy_document_ref: Optional[str] = None
    data_source: str
    conditions_and_endorsements: list[Any] = Field(default_factory=list)
    exclusions: list[Any] = Field(default_factory=list)
    sections: list[CoverageSectionSchema] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


# =============================================================================
# Evaluation, Gaps & Hypothetical Scenario Schemas
# =============================================================================

class CoverageGapFinding(BaseModel):
    """Itemized coverage gap identified between cyber risk posture and policy terms."""
    gap_id: str
    organization_ref: str
    policy_number: str
    coverage_category: CoverageCategoryEnum
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, ADVISORY
    gap_title: str
    explanation: str
    supporting_policy_term: str
    supporting_risk_evidence: str
    recommended_review_action: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HypotheticalLossScenario(BaseModel):
    """
    Illustrative financial loss simulation modeling deductible, coinsurance, sublimit, and gaps.
    Clearly marked as a hypothetical model and not an actual claim adjudication.
    """
    scenario_id: str
    scenario_name: str
    description: str
    coverage_category: CoverageCategoryEnum
    estimated_gross_loss: float
    currency: str = "USD"
    coverage_status: CoverageStatusEnum
    applicable_limit: Optional[float]
    applicable_deductible: float
    applicable_coinsurance_pct: float
    waiting_period_impact: Optional[str] = None
    estimated_covered_amount: Optional[float]
    estimated_insured_retention: float
    estimated_uncovered_gap: float
    calculation_explanation: str
    assumptions_and_limitations: list[str] = Field(default_factory=list)


class CategoryEvaluationDetail(BaseModel):
    """Evaluated coverage standing for a specific cyber insurance category."""
    category: CoverageCategoryEnum
    category_title: str
    status: CoverageStatusEnum
    limit_amount: Optional[float] = None
    is_sublimit: bool = False
    deductible_amount: Optional[float] = None
    waiting_period_hours: Optional[int] = None
    coinsurance_pct: Optional[float] = None
    wording_clarity: WordingClarityEnum = WordingClarityEnum.EXPLICIT
    relevance_to_risk_posture: str
    gap_count: int = 0
    gap_ids: list[str] = Field(default_factory=list)
    evaluation_notes: str


class CoverageEvaluationRequest(BaseModel):
    """Request to execute a coverage gap evaluation against an organization's policy and risk posture."""
    organization_ref: Optional[str] = None
    policy_number: Optional[str] = None
    assessment_id: Optional[str] = None


class CoverageEvaluationResponse(BaseModel):
    """Comprehensive, explainable coverage evaluation result."""
    evaluation_id: str
    organization_ref: str
    policy_number: str
    assessment_id: Optional[str] = None
    evaluation_timestamp: datetime
    policy_status: str
    overall_gap_count: int
    critical_gap_count: int
    summary: dict[str, Any] = Field(default_factory=dict)
    policy_snapshot: dict[str, Any] = Field(default_factory=dict)
    risk_assessment_snapshot: dict[str, Any] = Field(default_factory=dict)
    category_evaluations: list[CategoryEvaluationDetail] = Field(default_factory=list)
    coverage_gaps: list[CoverageGapFinding] = Field(default_factory=list)
    hypothetical_loss_scenarios: list[HypotheticalLossScenario] = Field(default_factory=list)
    governance_notice: str = (
        "Coverage analysis is strictly advisory for underwriting and risk management. "
        "It does not constitute legal contract interpretation, guaranteed coverage, or actual claim settlement."
    )


class HypotheticalCalculationRequest(BaseModel):
    """Request model for evaluating custom or standard loss scenarios against a policy."""
    policy_id: uuid.UUID
    custom_gross_loss: Optional[float] = None
    custom_category: Optional[CoverageCategoryEnum] = None
