"""
CyberRisk-Guidewire-Connector (CRGC)
Risk Schemas - Actuarial Scoring, Factor Penalties, and Coverage Recommendations
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    """Actuarial categorization of cyber risk profile based on aggregate score."""
    LOW = "LOW"             # Score 0 - 39.9: Clean risk profile
    MEDIUM = "MEDIUM"       # Score 40.0 - 59.9: Moderate exposure, monitor
    HIGH = "HIGH"           # Score 60.0 - 79.9: Elevated exposure, underwriter intervention required
    CRITICAL = "CRITICAL"   # Score 80.0 - 100.0: Severe exposure, immediate policy endorsement or cancellation


class PolicyAction(str, Enum):
    """
    Automated insurance underwriting action determined by risk score thresholds:
    - NOMINAL: Score < 40 (Maintain standard in-force policy terms)
    - MONITOR: Score 40 - 60 (Log advisory warning to policy file, broker advisory)
    - REVIEW_REQUIRED: Score > 60 (Generate Guidewire PolicyCenter Underwriter Activity & Endorsements)
    """
    NOMINAL = "NOMINAL"
    MONITOR = "MONITOR"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class FactorPenalty(BaseModel):
    """
    Individual actuarial factor penalty component.
    Provides complete mathematical explainability (no black-box ML).
    """
    factor_name: Annotated[str, Field(description="Name of the evaluated cybersecurity control")]
    penalty_points: Annotated[
        float,
        Field(
            ge=0.0,
            le=100.0,
            description="Numeric penalty points added to base score (0.0 to 100.0)",
        ),
    ]
    observed_value: Annotated[Any, Field(description="Actual telemetric observation value")]
    benchmark_threshold: Annotated[Any, Field(description="Standard actuarial underwriting benchmark threshold")]
    explanation: Annotated[str, Field(description="Human-readable explanation of why the penalty was or was not applied")]
    actuarial_rationale: Annotated[
        str,
        Field(description="Insurance loss correlation rationale (e.g. claim frequency/severity impact)"),
    ]
    evidence_source: Annotated[
        Optional[str],
        Field(default="TELEMETRY_SNAPSHOT", description="Source sensor or evidence origin of this control"),
    ] = "TELEMETRY_SNAPSHOT"
    evidence_classification: Annotated[
        Optional[str],
        Field(default="CONFIRMED", description="Evidence classification: CONFIRMED, POTENTIAL, or UNVERIFIED"),
    ] = "CONFIRMED"
    evidence_timestamp: Annotated[
        Optional[datetime],
        Field(default=None, description="Observation or sensor timestamp"),
    ] = None


class FinancialExposureEstimate(BaseModel):
    """
    Estimated financial exposure modeling potential breach loss vs in-force policy limits.
    Translates technical telemetry into actuarial dollars and identifies coverage gaps.
    """
    estimated_event_loss: Annotated[
        float,
        Field(description="Projected breach severity in USD based on posture decay"),
    ]
    carrier_covered_amount: Annotated[
        float,
        Field(description="Estimated insurance claim payout under in-force terms"),
    ]
    insured_retained_deductible: Annotated[
        float,
        Field(description="Out-of-pocket deductible paid by insured"),
    ]
    uninsured_coverage_gap: Annotated[
        float,
        Field(description="Uninsured financial gap exceeding limits or sublimits"),
    ]


class CoverageRecommendation(BaseModel):
    """
    Actionable coverage modifications and policy endorsement recommendations.
    Formulated according to Guidewire PolicyCenter cyber insurance product model.
    """
    action: Annotated[PolicyAction, Field(description="Primary policy action")]
    financial_exposure: Annotated[
        Optional[FinancialExposureEstimate],
        Field(
            default=None,
            description="Estimated financial breach exposure and coverage gap analysis",
        ),
    ]
    ransomware_sublimit_adjustment_pct: Annotated[
        Optional[float],
        Field(
            default=None,
            description="Recommended percentage adjustment to ransomware/extortion sublimit (e.g., -50.0 for 50% cut)",
        ),
    ]
    retention_deductible_multiplier: Annotated[
        Optional[float],
        Field(
            default=None,
            description="Recommended multiplier for policy retention / deductible (e.g., 2.0x, 3.0x)",
        ),
    ]
    coinsurance_requirement_pct: Annotated[
        Optional[float],
        Field(
            default=None,
            description="Mandatory co-insurance requirement on ransomware losses (e.g., 20% or 25%)",
        ),
    ]
    recommended_endorsement_code: Annotated[
        Optional[str],
        Field(
            default=None,
            description="PolicyCenter endorsement form code (e.g., 'CYBER-RANSOM-SUB-RESTRICT-2026')",
        ),
    ]
    underwriter_notes: Annotated[
        str,
        Field(description="Detailed narrative guidance for the assigned underwriter in PolicyCenter"),
    ]


class RiskAssessmentResult(BaseModel):
    """
    Consolidated, explainable cyber risk assessment result.
    Synthesizes telemetry, actuarial penalties, coverage recommendations, and Guidewire linkage.
    """
    assessment_id: Annotated[
        str,
        Field(default_factory=lambda: f"ASM-{uuid4().hex[:8].upper()}"),
    ]
    timestamp: Annotated[
        datetime,
        Field(default_factory=lambda: datetime.now(timezone.utc)),
    ]
    organization_ref: Annotated[
        Optional[str],
        Field(default=None, description="Associated organization reference in CRGC"),
    ] = None
    policy_number: Annotated[str, Field(description="Guidewire PolicyCenter policy number")]
    company_name: Annotated[str, Field(description="Insured account legal name")]
    assessment_type: Annotated[
        str,
        Field(default="ON_DEMAND", description="ON_DEMAND, SCHEDULED, or SCENARIO"),
    ] = "ON_DEMAND"
    base_score: Annotated[float, Field(ge=0.0, le=100.0, description="Inherent baseline risk score")]
    aggregate_risk_score: Annotated[
        float,
        Field(
            ge=0.0,
            le=100.0,
            description="Final aggregated risk score (0.0 = Best, 100.0 = Worst)",
        ),
    ]
    risk_tier: Annotated[RiskTier, Field(description="Actuarial risk classification tier")]
    policy_action: Annotated[PolicyAction, Field(description="Underwriting policy action")]
    calculation_formula: Annotated[
        str,
        Field(default="clamp(5 + MFA + RDP + CVE + EDR, 0, 100) v1.0", description="Actuarial formula version"),
    ] = "clamp(5 + MFA + RDP + CVE + EDR, 0, 100) v1.0"
    status: Annotated[
        str,
        Field(default="COMPLETED", description="Assessment completion status: COMPLETED or INCOMPLETE_EVIDENCE"),
    ] = "COMPLETED"
    previous_assessment_id: Annotated[
        Optional[str],
        Field(default=None, description="Reference to previous historical assessment for trend audit"),
    ] = None
    factor_breakdowns: Annotated[
        list[FactorPenalty],
        Field(description="Itemized, explainable mathematical breakdown of all factor penalties"),
    ]
    coverage_recommendations: Annotated[
        CoverageRecommendation,
        Field(description="PolicyCenter terms & conditions adjustments"),
    ]
    telemetry_summary: Annotated[
        dict[str, Any],
        Field(description="Summary snapshot of the underlying security posture metrics"),
    ]
    vulnerability_evidence: Annotated[
        list[dict[str, Any]],
        Field(default_factory=list, description="Snapshots of organization-specific vulnerability matches considered"),
    ]
    guidewire_activity_created: Annotated[
        bool,
        Field(
            default=False,
            description="Flag indicating if a Guidewire PolicyCenter Activity task was dispatched",
        ),
    ]
    guidewire_activity_id: Annotated[
        Optional[str],
        Field(
            default=None,
            description="PolicyCenter Activity Public ID (e.g., pc:act_8921)",
        ),
    ]
    guidewire_note_id: Annotated[
        Optional[str],
        Field(
            default=None,
            description="PolicyCenter Policy Note Public ID (e.g., pc:note_4401)",
        ),
    ]


class AssessmentRequest(BaseModel):
    """Payload to trigger an on-demand risk assessment."""
    policy_number: Annotated[
        Optional[str],
        Field(default=None, description="Target policy number to evaluate", examples=["POL-001"]),
    ] = None
    organization_ref: Annotated[
        Optional[str],
        Field(default=None, description="Target organization reference to evaluate", examples=["DEMO-ACME-001"]),
    ] = None
    telemetry_id: Annotated[
        Optional[Any],
        Field(default=None, description="Specific telemetry snapshot ID to evaluate against"),
    ] = None
    trigger_guidewire_workflow: Annotated[
        bool,
        Field(
            default=True,
            description="Whether to dispatch activities/notes to Guidewire PolicyCenter if thresholds are met",
        ),
    ]


class FactorComparisonItem(BaseModel):
    """Itemized difference between two assessment runs for a specific risk control."""
    factor_identifier: str
    factor_name: str
    base_penalty: float
    target_penalty: float
    penalty_delta: float  # target - base
    direction: str  # INCREASED, DECREASED, UNCHANGED
    base_observed: Any
    target_observed: Any
    explanation: str


class VulnerabilityEvidenceDiff(BaseModel):
    """Diff of vulnerability matches between two assessment runs."""
    added_cves: list[dict[str, Any]] = Field(default_factory=list)
    resolved_cves: list[dict[str, Any]] = Field(default_factory=list)
    persisting_cves: list[dict[str, Any]] = Field(default_factory=list)
    added_count: int = 0
    resolved_count: int = 0
    persisting_count: int = 0


class AssessmentComparisonResult(BaseModel):
    """Comparative posture diff between two historical risk assessments."""
    base_assessment_id: str
    target_assessment_id: str
    organization_ref: str
    policy_number: str
    base_timestamp: datetime
    target_timestamp: datetime
    base_risk_score: float
    target_risk_score: float
    score_delta: float  # target - base
    base_risk_tier: str
    target_risk_tier: str
    tier_change: str  # IMPROVED, DETERIORATED, UNCHANGED
    base_policy_action: str
    target_policy_action: str
    action_change: str
    factor_changes: list[FactorComparisonItem] = Field(default_factory=list)
    vulnerability_changes: VulnerabilityEvidenceDiff = Field(default_factory=VulnerabilityEvidenceDiff)
    telemetry_changes: dict[str, Any] = Field(default_factory=dict)
    summary_narrative: str

