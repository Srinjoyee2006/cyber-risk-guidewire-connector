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
    policy_number: Annotated[str, Field(description="Guidewire PolicyCenter policy number")]
    company_name: Annotated[str, Field(description="Insured account legal name")]
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
        str,
        Field(description="Target policy number to evaluate", examples=["POL-001"]),
    ]
    trigger_guidewire_workflow: Annotated[
        bool,
        Field(
            default=True,
            description="Whether to dispatch activities/notes to Guidewire PolicyCenter if thresholds are met",
        ),
    ]
