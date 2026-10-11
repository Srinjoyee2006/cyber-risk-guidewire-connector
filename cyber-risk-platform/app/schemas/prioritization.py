"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Prioritization Pydantic Schemas
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class PriorityBand(str, Enum):
    """Deterministic priority triage bands for public vulnerability intelligence."""
    P1 = "P1"  # Score >= 75: Critical urgency
    P2 = "P2"  # Score >= 50 and < 75: High urgency
    P3 = "P3"  # Score >= 25 and < 50: Medium urgency
    P4 = "P4"  # Score < 25: Low urgency


class PrioritizationFactorResult(BaseModel):
    """
    Detailed audit result for a single prioritization factor.
    Guarantees full explainability and transparent rationale for every factor.
    """
    rule_code: str = Field(description="Unique code identifying the evaluation rule (e.g. 'KEV_LISTED')")
    triggered: bool = Field(description="Whether the rule criteria were satisfied by the vulnerability")
    score_contribution: float = Field(description="Numerical points contributed to priority_score")
    evidence: str = Field(description="Empirical data point from source intelligence justifying the result")
    rationale: str = Field(description="Human-readable threat intelligence explanation for the rule's relevance")


class PrioritizationRunRequest(BaseModel):
    """
    Input request for executing vulnerability prioritization evaluation.
    Supports single CVE ID, a bounded list of CVE IDs, or all ingested CVEs with pagination.
    """
    model_config = ConfigDict(populate_by_name=True)

    cve_id: Optional[str] = Field(
        default=None,
        description="Prioritize a specific single CVE ID (e.g. 'CVE-2024-38077')",
    )
    cve_ids: Optional[list[str]] = Field(
        default=None,
        description="Prioritize a bounded batch of specific CVE IDs (maximum 200)",
    )
    limit: Optional[int] = Field(
        default=100,
        ge=1,
        le=500,
        description="When prioritizing all ingested CVEs, batch limit to process",
    )
    offset: Optional[int] = Field(
        default=0,
        ge=0,
        description="When prioritizing all ingested CVEs, batch offset pagination index",
    )


class VulnerabilityPrioritizationResponse(BaseModel):
    """
    Public representation of a vulnerability prioritization assessment result.
    """
    model_config = ConfigDict(from_attributes=True)

    prioritization_id: UUID = Field(description="Unique internal UUID of the prioritization record")
    vulnerability_id: Optional[UUID] = Field(default=None, description="Linked internal Vulnerability record UUID")
    cve_id: str = Field(description="Unique CVE Identifier (e.g. 'CVE-2024-38077')")
    priority: PriorityBand = Field(description="Assigned deterministic priority band (P1, P2, P3, P4)")
    priority_score: float = Field(description="Calculated priority score (0.0 to 100.0)")
    reason_codes: list[str] = Field(description="List of triggered rule codes justifying the priority")
    factor_results: list[PrioritizationFactorResult] = Field(description="Factor-by-factor breakdown with evidence and rationale")
    ruleset_version: str = Field(description="Semantic version of the ruleset configuration utilized")
    insured_impact: str = Field(
        default="UNKNOWN_UNTIL_AUTHORIZED_ASSET_DATA_IS_PROVIDED",
        description="Boundary declaration confirming public threat context without claiming insured impact",
    )
    input_snapshot: dict[str, Any] = Field(description="Reproducible snapshot of source inputs evaluated")
    assessed_at: datetime = Field(description="Evaluation timestamp")
    created_at: datetime = Field(description="Record creation timestamp")
    updated_at: datetime = Field(description="Record last updated timestamp")


class PrioritizationRunSummaryResponse(BaseModel):
    """
    Summary response returned when a prioritization batch execution is triggered.
    """
    ruleset_version: str = Field(description="Ruleset version utilized for execution")
    total_evaluated: int = Field(description="Total CVE vulnerability records evaluated")
    p1_count: int = Field(description="Count of CVEs triaged into Priority P1")
    p2_count: int = Field(description="Count of CVEs triaged into Priority P2")
    p3_count: int = Field(description="Count of CVEs triaged into Priority P3")
    p4_count: int = Field(description="Count of CVEs triaged into Priority P4")
    results: list[VulnerabilityPrioritizationResponse] = Field(description="List of prioritization assessment records")
