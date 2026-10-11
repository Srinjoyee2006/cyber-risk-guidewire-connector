"""
CyberRisk-Guidewire-Connector (CRGC)
Overview Stats Pydantic Schema
"""

from pydantic import BaseModel, ConfigDict, Field


class OverviewStatsResponse(BaseModel):
    """
    Portfolio-wide aggregated counts across NVD CVEs, CISA KEV catalog, and Prioritization bands.
    Guarantees accurate backend counts rather than first-page slice approximations.
    """
    model_config = ConfigDict(from_attributes=True)

    total_vulnerabilities: int = Field(
        default=0,
        description="Total public CVE vulnerabilities stored in the local NVD intelligence repository",
    )
    total_kev: int = Field(
        default=0,
        description="Total known exploited vulnerability records in the local CISA KEV repository",
    )
    kev_matched_vulnerabilities: int = Field(
        default=0,
        description="Total local vulnerabilities matched and enriched with CISA KEV exploitation evidence",
    )
    total_prioritized: int = Field(
        default=0,
        description="Total vulnerability prioritization records evaluated",
    )
    p1_count: int = Field(default=0, description="Count of P1 Critical triage vulnerabilities")
    p2_count: int = Field(default=0, description="Count of P2 High priority vulnerabilities")
    p3_count: int = Field(default=0, description="Count of P3 Medium priority vulnerabilities")
    p4_count: int = Field(default=0, description="Count of P4 Low priority vulnerabilities")
