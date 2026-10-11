"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Observation Pydantic Schemas
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class ObservationStatus(str, Enum):
    OBSERVED = "OBSERVED"
    CONFIRMED = "CONFIRMED"
    FIXED = "FIXED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNKNOWN = "UNKNOWN"


class MatchType(str, Enum):
    SCANNER_REPORTED = "SCANNER_REPORTED"
    CPE_CANDIDATE = "CPE_CANDIDATE"


class VulnerabilityObservationBase(BaseModel):
    cve_id: str = Field(..., max_length=32, description="Normalized CVE identifier e.g. CVE-2021-44228")
    scanner_source: str = Field(..., max_length=64, description="Scanner tool e.g. Tenable, Qualys, Snyk")
    status: ObservationStatus = Field(
        default=ObservationStatus.OBSERVED,
        description="Observation status. Not CONFIRMED unless scanner explicitly states so."
    )
    observed_at: Optional[datetime] = None
    scanner_severity: Optional[str] = Field(None, max_length=32)
    evidence: dict[str, Any] = Field(default_factory=dict, description="Scanner evidence, proof, or plugin output")
    source_record_id: Optional[str] = Field(None, max_length=128, description="Scanner internal finding ID")


class VulnerabilityObservationCreate(VulnerabilityObservationBase):
    asset_id: Optional[uuid.UUID] = None
    external_asset_ref: Optional[str] = None


class VulnerabilityObservationResponse(VulnerabilityObservationBase):
    model_config = ConfigDict(from_attributes=True)

    observation_id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID
    observed_at: datetime
    dedup_hash: str
    created_at: datetime
    # Enriched fields for API consumers
    external_asset_ref: Optional[str] = None
    asset_hostname: Optional[str] = None
    is_known_vulnerability: bool = False
    kev_flag: Optional[bool] = None
    public_priority: Optional[str] = None


class ObservationImportItemResult(BaseModel):
    row_number: int
    cve_id: Optional[str] = None
    external_asset_ref: Optional[str] = None
    status: str  # ACCEPTED or REJECTED
    reason: Optional[str] = None
    observation_id: Optional[uuid.UUID] = None


class ObservationImportResponse(BaseModel):
    organization_ref: str
    total_rows: int
    accepted_count: int
    rejected_count: int
    errors: list[ObservationImportItemResult] = Field(default_factory=list)


class AssetVulnerabilityMatch(BaseModel):
    """
    Representation of an asset's vulnerability match, clearly distinguishing
    scanner-reported evidence from CPE applicability candidates.
    """
    cve_id: str
    match_type: MatchType  # SCANNER_REPORTED or CPE_CANDIDATE
    observation_status: Optional[str] = None  # None for CPE candidates
    scanner_source: Optional[str] = None
    scanner_severity: Optional[str] = None
    observed_at: Optional[datetime] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: str = Field(..., description="HIGH for scanner reported, LOW_TO_MEDIUM for CPE candidate")
    limitations: str = Field(
        ...,
        description="Notice explaining that public intelligence / CPE matching does not prove exposure."
    )
    # Public CVE intelligence enrichment if available
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    kev_flag: Optional[bool] = None
    priority: Optional[str] = None


class AssetVulnerabilitiesResponse(BaseModel):
    asset_id: uuid.UUID
    organization_ref: str
    external_asset_ref: str
    hostname: Optional[str] = None
    scanner_reported_matches: list[AssetVulnerabilityMatch] = Field(default_factory=list)
    cpe_candidate_matches: list[AssetVulnerabilityMatch] = Field(default_factory=list)
    notice: str = (
        "Public vulnerability intelligence or CPE match candidates alone do not establish organizational impact. "
        "Scanner-reported observations represent authorized evidence; CPE candidates are prospective applicability indicators only."
    )
