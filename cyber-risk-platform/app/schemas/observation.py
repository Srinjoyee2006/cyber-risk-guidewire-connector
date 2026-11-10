"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Observation & Matching Pydantic Schemas
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


class EvidenceClassification(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    UNVERIFIED = "UNVERIFIED"


class MatchingMethod(str, Enum):
    SCANNER_CVE_OBSERVATION = "SCANNER_CVE_OBSERVATION"
    EXACT_CPE_MATCH = "EXACT_CPE_MATCH"
    CPE_VERSION_RANGE_MATCH = "CPE_VERSION_RANGE_MATCH"
    VENDOR_PRODUCT_VERSION_MATCH = "VENDOR_PRODUCT_VERSION_MATCH"
    VENDOR_PRODUCT_RANGE_MATCH = "VENDOR_PRODUCT_RANGE_MATCH"
    VENDOR_PRODUCT_WILDCARD_MATCH = "VENDOR_PRODUCT_WILDCARD_MATCH"
    CPE_PRODUCT_UNVERIFIED_VERSION = "CPE_PRODUCT_UNVERIFIED_VERSION"
    VENDOR_PRODUCT_UNVERIFIED_VERSION = "VENDOR_PRODUCT_UNVERIFIED_VERSION"
    SCANNER_OBSERVATION_UNVERIFIED = "SCANNER_OBSERVATION_UNVERIFIED"


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


# ==============================================================================
# Phase 1A Explainable Organization Vulnerability Matching Schemas
# ==============================================================================

class VulnerabilityMatchRecord(BaseModel):
    """
    Deterministic, explainable vulnerability match record linking public intelligence
    with a specific organization asset.
    """
    organization_ref: str
    asset_id: uuid.UUID
    external_asset_ref: str
    asset_hostname: Optional[str] = None
    asset_criticality: str = "MEDIUM"
    cve_id: str
    vulnerability_description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    kev_status: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    known_ransomware_use: Optional[bool] = None
    prioritization_score: Optional[float] = None
    prioritization_category: Optional[str] = None  # P1, P2, P3, P4
    evidence_classification: str = Field(
        ...,
        description="Explicit classification: CONFIRMED, POTENTIAL, or UNVERIFIED"
    )
    matching_method: str = Field(
        ...,
        description="Exact method used (e.g., SCANNER_CVE_OBSERVATION, EXACT_CPE_MATCH, VENDOR_PRODUCT_RANGE_MATCH)"
    )
    matching_reason: str = Field(
        ...,
        description="Deterministic, human-readable justification of the match and classification"
    )
    confidence: str = Field(
        ...,
        description="HIGH, MEDIUM, or LOW based on concrete evidence strength"
    )
    limitations: str = Field(
        ...,
        description="Explicit caveats regarding applicability, public intelligence boundaries, or missing data"
    )
    observation_status: Optional[str] = Field(
        None,
        description="Scanner status if observed (CONFIRMED, OBSERVED, FIXED, FALSE_POSITIVE, UNKNOWN), or None for pure inventory matches"
    )
    is_active_exposure: bool = Field(
        ...,
        description="True only if finding represents current active organizational vulnerability exposure"
    )
    has_conflict: bool = Field(
        default=False,
        description="True if multiple scanner sources reported conflicting observation statuses"
    )
    conflict_details: Optional[str] = None
    source_observation: Optional[dict[str, Any]] = None
    asset_evidence: dict[str, Any] = Field(default_factory=dict)
    all_observations: list[dict[str, Any]] = Field(default_factory=list)


class AffectedAssetSummary(BaseModel):
    asset_id: uuid.UUID
    external_asset_ref: str
    hostname: Optional[str] = None
    asset_type: str
    criticality: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe_name: Optional[str] = None
    confirmed_count: int = 0
    potential_count: int = 0
    unverified_count: int = 0
    fixed_count: int = 0
    false_positive_count: int = 0
    critical_count: int = 0
    kev_count: int = 0


class OrganizationVulnerabilitySummary(BaseModel):
    """
    Aggregated organization-level vulnerability matching statistics.
    """
    organization_ref: str
    display_name: str
    data_authorization_status: str
    total_assets: int
    assets_with_confirmed_vulnerabilities: int
    assets_with_potential_vulnerabilities: int
    total_confirmed_matches: int
    total_potential_matches: int
    unverified_findings: int
    fixed_findings: int
    false_positives: int
    critical_findings: int
    kev_listed_findings: int
    affected_assets: list[AffectedAssetSummary] = Field(default_factory=list)
    rules_applied: list[str] = Field(
        default_factory=lambda: [
            "Rule 1 (Confirmed): Active scanner observations (CONFIRMED/OBSERVED) associate public CVEs with asset evidence.",
            "Rule 2 (Potential): Asset product/CPE and version match public vulnerability criteria or ranges without scanner confirmation.",
            "Rule 3 (Unverified): Missing versions, ambiguous criteria, or unknown scanner observation statuses.",
            "Rule 4 (Status Filtering): Remediated (FIXED) and non-issue (FALSE_POSITIVE) findings are never counted as active exposure.",
            "Rule 5 (Boundary): Presence in public NVD or CISA KEV alone never creates a confirmed organizational exposure.",
            "Rule 6 (Scoping): All queries are strictly scoped to the authorized organization boundary.",
        ]
    )


class OrganizationVulnerabilityMatchesResponse(BaseModel):
    organization_ref: str
    summary: OrganizationVulnerabilitySummary
    matches: list[VulnerabilityMatchRecord] = Field(default_factory=list)
    total_matches: int
    limit: int
    offset: int
