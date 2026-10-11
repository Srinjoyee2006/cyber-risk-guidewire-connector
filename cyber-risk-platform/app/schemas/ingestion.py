"""
CyberRisk-Guidewire-Connector (CRGC)
Ingestion Job Pydantic Schemas
"""

from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class IngestionRunRequest(BaseModel):
    """
    Parameters for triggering a vulnerability intelligence ingestion job.
    Maps to NVD API 2.0 query specifications.
    """
    model_config = ConfigDict(populate_by_name=True)

    cve_id: Optional[str] = Field(
        default=None,
        alias="cveId",
        description="Filter by specific CVE ID (e.g., 'CVE-2024-38077') or comma-separated list of IDs",
    )
    cve_ids: Optional[list[str]] = Field(
        default=None,
        alias="cveIds",
        description="Filter by one or more specified CVE IDs (e.g. ['CVE-2021-44228', 'CVE-2024-38077'])",
    )
    pub_start_date: Optional[str] = Field(
        default=None,
        alias="pubStartDate",
        description="Published start date filter in ISO-8601 format (e.g. '2024-01-01T00:00:00.000')",
    )
    pub_end_date: Optional[str] = Field(
        default=None,
        alias="pubEndDate",
        description="Published end date filter in ISO-8601 format",
    )
    last_mod_start_date: Optional[str] = Field(
        default=None,
        alias="lastModStartDate",
        description="Last modified start date filter in ISO-8601 format",
    )
    last_mod_end_date: Optional[str] = Field(
        default=None,
        alias="lastModEndDate",
        description="Last modified end date filter in ISO-8601 format",
    )
    has_kev: Optional[bool] = Field(
        default=None,
        alias="hasKev",
        description="Filter for vulnerabilities present in CISA Known Exploited Vulnerabilities catalog",
    )
    results_per_page: Optional[int] = Field(
        default=2000,
        ge=1,
        le=2000,
        alias="resultsPerPage",
        description="Number of records requested per pagination batch (max 2000)",
    )
    start_index: Optional[int] = Field(
        default=0,
        ge=0,
        alias="startIndex",
        description="Zero-based index for offset pagination",
    )
    max_records: Optional[int] = Field(
        default=None,
        ge=1,
        description="Visible safety limit capping maximum records to ingest in this run to avoid unbounded NVD crawl (defaults to 100 for broad crawl)",
    )


class KevIngestionRunRequest(BaseModel):
    """
    Optional parameters for triggering a CISA KEV ingestion job.
    """
    model_config = ConfigDict(populate_by_name=True)

    max_records: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional safety limit capping KEV entries to ingest (e.g. 50 or 100; omit to process the entire single CISA KEV catalog feed of ~1,700+ entries)",
    )


class IngestionRunResponse(BaseModel):
    """
    Status and audit record for an executed data ingestion run.
    """
    model_config = ConfigDict(from_attributes=True)

    ingestion_run_id: UUID = Field(description="Unique UUID identifier of the ingestion execution")
    source: str = Field(description="Ingestion upstream source identifier (e.g. 'NVD_CVE_API')")
    source_url: str = Field(description="Source API endpoint invoked")
    retrieved_at: datetime = Field(description="Timestamp of job execution")
    status: str = Field(description="Final job execution status: SUCCESS, PARTIAL_SUCCESS, FAILED")
    records_received: int = Field(default=0, description="Total raw CVE records parsed from API")
    records_inserted: int = Field(default=0, description="New vulnerability rows created")
    records_updated: int = Field(default=0, description="Existing vulnerability rows updated")
    records_skipped: int = Field(default=0, description="Records skipped due to parsing or validation errors")
    error_message: Optional[str] = Field(default=None, description="Detailed error message if failed")
    correlation_id: UUID = Field(description="Correlation tracking UUID for distributed tracing")
