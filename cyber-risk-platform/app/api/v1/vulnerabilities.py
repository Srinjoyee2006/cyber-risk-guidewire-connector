"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerabilities Intelligence Query API Endpoints
"""

import logging
from datetime import datetime
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.vulnerability import VulnerabilityResponse, VulnerabilityDetailResponse

logger = logging.getLogger("crgc.api.vulnerabilities")

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Intelligence"])


def get_vuln_repo(db: Annotated[Session, Depends(get_db)]) -> VulnerabilityRepository:
    return VulnerabilityRepository(db=db)


@router.get(
    "",
    response_model=list[VulnerabilityResponse],
    summary="List Ingested Vulnerabilities",
    description="Query normalized vulnerability records with pagination and filters including KEV presence, minimum CVSS score, severity, published date, and CVE partial search.",
)
async def list_vulnerabilities(
    repo: Annotated[VulnerabilityRepository, Depends(get_vuln_repo)],
    limit: Annotated[int, Query(ge=1, le=200, description="Page limit")] = 50,
    offset: Annotated[int, Query(ge=0, description="Page offset")] = 0,
    kev: Annotated[Optional[bool], Query(description="Filter by CISA KEV exploitation presence (true or false)")] = None,
    minimum_cvss: Annotated[Optional[float], Query(ge=0.0, le=10.0, description="Filter vulnerabilities with CVSS score >= minimum_cvss")] = None,
    severity: Annotated[Optional[str], Query(description="Filter by qualitative CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)")] = None,
    cvss_severity: Annotated[Optional[str], Query(include_in_schema=False, description="Legacy alias for severity")] = None,
    published_after: Annotated[Optional[datetime], Query(description="Filter vulnerabilities published on or after timestamp")] = None,
    cve_id: Annotated[Optional[str], Query(description="Filter by partial or exact CVE ID")] = None,
) -> list[VulnerabilityResponse]:
    """List normalized vulnerability intelligence records with CISA KEV exploitation enrichment."""
    effective_severity = severity or cvss_severity
    vulns = repo.list_vulnerabilities(
        limit=limit,
        offset=offset,
        kev=kev,
        minimum_cvss=minimum_cvss,
        severity=effective_severity,
        published_after=published_after,
        cve_id=cve_id,
    )
    return [VulnerabilityResponse.model_validate(repo.to_enriched_dict(v)) for v in vulns]


@router.get(
    "/{cve_id}",
    response_model=VulnerabilityDetailResponse,
    summary="Get Vulnerability by CVE ID",
    description="Retrieve normalized metrics, CWE, CPE, complete preserved NVD raw payload, and CISA KEV enrichment when available.",
)
async def get_vulnerability_by_cve_id(
    cve_id: str,
    repo: Annotated[VulnerabilityRepository, Depends(get_vuln_repo)],
) -> VulnerabilityDetailResponse:
    """Retrieve detailed vulnerability intelligence by CVE ID with exploitation enrichment."""
    vuln = repo.get_by_cve_id(cve_id.strip())
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{cve_id}' not found in local intelligence repository. Ingest via /api/v1/ingestion/nvd/run first.",
        )
    enriched_dict = repo.to_enriched_dict(vuln)
    return VulnerabilityDetailResponse.model_validate(enriched_dict)
