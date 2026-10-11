"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerabilities Intelligence Query API Endpoints
"""

import logging
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
    description="Query normalized vulnerability records from NVD intelligence repository with pagination and filters.",
)
async def list_vulnerabilities(
    repo: Annotated[VulnerabilityRepository, Depends(get_vuln_repo)],
    limit: Annotated[int, Query(ge=1, le=200, description="Page limit")] = 50,
    offset: Annotated[int, Query(ge=0, description="Page offset")] = 0,
    cvss_severity: Annotated[Optional[str], Query(description="Filter by CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)")] = None,
    cve_id: Annotated[Optional[str], Query(description="Filter by partial or exact CVE ID")] = None,
) -> list[VulnerabilityResponse]:
    """List normalized vulnerability intelligence records."""
    vulns = repo.list_vulnerabilities(
        limit=limit,
        offset=offset,
        cvss_severity=cvss_severity,
        cve_id=cve_id,
    )
    return [VulnerabilityResponse.model_validate(v) for v in vulns]


@router.get(
    "/{cve_id}",
    response_model=VulnerabilityDetailResponse,
    summary="Get Vulnerability by CVE ID",
    description="Retrieve normalized metrics, CWE, CPE, and complete preserved NVD raw payload for a specific CVE.",
)
async def get_vulnerability_by_cve_id(
    cve_id: str,
    repo: Annotated[VulnerabilityRepository, Depends(get_vuln_repo)],
) -> VulnerabilityDetailResponse:
    """Retrieve detailed vulnerability intelligence by CVE ID."""
    vuln = repo.get_by_cve_id(cve_id.strip())
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{cve_id}' not found in local intelligence repository. Ingest via /api/v1/ingestion/nvd/run first.",
        )
    return VulnerabilityDetailResponse.model_validate(vuln)
