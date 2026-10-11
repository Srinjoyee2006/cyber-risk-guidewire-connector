"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Prioritization API Endpoints
"""

from datetime import datetime
import logging
from typing import Annotated, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.repositories.prioritization_repository import PrioritizationRepository
from app.schemas.prioritization import (
    PrioritizationRunRequest,
    PrioritizationRunSummaryResponse,
    VulnerabilityPrioritizationResponse,
)
from app.services.prioritization_service import PrioritizationService

logger = logging.getLogger("crgc.api.prioritization")

router = APIRouter(prefix="/prioritization", tags=["Vulnerability Prioritization Intelligence"])


def get_prioritization_service(db: Annotated[Session, Depends(get_db)]) -> PrioritizationService:
    return PrioritizationService(db=db)


def get_prioritization_repo(db: Annotated[Session, Depends(get_db)]) -> PrioritizationRepository:
    return PrioritizationRepository(db=db)


@router.post(
    "/run",
    response_model=PrioritizationRunSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Vulnerability Prioritization Run",
    description=(
        "Evaluates public threat factors (KEV listing, CVSS critical/high severity, network exploitability, "
        "low privileges required, near KEV due dates, and recent publication) to assign deterministic P1-P4 priority bands. "
        "Operates strictly on public vulnerability intelligence without claiming insured organization impact."
    ),
)
async def run_prioritization(
    service: Annotated[PrioritizationService, Depends(get_prioritization_service)],
    request: Optional[PrioritizationRunRequest] = Body(default=None),
) -> PrioritizationRunSummaryResponse:
    """Trigger a deterministic vulnerability prioritization evaluation job."""
    return service.execute_prioritization_run(request=request)


@router.get(
    "/results",
    response_model=list[VulnerabilityPrioritizationResponse],
    summary="List Prioritization Results",
    description=(
        "Query prioritized vulnerability intelligence records with filtering across priority bands (P1-P4), "
        "CISA KEV presence, minimum CVSS score, severity, publication date, and CVE partial text search."
    ),
)
async def list_prioritization_results(
    repo: Annotated[PrioritizationRepository, Depends(get_prioritization_repo)],
    limit: Annotated[int, Query(ge=1, le=200, description="Page limit")] = 50,
    offset: Annotated[int, Query(ge=0, description="Page offset")] = 0,
    priority: Annotated[Optional[str], Query(description="Filter by priority band (P1, P2, P3, P4)")] = None,
    kev: Annotated[Optional[bool], Query(description="Filter by CISA KEV exploitation presence (true or false)")] = None,
    minimum_cvss: Annotated[Optional[float], Query(ge=0.0, le=10.0, description="Filter vulnerabilities with CVSS score >= minimum_cvss")] = None,
    severity: Annotated[Optional[str], Query(description="Filter by qualitative CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)")] = None,
    published_after: Annotated[Optional[datetime], Query(description="Filter vulnerabilities published on or after timestamp")] = None,
    cve_id: Annotated[Optional[str], Query(description="Filter by partial or exact CVE ID")] = None,
) -> list[VulnerabilityPrioritizationResponse]:
    """Retrieve filtered vulnerability prioritization assessment records."""
    records = repo.list_results(
        limit=limit,
        offset=offset,
        priority=priority,
        kev=kev,
        minimum_cvss=minimum_cvss,
        severity=severity,
        published_after=published_after,
        cve_id=cve_id,
    )
    return [VulnerabilityPrioritizationResponse.model_validate(r) for r in records]


@router.get(
    "/results/{cve_id}",
    response_model=VulnerabilityPrioritizationResponse,
    summary="Get Prioritization Result by CVE ID",
    description="Retrieve the latest prioritization assessment, factor breakdown, evidence, and input snapshot for a specific CVE.",
)
async def get_prioritization_result_by_cve(
    cve_id: str,
    repo: Annotated[PrioritizationRepository, Depends(get_prioritization_repo)],
) -> VulnerabilityPrioritizationResponse:
    """Retrieve prioritization assessment details by CVE ID."""
    record = repo.get_by_cve_id(cve_id.strip())
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prioritization result for '{cve_id}' not found. Run /api/v1/prioritization/run first.",
        )
    return VulnerabilityPrioritizationResponse.model_validate(record)
