"""
CyberRisk-Guidewire-Connector (CRGC)
Overview Stats and Intelligence Summary API Endpoints
"""

import logging
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.exploitation_repository import ExploitationRepository
from app.repositories.prioritization_repository import PrioritizationRepository
from app.schemas.overview import OverviewStatsResponse

logger = logging.getLogger("crgc.api.overview")

router = APIRouter(prefix="/overview", tags=["Overview Intelligence"])


def get_vuln_repo(db: Annotated[Session, Depends(get_db)]) -> VulnerabilityRepository:
    return VulnerabilityRepository(db=db)


def get_exploitation_repo(db: Annotated[Session, Depends(get_db)]) -> ExploitationRepository:
    return ExploitationRepository(db=db)


def get_prioritization_repo(db: Annotated[Session, Depends(get_db)]) -> PrioritizationRepository:
    return PrioritizationRepository(db=db)


@router.get(
    "/stats",
    response_model=OverviewStatsResponse,
    summary="Get Overview Intelligence Totals and Stats",
    description="Returns accurate backend database totals across NVD vulnerabilities, CISA KEV catalog records, and prioritization priority bands without pagination bias.",
)
async def get_overview_stats(
    vuln_repo: Annotated[VulnerabilityRepository, Depends(get_vuln_repo)],
    exploitation_repo: Annotated[ExploitationRepository, Depends(get_exploitation_repo)],
    prioritization_repo: Annotated[PrioritizationRepository, Depends(get_prioritization_repo)],
) -> OverviewStatsResponse:
    """Retrieve comprehensive overview counts using backend aggregate totals."""
    total_vulns = vuln_repo.count_vulnerabilities()
    total_kev = exploitation_repo.count_records()
    kev_matched = vuln_repo.count_vulnerabilities(kev=True)
    total_prioritized = prioritization_repo.count_results()
    p1 = prioritization_repo.count_results(priority="P1")
    p2 = prioritization_repo.count_results(priority="P2")
    p3 = prioritization_repo.count_results(priority="P3")
    p4 = prioritization_repo.count_results(priority="P4")

    return OverviewStatsResponse(
        total_vulnerabilities=total_vulns,
        total_kev=total_kev,
        kev_matched_vulnerabilities=kev_matched,
        total_prioritized=total_prioritized,
        p1_count=p1,
        p2_count=p2,
        p3_count=p3,
        p4_count=p4,
    )
