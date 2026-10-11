"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Ingestion API Endpoints
"""

import logging
from typing import Annotated, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, Body, Depends, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.repositories.ingestion_repository import IngestionRepository
from app.schemas.ingestion import IngestionRunRequest, KevIngestionRunRequest, IngestionRunResponse
from app.services.ingestion_service import IngestionService

logger = logging.getLogger("crgc.api.ingestion")

router = APIRouter(prefix="/ingestion", tags=["Vulnerability Ingestion Intelligence"])


def get_ingestion_service(db: Annotated[Session, Depends(get_db)]) -> IngestionService:
    return IngestionService(db=db)


def get_ingestion_repo(db: Annotated[Session, Depends(get_db)]) -> IngestionRepository:
    return IngestionRepository(db=db)


@router.post(
    "/nvd/run",
    response_model=IngestionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger NVD CVE Ingestion Job",
    description="Ingests public CVE vulnerability intelligence records from NIST NVD API 2.0 with idempotent persistence.",
)
async def run_nvd_ingestion(
    request: IngestionRunRequest,
    service: Annotated[IngestionService, Depends(get_ingestion_service)],
) -> IngestionRunResponse:
    """Trigger an on-demand NVD CVE ingestion job."""
    correlation_id = uuid4()
    run = await service.execute_nvd_ingestion(request=request, correlation_id=correlation_id)
    return IngestionRunResponse.model_validate(run)


@router.post(
    "/kev/run",
    response_model=IngestionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger CISA KEV Ingestion Job",
    description="Ingests CISA Known Exploited Vulnerabilities catalog JSON, linking existing CVEs and recording exploitation telemetry.",
)
async def run_cisa_kev_ingestion(
    service: Annotated[IngestionService, Depends(get_ingestion_service)],
    request: Optional[KevIngestionRunRequest] = Body(default=None),
) -> IngestionRunResponse:
    """Trigger an on-demand CISA KEV catalog ingestion and enrichment job."""
    correlation_id = uuid4()
    max_records = request.max_records if request else None
    run = await service.execute_cisa_kev_ingestion(max_records=max_records, correlation_id=correlation_id)
    return IngestionRunResponse.model_validate(run)


@router.get(
    "/runs",
    response_model=list[IngestionRunResponse],
    summary="List Data Ingestion Execution History",
    description="Lists previous vulnerability ingestion jobs with records inserted/updated metrics and status.",
)
async def list_ingestion_runs(
    repo: Annotated[IngestionRepository, Depends(get_ingestion_repo)],
    limit: Annotated[int, Query(ge=1, le=200, description="Page limit")] = 50,
    offset: Annotated[int, Query(ge=0, description="Page offset")] = 0,
) -> list[IngestionRunResponse]:
    """Retrieve history of ingestion executions."""
    runs = repo.list_runs(limit=limit, offset=offset)
    return [IngestionRunResponse.model_validate(r) for r in runs]
