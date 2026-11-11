"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Observations API Endpoints
"""

import io
import logging
from typing import Optional, Sequence
import uuid
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.core.security import get_current_user, UserProfile
from app.db.session import get_db
from app.models.observation import VulnerabilityObservation
from app.models.vulnerability import Vulnerability
from app.models.exploitation import ExploitationStatus
from app.models.prioritization import VulnerabilityPrioritization
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.observation_repository import ObservationRepository
from app.services.asset_observation_service import AssetObservationService
from app.schemas.observation import (
    ObservationImportResponse,
    VulnerabilityObservationResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Vulnerability Observations"])


class ObservationJsonImportRequest(BaseModel):
    organization_ref: str
    csv_data: str


@router.post(
    "/vulnerability-observations/import",
    response_model=ObservationImportResponse,
    summary="Import scanner vulnerability observations via CSV (multipart file or raw text)",
)
async def import_observations(
    organization_ref: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    json_payload: Optional[ObservationJsonImportRequest] = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current_user: UserProfile = Depends(get_current_user),
) -> ObservationImportResponse:
    service = AssetObservationService(db)
    max_bytes = settings.max_csv_upload_bytes

    target_org_ref = organization_ref
    csv_text = ""

    if file is not None:
        if file.filename and not file.filename.lower().endswith(".csv"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file extension for '{file.filename}'. Only .csv files are permitted.",
            )
        content_bytes = await file.read(max_bytes + 1)
        if len(content_bytes) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Uploaded file exceeds the maximum allowed limit of {max_bytes // (1024 * 1024)} MB.",
            )
        csv_text = content_bytes.decode("utf-8-sig", errors="replace")
    elif json_payload is not None:
        if len(json_payload.csv_data.encode("utf-8")) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"CSV payload exceeds the maximum allowed limit of {max_bytes // (1024 * 1024)} MB.",
            )
        target_org_ref = json_payload.organization_ref
        csv_text = json_payload.csv_data
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide CSV file via multipart form or json_payload with 'organization_ref' and 'csv_data'.",
        )

    if not target_org_ref or not target_org_ref.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field 'organization_ref' is required for vulnerability observation import.",
        )

    return service.import_observations_csv(target_org_ref.strip(), csv_text)


@router.get(
    "/organizations/{organization_ref}/observations",
    response_model=list[VulnerabilityObservationResponse],
    summary="Get scanner vulnerability observations belonging to an organization",
)
def get_organization_observations(
    organization_ref: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[VulnerabilityObservationResponse]:
    org_repo = OrganizationRepository(db)
    org = org_repo.get_by_ref(organization_ref)
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ref '{organization_ref}' was not found.",
        )
    if not org.is_authorized():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Organization '{org.organization_ref}' data authorization status is '{org.data_authorization_status}'. "
                "Access is forbidden unless authorization status is 'GRANTED'."
            ),
        )

    obs_repo = ObservationRepository(db)
    asset_repo = AssetRepository(db)
    observations = obs_repo.list_by_organization(org.organization_id, limit=limit, offset=offset)

    enriched: list[VulnerabilityObservationResponse] = []
    for obs in observations:
        asset = asset_repo.get_by_id(obs.asset_id)
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == obs.cve_id).first()
        kev = db.query(ExploitationStatus).filter(ExploitationStatus.cve_id == obs.cve_id).first()
        prio = db.query(VulnerabilityPrioritization).filter(VulnerabilityPrioritization.cve_id == obs.cve_id).first()

        item = VulnerabilityObservationResponse(
            observation_id=obs.observation_id,
            organization_id=obs.organization_id,
            asset_id=obs.asset_id,
            cve_id=obs.cve_id,
            scanner_source=obs.scanner_source,
            status=obs.status,
            observed_at=obs.observed_at,
            scanner_severity=obs.scanner_severity,
            evidence=obs.evidence,
            source_record_id=obs.source_record_id,
            dedup_hash=obs.dedup_hash,
            created_at=obs.created_at,
            external_asset_ref=asset.external_asset_ref if asset else None,
            asset_hostname=asset.hostname if asset else None,
            is_known_vulnerability=vuln is not None,
            kev_flag=kev.kev_flag if kev else False,
            public_priority=prio.priority if prio else None,
        )
        enriched.append(item)

    return enriched
