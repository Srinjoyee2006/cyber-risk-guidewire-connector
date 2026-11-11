"""
CyberRisk-Guidewire-Connector (CRGC)
Assets API Endpoints
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
from app.models.asset import Asset
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.asset_repository import AssetRepository
from app.services.asset_observation_service import AssetObservationService
from app.schemas.asset import (
    AssetResponse,
    AssetImportResponse,
)
from app.schemas.observation import (
    AssetVulnerabilitiesResponse,
    VulnerabilityMatchRecord,
)
from app.services.vulnerability_matching_service import VulnerabilityMatchingService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Assets"])


class AssetJsonImportRequest(BaseModel):
    organization_ref: str
    csv_data: str


@router.post(
    "/assets/import",
    response_model=AssetImportResponse,
    summary="Import asset inventory via CSV (multipart file or raw text)",
)
async def import_assets(
    organization_ref: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    json_payload: Optional[AssetJsonImportRequest] = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current_user: UserProfile = Depends(get_current_user),
) -> AssetImportResponse:
    service = AssetObservationService(db)
    max_bytes = settings.max_csv_upload_bytes

    # Support either Form multipart upload or JSON payload
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
            detail="Field 'organization_ref' is required for asset import.",
        )

    return service.import_assets_csv(target_org_ref.strip(), csv_text)


@router.get(
    "/organizations/{organization_ref}/assets",
    response_model=list[AssetResponse],
    summary="Get assets belonging to an organization",
)
def get_organization_assets(
    organization_ref: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> Sequence[Asset]:
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

    asset_repo = AssetRepository(db)
    return asset_repo.list_by_organization(org.organization_id, limit=limit, offset=offset)


@router.get(
    "/assets/{asset_id}/vulnerabilities",
    response_model=AssetVulnerabilitiesResponse,
    summary="Get vulnerability matches for a specific asset (scanner observations vs prospective CPE candidates)",
)
def get_asset_vulnerabilities(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> AssetVulnerabilitiesResponse:
    service = AssetObservationService(db)
    return service.get_asset_vulnerabilities(asset_id)


@router.get(
    "/assets/{asset_id}/vulnerability-matches",
    response_model=list[VulnerabilityMatchRecord],
    summary="Get explainable vulnerability matches for an asset (Phase 1A)",
)
def get_asset_vulnerability_matches(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> list[VulnerabilityMatchRecord]:
    service = VulnerabilityMatchingService(db)
    return service.get_asset_vulnerability_matches(asset_id)
