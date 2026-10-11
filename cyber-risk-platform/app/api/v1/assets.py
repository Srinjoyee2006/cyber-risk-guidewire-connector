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
)

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
) -> AssetImportResponse:
    service = AssetObservationService(db)

    # Support either Form multipart upload or JSON payload
    target_org_ref = organization_ref
    csv_text = ""

    if file is not None:
        content_bytes = await file.read()
        csv_text = content_bytes.decode("utf-8-sig", errors="replace")
    elif json_payload is not None:
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
