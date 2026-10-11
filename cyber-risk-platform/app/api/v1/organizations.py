"""
CyberRisk-Guidewire-Connector (CRGC)
Organizations API Endpoints
"""

import logging
from typing import Sequence
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.organization import Organization
from app.repositories.organization_repository import OrganizationRepository
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationResponse,
    OrganizationUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", tags=["Organizations"])


@router.post(
    "",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or register an organization with data authorization status",
)
def create_organization(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    repo = OrganizationRepository(db)
    existing = repo.get_by_ref(payload.organization_ref)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization with reference '{payload.organization_ref}' already exists.",
        )

    org = Organization(
        organization_ref=payload.organization_ref.strip(),
        display_name=payload.display_name.strip(),
        data_authorization_status=payload.data_authorization_status.value,
        authorization_scope=payload.authorization_scope,
    )
    saved = repo.create(org)
    logger.info("Created organization %s (%s)", saved.organization_ref, saved.data_authorization_status)
    return saved


@router.get(
    "",
    response_model=list[OrganizationResponse],
    summary="List all registered organizations",
)
def list_organizations(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> Sequence[Organization]:
    repo = OrganizationRepository(db)
    return repo.list_all(limit=limit, offset=offset)


@router.get(
    "/{organization_ref}",
    response_model=OrganizationResponse,
    summary="Get organization details by reference",
)
def get_organization(
    organization_ref: str,
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    repo = OrganizationRepository(db)
    org = repo.get_by_ref(organization_ref)
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ref '{organization_ref}' not found.",
        )
    return org


@router.patch(
    "/{organization_ref}",
    response_model=OrganizationResponse,
    summary="Update organization authorization status or scope",
)
def update_organization(
    organization_ref: str,
    payload: OrganizationUpdate,
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    repo = OrganizationRepository(db)
    org = repo.get_by_ref(organization_ref)
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization with ref '{organization_ref}' not found.",
        )

    if payload.display_name is not None:
        org.display_name = payload.display_name.strip()
    if payload.data_authorization_status is not None:
        org.data_authorization_status = payload.data_authorization_status.value
    if payload.authorization_scope is not None:
        org.authorization_scope = payload.authorization_scope

    updated = repo.update(org)
    logger.info("Updated organization %s status to %s", updated.organization_ref, updated.data_authorization_status)
    return updated
