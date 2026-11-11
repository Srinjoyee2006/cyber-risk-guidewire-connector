"""
CyberRisk-Guidewire-Connector (CRGC)
Insurance Policies API - Provisioning, configuration, and inspection of cyber insurance policies and coverage terms.
"""

import logging
from typing import Annotated, Sequence
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.core.security import get_current_user, UserProfile
from app.db.session import get_db
from app.services.coverage_service import CoverageService
from app.schemas.coverage import (
    InsurancePolicyCreateRequest,
    InsurancePolicyUpdateRequest,
    InsurancePolicyResponse,
    CoverageSectionCreateRequest,
    CoverageSectionSchema,
)

logger = logging.getLogger("crgc.api.policies")

router = APIRouter(prefix="/policies", tags=["Insurance Policies & Coverage Terms"])


def get_coverage_service(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> CoverageService:
    return CoverageService(db=db, settings=settings)


@router.post(
    "",
    response_model=InsurancePolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision New Insurance Policy",
    description="Registers a new cyber insurance policy with structured coverage terms, limits, and deductible sections.",
)
def create_policy(
    req: InsurancePolicyCreateRequest,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
    current_user: UserProfile = Depends(get_current_user),
) -> InsurancePolicyResponse:
    return service.create_policy(req)


@router.get(
    "/{policy_id}",
    response_model=InsurancePolicyResponse,
    summary="Get Policy by ID",
    description="Retrieves an insurance policy by its unique UUID.",
)
def get_policy_by_id(
    policy_id: uuid.UUID,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
) -> InsurancePolicyResponse:
    return service.get_policy_by_id(policy_id)


@router.get(
    "/by-number/{policy_number}",
    response_model=InsurancePolicyResponse,
    summary="Get Policy by Policy Number",
    description="Retrieves an insurance policy by its commercial policy number string.",
)
def get_policy_by_number(
    policy_number: str,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
) -> InsurancePolicyResponse:
    return service.get_policy_by_number(policy_number)


@router.get(
    "/organization/{org_ref}",
    response_model=Sequence[InsurancePolicyResponse],
    summary="List Policies for Organization",
    description="Lists all insurance policies associated with the specified organization reference.",
)
def list_policies_for_org(
    org_ref: str,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[InsurancePolicyResponse]:
    return service.list_policies_for_org(org_ref, limit=limit, offset=offset)


@router.put(
    "/{policy_id}",
    response_model=InsurancePolicyResponse,
    summary="Update Policy Terms",
    description="Modifies terms, limits, deductible, or underwriting status for an existing policy.",
)
def update_policy(
    policy_id: uuid.UUID,
    req: InsurancePolicyUpdateRequest,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
    current_user: UserProfile = Depends(get_current_user),
) -> InsurancePolicyResponse:
    return service.update_policy(policy_id, req)


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Policy",
    description="Permanently removes an insurance policy and all its child coverage sections.",
)
def delete_policy(
    policy_id: uuid.UUID,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
    current_user: UserProfile = Depends(get_current_user),
) -> None:
    service.delete_policy(policy_id)


@router.post(
    "/{policy_id}/sections",
    response_model=CoverageSectionSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Add Coverage Section",
    description="Appends an individual coverage section or sublimit endorsement to a policy.",
)
def add_coverage_section(
    policy_id: uuid.UUID,
    section: CoverageSectionCreateRequest,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
    current_user: UserProfile = Depends(get_current_user),
) -> CoverageSectionSchema:
    return service.add_coverage_section(policy_id, section)


@router.delete(
    "/{policy_id}/sections/{section_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove Coverage Section",
    description="Deletes a specific coverage section from a policy.",
)
def delete_coverage_section(
    policy_id: uuid.UUID,
    section_id: uuid.UUID,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
    current_user: UserProfile = Depends(get_current_user),
) -> None:
    service.delete_coverage_section(policy_id, section_id)
