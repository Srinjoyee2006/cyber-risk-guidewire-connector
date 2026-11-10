"""
CyberRisk-Guidewire-Connector (CRGC)
Coverage Evaluation API - Gap analysis, coverage term evaluation, and hypothetical loss scenario simulations.
"""

import logging
from typing import Annotated, Sequence
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.db.session import get_db
from app.services.coverage_service import CoverageService
from app.schemas.coverage import (
    CoverageEvaluationRequest,
    CoverageEvaluationResponse,
    CoverageGapFinding,
    HypotheticalLossScenario,
    HypotheticalCalculationRequest,
)

logger = logging.getLogger("crgc.api.coverage")

router = APIRouter(prefix="/coverage", tags=["Coverage Evaluation & Cyber Insurance Gaps"])


def get_coverage_service(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> CoverageService:
    return CoverageService(db=db, settings=settings)


@router.post(
    "/evaluate",
    response_model=CoverageEvaluationResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate Coverage Gaps",
    description="Executes a deterministic, explainable evaluation of policy coverage terms against active cybersecurity risk evidence.",
)
def evaluate_coverage(
    req: CoverageEvaluationRequest,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
) -> CoverageEvaluationResponse:
    return service.evaluate_coverage(req)


@router.get(
    "/latest/{org_ref}",
    response_model=CoverageEvaluationResponse,
    summary="Get Latest Coverage Evaluation",
    description="Retrieves the most recent coverage gap evaluation for the specified organization, evaluating immediately if none exists.",
)
def get_latest_evaluation(
    org_ref: str,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
) -> CoverageEvaluationResponse:
    return service.get_latest_evaluation(org_ref)


@router.get(
    "/history/{org_ref}",
    response_model=Sequence[CoverageEvaluationResponse],
    summary="List Coverage Evaluation History",
    description="Retrieves persistent historical coverage evaluations for trend analysis and historical comparisons.",
)
def get_evaluation_history(
    org_ref: str,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[CoverageEvaluationResponse]:
    return service.get_evaluation_history(org_ref, limit=limit, offset=offset)


@router.get(
    "/gaps/{org_ref}",
    response_model=Sequence[CoverageGapFinding],
    summary="Get Active Coverage Gaps",
    description="Lists all currently identified coverage gaps and unhedged cyber risks for the organization.",
)
def get_active_gaps(
    org_ref: str,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
) -> Sequence[CoverageGapFinding]:
    return service.get_active_gaps(org_ref)


@router.post(
    "/hypothetical-scenarios",
    response_model=Sequence[HypotheticalLossScenario],
    summary="Calculate Hypothetical Loss Scenarios",
    description="Simulates financial payout, deductible retention, coinsurance, sublimit caps, and uninsured gaps for loss scenarios.",
)
def calculate_hypothetical_scenarios(
    req: HypotheticalCalculationRequest,
    service: Annotated[CoverageService, Depends(get_coverage_service)],
) -> Sequence[HypotheticalLossScenario]:
    return service.calculate_hypothetical_scenarios(
        policy_id=req.policy_id,
        custom_gross_loss=req.custom_gross_loss,
        custom_category=req.custom_category,
    )
