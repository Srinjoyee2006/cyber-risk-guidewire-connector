"""
CyberRisk-Guidewire-Connector (CRGC)
Underwriting Workflow & PolicyCenter Connector API Routes
"""

import logging
from typing import Annotated, Optional, Sequence
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.db.session import get_db
from app.services.underwriting_service import UnderwritingService
from app.schemas.underwriting import (
    UnderwritingReviewCreateRequest,
    UnderwritingStatusTransitionRequest,
    UnderwritingDispatchRequest,
    UnderwritingReviewResponse,
    UnderwritingDispatchAttemptSchema,
    UnderwritingDashboardMetricsResponse,
    SimulatedPolicyCenterActivityResponse,
)

logger = logging.getLogger("crgc.api.underwriting")

router = APIRouter(prefix="/underwriting", tags=["Underwriting Workflow & Guidewire Connector"])


def get_underwriting_service(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> UnderwritingService:
    return UnderwritingService(db=db, settings=settings)


@router.post(
    "/reviews",
    response_model=UnderwritingReviewResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger or Evaluate Underwriting Review",
    description=(
        "Evaluates organization security posture, vulnerability intelligence, and coverage terms "
        "to generate a structured Underwriting Review recommendation. Reuses unresolved reviews if duplicate."
    ),
)
def create_or_trigger_review(
    req: UnderwritingReviewCreateRequest,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
) -> UnderwritingReviewResponse:
    return service.create_or_trigger_review(req)


@router.get(
    "/reviews/{review_id}",
    response_model=UnderwritingReviewResponse,
    summary="Get Underwriting Review by ID",
    description="Retrieves a complete underwriting review record including immutable evidence snapshot and status history.",
)
def get_review_by_id(
    review_id: str,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
) -> UnderwritingReviewResponse:
    return service.get_review_by_id(review_id)


@router.get(
    "/reviews/organization/{org_ref}",
    response_model=Sequence[UnderwritingReviewResponse],
    summary="List Underwriting Reviews for Organization",
    description="Lists all underwriting reviews associated with an authorized organization reference.",
)
def list_reviews_for_org(
    org_ref: str,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
    status_filter: Annotated[Optional[str], Query(alias="status", description="Filter by status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[UnderwritingReviewResponse]:
    return service.list_reviews_for_org(org_ref, status_filter=status_filter, limit=limit, offset=offset)


@router.get(
    "/reviews",
    response_model=Sequence[UnderwritingReviewResponse],
    summary="List All Underwriting Reviews",
    description="Lists underwriting reviews across organizations with optional search and status filtering.",
)
def list_all_reviews(
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
    status_filter: Annotated[Optional[str], Query(alias="status", description="Filter by status")] = None,
    search: Annotated[Optional[str], Query(description="Search by review ID, org, policy, or reason")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Sequence[UnderwritingReviewResponse]:
    return service.list_all_reviews(status_filter=status_filter, search=search, limit=limit, offset=offset)


@router.post(
    "/reviews/{review_id}/dispatch",
    response_model=UnderwritingReviewResponse,
    summary="Dispatch Review to Simulated PolicyCenter",
    description="Transmits the underwriting review recommendation to the simulated Guidewire PolicyCenter 10.2.1 queue.",
)
def dispatch_review(
    review_id: str,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
    req: Optional[UnderwritingDispatchRequest] = None,
) -> UnderwritingReviewResponse:
    return service.dispatch_review(review_id, req=req)


@router.post(
    "/reviews/{review_id}/retry",
    response_model=UnderwritingReviewResponse,
    summary="Retry Failed PolicyCenter Dispatch",
    description="Safely retries a previously failed dispatch without creating duplicate reviews or activities.",
)
def retry_dispatch(
    review_id: str,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
    req: Optional[UnderwritingDispatchRequest] = None,
) -> UnderwritingReviewResponse:
    return service.retry_dispatch(review_id, req=req)


@router.get(
    "/reviews/{review_id}/dispatch-history",
    response_model=Sequence[UnderwritingDispatchAttemptSchema],
    summary="Get Review Dispatch History",
    description="Retrieves the audit trail of all dispatch attempts and raw payloads for a review.",
)
def get_dispatch_history(
    review_id: str,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
) -> Sequence[UnderwritingDispatchAttemptSchema]:
    return service.get_dispatch_history(review_id)


@router.patch(
    "/reviews/{review_id}/status",
    response_model=UnderwritingReviewResponse,
    summary="Transition Review Status",
    description="Advances or updates review status according to workflow state machine rules. Audits actor and comment.",
)
def transition_review_status(
    review_id: str,
    req: UnderwritingStatusTransitionRequest,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
) -> UnderwritingReviewResponse:
    return service.transition_review_status(review_id, req)


@router.get(
    "/activities/{activity_id}",
    response_model=SimulatedPolicyCenterActivityResponse,
    summary="Get Simulated PolicyCenter Activity Details",
    description="Inspects simulated Guidewire PolicyCenter Activity details by its PublicID.",
)
def get_simulated_activity_details(
    activity_id: str,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
) -> SimulatedPolicyCenterActivityResponse:
    return service.get_simulated_activity_details(activity_id)


@router.get(
    "/dashboard/{org_ref}",
    response_model=UnderwritingDashboardMetricsResponse,
    summary="Get Underwriting Dashboard Metrics for Organization",
    description="Calculates review KPI counts across lifecycle stages for a specific organization.",
)
def get_org_dashboard_metrics(
    org_ref: str,
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
) -> UnderwritingDashboardMetricsResponse:
    return service.get_dashboard_metrics(org_ref=org_ref)


@router.get(
    "/dashboard",
    response_model=UnderwritingDashboardMetricsResponse,
    summary="Get Global Underwriting Dashboard Metrics",
    description="Calculates overall review KPI counts across all organizations.",
)
def get_global_dashboard_metrics(
    service: Annotated[UnderwritingService, Depends(get_underwriting_service)],
) -> UnderwritingDashboardMetricsResponse:
    return service.get_dashboard_metrics(org_ref=None)

