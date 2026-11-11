"""
CyberRisk-Guidewire-Connector (CRGC)
Assessments API - Trigger Risk Evaluation & Underwriter Review Workflow (Persistent Database Storage)
"""

import json
import logging
from pathlib import Path
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from config.settings import Settings, get_settings
from app.core.security import get_current_user, UserProfile
from app.db.session import get_db, SessionLocal
from app.core.risk_engine import RiskEngine
from app.core.coverage_engine import CoverageEngine
from app.schemas.telemetry import TelemetrySnapshot
from app.schemas.risk import (
    AssessmentRequest,
    RiskAssessmentResult,
    AssessmentComparisonResult,
)
from app.services.guidewire_client import GuidewireClient
from app.services.assessment_service import AssessmentService

logger = logging.getLogger("crgc.api.assessments")

router = APIRouter(prefix="/assessments", tags=["Risk Assessment & Guidewire Workflow"])


def get_risk_engine(settings: Annotated[Settings, Depends(get_settings)]) -> RiskEngine:
    return RiskEngine(settings=settings)


def get_coverage_engine() -> CoverageEngine:
    return CoverageEngine()


def get_guidewire_client(settings: Annotated[Settings, Depends(get_settings)]) -> GuidewireClient:
    return GuidewireClient(settings=settings)


def load_scenarios_data() -> dict:
    """Load deterministic scenarios from data/scenarios.json."""
    scenario_path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "scenarios.json"
    if not scenario_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scenarios data file not found at {scenario_path}",
        )
    with open(scenario_path, "r", encoding="utf-8") as f:
        return json.load(f)


@router.post(
    "/evaluate",
    response_model=RiskAssessmentResult,
    summary="Evaluate Policy Risk & Route Underwriting Workflow",
    description=(
        "Executes explainable deterministic risk scoring on the latest persisted telemetry and organization vulnerability matches. "
        "Stores the assessment, factor breakdown, and vulnerability evidence snapshots persistently in SQLite. "
        "If score > 60 (REVIEW_REQUIRED), routes through the persistent UnderwritingService workflow."
    ),
)
async def evaluate_assessment(
    request: AssessmentRequest,
    db: Session = Depends(get_db),
    settings: Annotated[Settings, Depends(get_settings)] = None,
    current_user: UserProfile = Depends(get_current_user),
) -> RiskAssessmentResult:
    """
    Execute deterministic risk evaluation on latest telemetry for policy/organization and persist results.
    """
    service = AssessmentService(db, settings=settings)
    return await service.evaluate_assessment(request)


@router.post(
    "/scenarios/{scenario_id}/execute",
    response_model=RiskAssessmentResult,
    summary="Execute Deterministic Underwriting Scenario",
    description=(
        "Executes a pre-defined deterministic underwriting scenario from data/scenarios.json. "
        "Available scenario_id values: 'scenario_a_healthy_baseline', 'scenario_b_deteriorating_risk', 'scenario_c_remediated_posture'."
    ),
)
async def execute_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
    settings: Annotated[Settings, Depends(get_settings)] = None,
    current_user: UserProfile = Depends(get_current_user),
) -> RiskAssessmentResult:
    """
    Run one of the predefined deterministic scenarios directly.
    Persists scenario telemetry, computes assessment, stores factor breakdowns and evidence, and dispatches Guidewire activities if applicable.
    """
    data = load_scenarios_data()
    scenarios = data.get("scenarios", {})

    if scenario_id not in scenarios:
        valid_ids = list(scenarios.keys())
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found. Available scenarios: {valid_ids}",
        )

    scenario = scenarios[scenario_id]
    telemetry_raw = scenario["telemetry"]
    snapshot = TelemetrySnapshot.model_validate(telemetry_raw)

    service = AssessmentService(db, settings=settings)
    # 1. Ingest scenario telemetry into database
    service.ingest_telemetry(snapshot)

    # 2. Evaluate and persist assessment
    req = AssessmentRequest(
        policy_number=snapshot.policy_number,
        trigger_guidewire_workflow=True,
    )
    return await service.evaluate_assessment(req)


@router.get(
    "/scenarios/catalog",
    summary="List Predefined Underwriting Scenarios",
    description="Catalog of deterministic scenarios for testing and demonstration.",
)
async def list_scenarios() -> dict:
    """List all available test scenarios."""
    data = load_scenarios_data()
    scenarios = data.get("scenarios", {})
    return {
        "company": data.get("company_profile"),
        "scenarios": [
            {
                "id": k,
                "name": v["name"],
                "description": v["description"],
                "expected_outcome": v["expected_outcome"],
            }
            for k, v in scenarios.items()
        ],
    }


@router.get(
    "/compare",
    response_model=AssessmentComparisonResult,
    summary="Compare Two Risk Assessments (Query Params)",
    description="Compares two persisted historical assessments and calculates factor diffs, score changes, and evidence changes.",
)
async def compare_assessments_query(
    base_id: str = Query(..., description="ID of baseline assessment"),
    target_id: str = Query(..., description="ID of target assessment to compare against baseline"),
    db: Session = Depends(get_db),
) -> AssessmentComparisonResult:
    service = AssessmentService(db)
    return service.compare_assessments(base_id=base_id, target_id=target_id)


@router.get(
    "/compare/{base_id}/{target_id}",
    response_model=AssessmentComparisonResult,
    summary="Compare Two Risk Assessments (Path Params)",
    description="Compares two persisted historical assessments and calculates factor diffs, score changes, and evidence changes.",
)
async def compare_assessments_path(
    base_id: str,
    target_id: str,
    db: Session = Depends(get_db),
) -> AssessmentComparisonResult:
    service = AssessmentService(db)
    return service.compare_assessments(base_id=base_id, target_id=target_id)


@router.get(
    "/{assessment_id}",
    response_model=RiskAssessmentResult,
    summary="Get Assessment Details by ID",
)
async def get_assessment(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> RiskAssessmentResult:
    """Retrieve an assessment by its unique ID from database storage."""
    service = AssessmentService(db)
    return service.get_assessment(assessment_id)


@router.get(
    "",
    response_model=list[dict],
    summary="List Recent Assessments",
)
async def list_assessments(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List recent assessments summary from persistent database storage."""
    service = AssessmentService(db)
    return service.list_all_assessments(limit=limit, offset=offset)
