"""
CyberRisk-Guidewire-Connector (CRGC)
Assessments API - Trigger Risk Evaluation & Underwriter Review Workflow
"""

import json
import logging
from pathlib import Path
from typing import Annotated, Dict, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, status

from config.settings import Settings, get_settings
from app.api.v1.telemetry import get_stored_telemetry, store_telemetry
from app.core.risk_engine import RiskEngine
from app.core.coverage_engine import CoverageEngine
from app.schemas.telemetry import TelemetrySnapshot
from app.schemas.risk import (
    AssessmentRequest,
    RiskAssessmentResult,
    PolicyAction,
)
from app.services.guidewire_client import GuidewireClient

logger = logging.getLogger("crgc.api.assessments")

router = APIRouter(prefix="/assessments", tags=["Risk Assessment & Guidewire Workflow"])

# In-memory storage of completed assessments for audit history
_assessments_store: Dict[str, RiskAssessmentResult] = {}


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
    summary="Evaluate Policy Risk & Trigger Guidewire Workflow",
    description=(
        "Executes explainable actuarial risk scoring on the latest ingested telemetry. "
        "If score > 60 (REVIEW_REQUIRED), automatically dispatches an Underwriter Activity "
        "and Policy Audit Note to Guidewire PolicyCenter 10.2.1."
    ),
)
async def evaluate_assessment(
    request: AssessmentRequest,
    risk_engine: Annotated[RiskEngine, Depends(get_risk_engine)],
    coverage_engine: Annotated[CoverageEngine, Depends(get_coverage_engine)],
    gw_client: Annotated[GuidewireClient, Depends(get_guidewire_client)],
) -> RiskAssessmentResult:
    """
    Execute actuarial evaluation on latest telemetry for policy.
    """
    telemetry = get_stored_telemetry(request.policy_number)
    if not telemetry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No telemetry found for policy '{request.policy_number}'. "
                f"Please ingest telemetry first or run a scenario via /assessments/scenarios/{{scenario_id}}/execute."
            ),
        )

    # 1. Run deterministic Actuarial Risk Engine
    aggregate_score, factor_penalties = risk_engine.compute_risk_score(telemetry)
    risk_tier = risk_engine.determine_risk_tier(aggregate_score)
    policy_action = risk_engine.determine_policy_action(aggregate_score)

    # 2. Run Coverage Engine to evaluate policy terms & endorsements
    coverage_recommendations = coverage_engine.evaluate_coverage(
        policy_number=telemetry.policy_number,
        risk_score=aggregate_score,
        risk_tier=risk_tier,
        policy_action=policy_action,
        factor_penalties=factor_penalties,
    )

    assessment_id = f"ASM-{uuid4().hex[:8].upper()}"

    telemetry_summary = {
        "mfa_enforcement_rate": f"{telemetry.mfa_enforcement_rate * 100:.1f}%",
        "exposed_rdp_port": telemetry.exposed_rdp_port,
        "critical_cves_count": telemetry.critical_cve_count,
        "edr_agent_coverage": f"{telemetry.edr_agent_coverage * 100:.1f}%",
        "open_ports": telemetry.open_ports,
        "immutable_backups_verified": telemetry.immutable_backups_verified,
    }

    # 3. Form initial assessment object
    assessment = RiskAssessmentResult(
        assessment_id=assessment_id,
        policy_number=telemetry.policy_number,
        company_name=telemetry.company_name,
        base_score=risk_engine.settings.base_risk_score,
        aggregate_risk_score=aggregate_score,
        risk_tier=risk_tier,
        policy_action=policy_action,
        factor_breakdowns=factor_penalties,
        coverage_recommendations=coverage_recommendations,
        telemetry_summary=telemetry_summary,
        guidewire_activity_created=False,
    )

    # 4. Guidewire Cloud Integration Trigger
    # Triggered when action is REVIEW_REQUIRED (Score > 60) and workflow trigger is enabled
    if request.trigger_guidewire_workflow and policy_action == PolicyAction.REVIEW_REQUIRED:
        logger.warning(
            "Policy %s exceeded review threshold (Score=%.1f). Triggering Guidewire PolicyCenter 10.2.1 activity creation.",
            telemetry.policy_number,
            aggregate_score,
        )
        try:
            # Create Policy Note for audit trail
            note_resp = await gw_client.create_policy_note(
                policy_number=telemetry.policy_number,
                assessment=assessment,
            )
            assessment.guidewire_note_id = note_resp.data.id

            # Create Underwriter Review Activity Task
            activity_resp = await gw_client.create_underwriter_activity(
                policy_number=telemetry.policy_number,
                assessment=assessment,
            )
            assessment.guidewire_activity_created = True
            assessment.guidewire_activity_id = activity_resp.data.id

            logger.info(
                "Successfully dispatched Guidewire Activity %s and Note %s for policy %s",
                assessment.guidewire_activity_id,
                assessment.guidewire_note_id,
                telemetry.policy_number,
            )
        except Exception as e:
            logger.error("Failed to execute Guidewire Cloud integration: %s", str(e), exc_info=True)
            # Retain assessment results even if external call fails
            assessment.coverage_recommendations.underwriter_notes += f" [Guidewire Dispatch Warning: {str(e)}]"

    # Store for audit trail
    _assessments_store[assessment.assessment_id] = assessment
    return assessment


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
    risk_engine: Annotated[RiskEngine, Depends(get_risk_engine)],
    coverage_engine: Annotated[CoverageEngine, Depends(get_coverage_engine)],
    gw_client: Annotated[GuidewireClient, Depends(get_guidewire_client)],
) -> RiskAssessmentResult:
    """
    Run one of the predefined deterministic scenarios directly.
    Auto-ingests the scenario's telemetry, runs the engines, and dispatches Guidewire activities if applicable.
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

    # Ingest into store
    store_telemetry(snapshot)

    # Evaluate
    req = AssessmentRequest(
        policy_number=snapshot.policy_number,
        trigger_guidewire_workflow=True,
    )
    return await evaluate_assessment(
        request=req,
        risk_engine=risk_engine,
        coverage_engine=coverage_engine,
        gw_client=gw_client,
    )


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
    "/{assessment_id}",
    response_model=RiskAssessmentResult,
    summary="Get Assessment Details by ID",
)
async def get_assessment(assessment_id: str) -> RiskAssessmentResult:
    """Retrieve an assessment by its unique ID."""
    assessment = _assessments_store.get(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    return assessment


@router.get(
    "",
    response_model=list[dict],
    summary="List Recent Assessments",
)
async def list_assessments() -> list[dict]:
    """List recent assessments summary."""
    return [
        {
            "assessment_id": a.assessment_id,
            "timestamp": a.timestamp.isoformat(),
            "policy_number": a.policy_number,
            "company_name": a.company_name,
            "aggregate_risk_score": a.aggregate_risk_score,
            "risk_tier": a.risk_tier.value,
            "policy_action": a.policy_action.value,
            "guidewire_activity_created": a.guidewire_activity_created,
            "guidewire_activity_id": a.guidewire_activity_id,
        }
        for a in _assessments_store.values()
    ]
