"""
CyberRisk-Guidewire-Connector (CRGC)
Telemetry API - Ingest and Retrieve Cybersecurity Posture Snapshots (Persistent Database Storage)
"""

from datetime import datetime, timezone
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import get_current_user, UserProfile
from app.db.session import get_db, SessionLocal
from app.schemas.telemetry import (
    TelemetrySnapshot,
    TelemetryIngestResponse,
)
from app.services.assessment_service import AssessmentService

logger = logging.getLogger("crgc.api.telemetry")

router = APIRouter(prefix="/telemetry", tags=["Cyber Telemetry Ingest"])


def get_stored_telemetry(policy_number: str) -> Optional[TelemetrySnapshot]:
    """Retrieve the latest telemetry snapshot for a given policy number from persistent storage."""
    db = SessionLocal()
    try:
        service = AssessmentService(db)
        return service.get_latest_telemetry(policy_number)
    finally:
        db.close()


def store_telemetry(snapshot: TelemetrySnapshot) -> None:
    """Persist a telemetry snapshot in database storage."""
    db = SessionLocal()
    try:
        service = AssessmentService(db)
        service.ingest_telemetry(snapshot)
    finally:
        db.close()


@router.post(
    "/ingest",
    response_model=TelemetryIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Cybersecurity Posture Telemetry Snapshot",
    description="Ingests continuous or periodic cybersecurity telemetry for an in-force insured entity into persistent storage.",
)
async def ingest_telemetry(
    snapshot: TelemetrySnapshot,
    db: Session = Depends(get_db),
    current_user: UserProfile = Depends(get_current_user),
) -> TelemetryIngestResponse:
    """
    Ingest a new telemetry snapshot from edge sensors, EDR, ASM, or identity governance feeds.
    Validates posture metrics, stores state in database, and prepares for risk assessment.
    """
    service = AssessmentService(db)
    return service.ingest_telemetry(snapshot)


@router.get(
    "/{policy_number}/latest",
    response_model=TelemetrySnapshot,
    summary="Get Latest Telemetry Snapshot for Policy",
    description="Fetches the most recent security posture snapshot stored for the specified policy number.",
)
async def get_latest_telemetry(
    policy_number: str,
    db: Session = Depends(get_db),
) -> TelemetrySnapshot:
    """Retrieve the latest telemetry for a policy."""
    service = AssessmentService(db)
    snapshot = service.get_latest_telemetry(policy_number)
    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No telemetry snapshot found for policy '{policy_number}'. Ingest telemetry or run a test scenario first.",
        )
    return snapshot


@router.get(
    "",
    response_model=list[dict],
    summary="List Tracked In-force Policies",
    description="Lists all policies currently possessing active telemetry snapshots.",
)
async def list_tracked_policies(
    db: Session = Depends(get_db),
) -> list[dict]:
    """List summary of all tracked policies."""
    service = AssessmentService(db)
    return service.list_tracked_policies()
