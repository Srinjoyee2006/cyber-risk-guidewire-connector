"""
CyberRisk-Guidewire-Connector (CRGC)
Telemetry API - Ingest and Retrieve Cybersecurity Posture Snapshots
"""

from datetime import datetime, timezone
import logging
from typing import Annotated, Dict
from uuid import uuid4
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.telemetry import (
    TelemetrySnapshot,
    TelemetryIngestResponse,
)

logger = logging.getLogger("crgc.api.telemetry")

router = APIRouter(prefix="/telemetry", tags=["Cyber Telemetry Ingest"])

# In-memory store for policy telemetry snapshots (keyed by policy_number)
# In production, this integrates with time-series or event stream storage (Kafka/PostgreSQL)
_telemetry_store: Dict[str, TelemetrySnapshot] = {}


def get_stored_telemetry(policy_number: str) -> TelemetrySnapshot | None:
    """Retrieve the latest telemetry snapshot for a given policy number."""
    return _telemetry_store.get(policy_number)


def store_telemetry(snapshot: TelemetrySnapshot) -> None:
    """Persist a telemetry snapshot in the active store."""
    _telemetry_store[snapshot.policy_number] = snapshot


@router.post(
    "/ingest",
    response_model=TelemetryIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Cybersecurity Posture Telemetry Snapshot",
    description="Ingests continuous or periodic cybersecurity telemetry for an in-force insured entity.",
)
async def ingest_telemetry(snapshot: TelemetrySnapshot) -> TelemetryIngestResponse:
    """
    Ingest a new telemetry snapshot from edge sensors, EDR, ASM, or identity governance feeds.
    Validates posture metrics, stores latest state, and prepares for risk assessment.
    """
    ingest_id = f"ING-{uuid4().hex[:8].upper()}"
    store_telemetry(snapshot)

    logger.info(
        "Ingested telemetry %s for policy %s (%s). MFA=%.1f%%, RDP=%s, Critical CVEs=%d, EDR=%.1f%%",
        ingest_id,
        snapshot.policy_number,
        snapshot.company_name,
        snapshot.mfa_enforcement_rate * 100,
        snapshot.exposed_rdp_port,
        snapshot.critical_cve_count,
        snapshot.edr_agent_coverage * 100,
    )

    return TelemetryIngestResponse(
        status="acknowledged",
        ingest_id=ingest_id,
        policy_number=snapshot.policy_number,
        received_at=datetime.now(timezone.utc),
        factors_summary={
            "company_name": snapshot.company_name,
            "mfa_enforcement_rate": f"{snapshot.mfa_enforcement_rate * 100:.1f}%",
            "exposed_rdp_port": snapshot.exposed_rdp_port,
            "critical_cve_count": snapshot.critical_cve_count,
            "edr_agent_coverage": f"{snapshot.edr_agent_coverage * 100:.1f}%",
            "immutable_backups_verified": snapshot.immutable_backups_verified,
        },
    )


@router.get(
    "/{policy_number}/latest",
    response_model=TelemetrySnapshot,
    summary="Get Latest Telemetry Snapshot for Policy",
    description="Fetches the most recent security posture snapshot stored for the specified policy number.",
)
async def get_latest_telemetry(policy_number: str) -> TelemetrySnapshot:
    """Retrieve the latest telemetry for a policy."""
    snapshot = get_stored_telemetry(policy_number)
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
async def list_tracked_policies() -> list[dict]:
    """List summary of all tracked policies."""
    return [
        {
            "policy_number": p,
            "company_name": s.company_name,
            "timestamp": s.timestamp.isoformat(),
            "mfa_rate": s.mfa_enforcement_rate,
            "rdp_exposed": s.exposed_rdp_port,
            "critical_cves": s.critical_cve_count,
            "edr_coverage": s.edr_agent_coverage,
        }
        for p, s in _telemetry_store.items()
    ]
