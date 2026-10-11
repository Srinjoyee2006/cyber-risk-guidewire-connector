"""
CyberRisk-Guidewire-Connector (CRGC)
Consolidated API v1 Router
"""

from fastapi import APIRouter
from app.api.v1.telemetry import router as telemetry_router
from app.api.v1.assessments import router as assessments_router
from app.api.v1.ingestion import router as ingestion_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router
from app.api.v1.exploitation import router as exploitation_router
from app.api.v1.prioritization import router as prioritization_router
from app.api.v1.overview import router as overview_router
from app.api.v1.organizations import router as organizations_router
from app.api.v1.assets import router as assets_router
from app.api.v1.observations import router as observations_router

api_v1_router = APIRouter(prefix="/v1")

# Mount modular sub-routers
api_v1_router.include_router(telemetry_router)
api_v1_router.include_router(assessments_router)
api_v1_router.include_router(ingestion_router)
api_v1_router.include_router(vulnerabilities_router)
api_v1_router.include_router(exploitation_router)
api_v1_router.include_router(prioritization_router)
api_v1_router.include_router(overview_router)
api_v1_router.include_router(organizations_router)
api_v1_router.include_router(assets_router)
api_v1_router.include_router(observations_router)

