"""
CyberRisk-Guidewire-Connector (CRGC)
Consolidated API v1 Router
"""

from fastapi import APIRouter
from app.api.v1.telemetry import router as telemetry_router
from app.api.v1.assessments import router as assessments_router

api_v1_router = APIRouter(prefix="/v1")

# Mount modular sub-routers
api_v1_router.include_router(telemetry_router)
api_v1_router.include_router(assessments_router)
