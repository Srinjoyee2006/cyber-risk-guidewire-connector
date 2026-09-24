"""
Pydantic v2 schemas package for CRGC.
"""

from app.schemas.telemetry import (
    CVEItem,
    CVESeverity,
    TelemetrySnapshot,
    TelemetryIngestResponse,
)
from app.schemas.risk import (
    RiskTier,
    PolicyAction,
    FactorPenalty,
    CoverageRecommendation,
    RiskAssessmentResult,
    AssessmentRequest,
)
from app.schemas.guidewire import (
    GuidewireActivityCreateRequest,
    GuidewireNoteCreateRequest,
    GuidewireActivityResponse,
    GuidewireNoteResponse,
)

__all__ = [
    "CVEItem",
    "CVESeverity",
    "TelemetrySnapshot",
    "TelemetryIngestResponse",
    "RiskTier",
    "PolicyAction",
    "FactorPenalty",
    "CoverageRecommendation",
    "RiskAssessmentResult",
    "AssessmentRequest",
    "GuidewireActivityCreateRequest",
    "GuidewireNoteCreateRequest",
    "GuidewireActivityResponse",
    "GuidewireNoteResponse",
]
