"""
CyberRisk-Guidewire-Connector (CRGC)
Enterprise FastAPI Application Entrypoint & Factory
"""

from contextlib import asynccontextmanager
import logging
import sys
import time
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import Settings, get_settings
from app.api.v1.router import api_v1_router

# ==============================================================================
# Logging Configuration
# ==============================================================================
def configure_logging(settings: Settings) -> None:
    """Configure structured logging for enterprise observability."""
    log_format = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format=log_format,
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


# ==============================================================================
# Lifespan Management
# ==============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and graceful shutdown lifecycle."""
    settings = get_settings()
    configure_logging(settings)
    logger = logging.getLogger("crgc.lifecycle")

    logger.info("=" * 70)
    logger.info("Initializing CyberRisk-Guidewire-Connector (CRGC) v1.0.0")
    logger.info("Target PolicyCenter Version: %s", settings.gw_policycenter_version)
    logger.info("Guidewire Mock Mode: %s", "ENABLED (Local Simulated)" if settings.gw_mock_mode else "DISABLED (Live GWCP)")
    logger.info("Actuarial Thresholds: Monitor=%.1f | Review=%.1f", settings.risk_score_monitor_threshold, settings.risk_score_review_threshold)
    logger.info("=" * 70)

    yield

    logger.info("Shutting down CRGC service. Closing connections.")


# ==============================================================================
# Application Factory
# ==============================================================================
def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Construct and configure the production FastAPI application instance.
    """
    app_settings = settings or get_settings()

    app = FastAPI(
        title="CyberRisk-Guidewire-Connector (CRGC)",
        description=(
            "Enterprise Edge Risk Analytics Service for Commercial Cyber Insurance.\n\n"
            "**Key Capabilities:**\n"
            "- Ingests continuous and periodic cybersecurity posture telemetry snapshots.\n"
            "- Evaluates explainable, deterministic actuarial scoring rules (MFA, EDR, RDP, Critical CVE Aging).\n"
            "- Formulates policy coverage modifications (sublimit cuts, retention surcharges, co-insurance).\n"
            "- Dispatches Underwriter Review Activities & Policy Notes to **Guidewire PolicyCenter 10.2.1** via Guidewire Cloud REST APIs."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # --------------------------------------------------------------------------
    # Security Middleware: CORS
    # --------------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --------------------------------------------------------------------------
    # Request Auditing & Latency Middleware
    # --------------------------------------------------------------------------
    @app.middleware("http")
    async def audit_and_timing_middleware(request: Request, call_next):
        start_time = time.perf_counter()
        response = await call_next(request)
        process_time_ms = (time.perf_counter() - start_time) * 1000.0
        response.headers["X-Process-Time-Ms"] = f"{process_time_ms:.2f}"
        response.headers["X-Service-Name"] = "CRGC-Guidewire-Connector"
        return response

    # --------------------------------------------------------------------------
    # Core Diagnostics Endpoints
    # --------------------------------------------------------------------------
    @app.get(
        "/",
        summary="Service Root & Health Overview",
        tags=["System"],
    )
    async def root_overview() -> dict:
        return {
            "service": "CyberRisk-Guidewire-Connector",
            "version": "1.0.0",
            "status": "OPERATIONAL",
            "target_guidewire_release": app_settings.gw_policycenter_version,
            "mock_mode": app_settings.gw_mock_mode,
            "documentation": "/docs",
            "actuarial_benchmarks": {
                "mfa_min_threshold": f"{app_settings.mfa_enforcement_threshold * 100:.0f}%",
                "edr_min_threshold": f"{app_settings.edr_agent_coverage_threshold * 100:.0f}%",
                "cve_max_aging_days": app_settings.critical_cve_aging_days_threshold,
                "review_action_trigger_score": app_settings.risk_score_review_threshold,
            },
        }

    @app.get(
        "/health",
        summary="Kubernetes / Guidewire Integration Liveness & Readiness Probe",
        tags=["System"],
        status_code=status.HTTP_200_OK,
    )
    async def health_check() -> dict:
        return {
            "status": "UP",
            "timestamp": time.time(),
            "guidewire_connectivity": {
                "target_version": app_settings.gw_policycenter_version,
                "mode": "MOCK_SIMULATOR" if app_settings.gw_mock_mode else "LIVE_GWCP",
                "base_url": app_settings.gw_base_url,
            },
        }

    # --------------------------------------------------------------------------
    # Mount Consolidated API Routers
    # --------------------------------------------------------------------------
    app.include_router(api_v1_router, prefix="/api")

    return app


# Default ASGI application instance for uvicorn
app = create_app()


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
