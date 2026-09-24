"""
CyberRisk-Guidewire-Connector (CRGC)
Configuration Module - Pydantic v2 BaseSettings
"""

from functools import lru_cache
from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized enterprise application configuration.
    Validates environment variables, API endpoints, credentials, and actuarial thresholds.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --------------------------------------------------------------------------
    # Application Runtime
    # --------------------------------------------------------------------------
    app_name: str = Field(
        default="CyberRisk-Guidewire-Connector",
        description="Name of the service instance",
    )
    app_env: Literal["development", "staging", "production", "test"] = Field(
        default="development",
        description="Execution deployment environment",
    )
    debug: bool = Field(
        default=True,
        description="Toggle verbose FastAPI debug mode",
    )
    host: str = Field(
        default="0.0.0.0",
        description="Bind network host address",
    )
    port: int = Field(
        default=8000,
        description="Bind network port",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Standardized logging level",
    )

    # --------------------------------------------------------------------------
    # Guidewire PolicyCenter 10.2.1 Integration Settings
    # --------------------------------------------------------------------------
    gw_mock_mode: bool = Field(
        default=True,
        description="Run against local deterministic mock simulator if True, or live Guidewire if False",
    )
    gw_base_url: str = Field(
        default="https://pc-eval-cloud.guidewire.net/pc",
        description="Base URL for Guidewire PolicyCenter instance",
    )
    gw_policycenter_version: str = Field(
        default="10.2.1",
        description="Target PolicyCenter release version",
    )
    gw_auth_type: Literal["oauth2", "basic"] = Field(
        default="oauth2",
        description="Guidewire Cloud Platform authentication mechanism",
    )
    gw_auth_url: str = Field(
        default="https://pc-eval-cloud.guidewire.net/oauth2/token",
        description="OAuth2 token authorization endpoint",
    )
    gw_client_id: str = Field(
        default="crgc_edge_service_client_id",
        description="Guidewire Cloud API client credentials identifier",
    )
    gw_client_secret: str = Field(
        default="crgc_edge_service_client_secret",
        description="Guidewire Cloud API client credentials secret",
    )
    gw_username: str = Field(
        default="su",
        description="Basic auth fallback username",
    )
    gw_password: str = Field(
        default="gw",
        description="Basic auth fallback password",
    )
    gw_timeout_seconds: float = Field(
        default=15.0,
        description="HTTP request timeout when communicating with PolicyCenter",
    )

    # Guidewire Cloud REST API Endpoint Templates
    gw_activities_path: str = Field(
        default="/rest/common/v1/activities",
        description="Endpoint for creating underwriter review tasks",
    )
    gw_policy_notes_path: str = Field(
        default="/rest/policy/v1/policies/{policyNumber}/notes",
        description="Endpoint for writing policy audit notes",
    )
    gw_policies_path: str = Field(
        default="/rest/policy/v1/policies/{policyNumber}",
        description="Endpoint for fetching policy details",
    )

    # --------------------------------------------------------------------------
    # Actuarial Risk Engine Thresholds & Calibrations
    # --------------------------------------------------------------------------
    base_risk_score: float = Field(
        default=5.0,
        ge=0.0,
        le=100.0,
        description="Baseline residual operational risk score for an in-force insured",
    )
    risk_score_monitor_threshold: float = Field(
        default=40.0,
        ge=0.0,
        le=100.0,
        description="Boundary score above which underwriting monitoring advisory is issued",
    )
    risk_score_review_threshold: float = Field(
        default=60.0,
        ge=0.0,
        le=100.0,
        description="Boundary score above which mandatory Underwriter Review activity is created in PolicyCenter",
    )

    # Benchmark Quality Minimums
    mfa_enforcement_threshold: float = Field(
        default=0.80,
        ge=0.0,
        le=1.0,
        description="Minimum enterprise MFA enforcement rate benchmark (80%)",
    )
    edr_agent_coverage_threshold: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Minimum enterprise EDR agent coverage benchmark (85%)",
    )
    critical_cve_aging_days_threshold: int = Field(
        default=14,
        ge=1,
        description="Maximum acceptable days to patch critical RCE vulnerabilities",
    )

    # Actuarial Penalty Point Allocations
    penalty_mfa_max: float = Field(
        default=30.0,
        ge=0.0,
        le=100.0,
        description="Maximum penalty points for unmitigated identity/MFA gaps",
    )
    penalty_exposed_rdp: float = Field(
        default=25.0,
        ge=0.0,
        le=100.0,
        description="Fixed penalty for public Internet-facing RDP port 3389 exposure",
    )
    penalty_critical_cve_per_item: float = Field(
        default=12.5,
        ge=0.0,
        le=100.0,
        description="Penalty points accrued per critical unpatched CVE aging past threshold",
    )
    penalty_critical_cve_max: float = Field(
        default=35.0,
        ge=0.0,
        le=100.0,
        description="Maximum accumulated penalty ceiling for critical CVE aging",
    )
    penalty_edr_max: float = Field(
        default=20.0,
        ge=0.0,
        le=100.0,
        description="Maximum penalty points for missing endpoint detection and response (EDR)",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached accessor for singleton Settings instance."""
    return Settings()
