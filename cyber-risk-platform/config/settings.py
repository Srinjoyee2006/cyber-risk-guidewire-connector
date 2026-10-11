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

    # --------------------------------------------------------------------------
    # Database Persistence (SQLite local / PostgreSQL compatible)
    # --------------------------------------------------------------------------
    database_url: str = Field(
        default="sqlite:///./crgc.db",
        description="Database connection URL (SQLite or PostgreSQL)",
    )
    db_echo: bool = Field(
        default=False,
        description="SQLAlchemy echo SQL statements",
    )

    # --------------------------------------------------------------------------
    # NVD API v2.0 Configuration
    # --------------------------------------------------------------------------
    nvd_api_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="Base URL for NVD CVE REST API v2.0",
    )
    nvd_api_key: str | None = Field(
        default=None,
        description="Optional NVD API key for higher rate limits",
    )
    nvd_request_timeout: float = Field(
        default=30.0,
        description="HTTP request timeout for NVD API calls in seconds",
    )
    nvd_rate_limit_delay: float = Field(
        default=0.6,
        ge=0.0,
        description="Delay between sequential NVD API requests in seconds",
    )
    nvd_default_results_per_page: int = Field(
        default=2000,
        ge=1,
        le=2000,
        description="Default number of CVE results per page for NVD requests",
    )

    # --------------------------------------------------------------------------
    # CISA Known Exploited Vulnerabilities (KEV) Catalog Configuration
    # --------------------------------------------------------------------------
    cisa_kev_catalog_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="Official CISA KEV catalog JSON endpoint",
    )
    cisa_kev_request_timeout: float = Field(
        default=30.0,
        description="HTTP request timeout for CISA KEV catalog fetch in seconds",
    )


    # --------------------------------------------------------------------------
    # Vulnerability Prioritization Engine (Public Vulnerability Intelligence)
    # --------------------------------------------------------------------------
    prioritization_ruleset_version: str = Field(
        default="v1.0.0",
        description="Version identifier of the deterministic vulnerability prioritization scoring ruleset",
    )
    # Priority Band Thresholds
    priority_band_p1_threshold: float = Field(
        default=75.0,
        ge=0.0,
        le=100.0,
        description="Minimum score threshold for Priority P1 (Critical triage)",
    )
    priority_band_p2_threshold: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
        description="Minimum score threshold for Priority P2 (High triage)",
    )
    priority_band_p3_threshold: float = Field(
        default=25.0,
        ge=0.0,
        le=100.0,
        description="Minimum score threshold for Priority P3 (Medium triage)",
    )
    # Rule Score Weights (Configuration-driven, heuristic/transparent, not actuarially calibrated)
    weight_kev_listed: float = Field(
        default=35.0,
        ge=0.0,
        le=100.0,
        description="Score weight for active presence in CISA Known Exploited Vulnerabilities catalog",
    )
    weight_cvss_critical: float = Field(
        default=25.0,
        ge=0.0,
        le=100.0,
        description="Score weight for CVSS base score >= 9.0",
    )
    weight_cvss_high: float = Field(
        default=15.0,
        ge=0.0,
        le=100.0,
        description="Score weight for CVSS base score >= 7.0 and < 9.0",
    )
    weight_remote_exploitable: float = Field(
        default=15.0,
        ge=0.0,
        le=100.0,
        description="Score weight for network attack vector (AV:N)",
    )
    weight_low_privileges_required: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Score weight for no privileges required (PR:N)",
    )
    weight_kev_due_date_near: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Score weight for KEV remediation due date within the next 14 days",
    )
    weight_recently_published: float = Field(
        default=5.0,
        ge=0.0,
        le=100.0,
        description="Score weight for NVD publication date within the last 30 days",
    )
    # Rule Parameter Thresholds
    cvss_critical_threshold: float = Field(
        default=9.0,
        ge=0.0,
        le=10.0,
        description="CVSS score threshold for critical classification",
    )
    cvss_high_threshold: float = Field(
        default=7.0,
        ge=0.0,
        le=10.0,
        description="CVSS score threshold for high classification",
    )
    kev_due_date_near_days: int = Field(
        default=14,
        ge=1,
        description="Days threshold for approaching KEV remediation due date",
    )
    recently_published_days: int = Field(
        default=30,
        ge=1,
        description="Days threshold for recently published CVEs",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached accessor for singleton Settings instance."""
    return Settings()
