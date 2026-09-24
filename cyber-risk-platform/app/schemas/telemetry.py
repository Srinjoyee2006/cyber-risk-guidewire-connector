"""
CyberRisk-Guidewire-Connector (CRGC)
Telemetry Schemas - Cybersecurity Posture Ingestion
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from pydantic import BaseModel, Field, field_validator


class CVESeverity(str, Enum):
    """Common Vulnerability Scoring System (CVSS) categorical severity ratings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CVEItem(BaseModel):
    """
    Individual Common Vulnerabilities and Exposures (CVE) record with CVSS metrics and aging.
    """
    cve_id: Annotated[
        str,
        Field(
            pattern=r"^CVE-\d{4}-\d{4,}$",
            description="Standardized CVE identifier (e.g., CVE-2024-38077)",
            examples=["CVE-2024-38077"],
        ),
    ]
    severity: Annotated[
        CVESeverity,
        Field(description="Categorical severity rating based on CVSS v3.1/v4.0"),
    ]
    cvss_score: Annotated[
        float,
        Field(
            ge=0.0,
            le=10.0,
            description="Numeric CVSS base score (0.0 to 10.0)",
            examples=[9.8],
        ),
    ]
    aging_days: Annotated[
        int,
        Field(
            ge=0,
            description="Elapsed days since vulnerability public disclosure without applied patch",
            examples=[28],
        ),
    ]
    is_rce: Annotated[
        bool,
        Field(
            default=False,
            description="Flag indicating Remote Code Execution capability",
        ),
    ]
    description: Annotated[
        Optional[str],
        Field(
            default=None,
            description="Brief summary of vulnerability impact and component",
        ),
    ]


class TelemetrySnapshot(BaseModel):
    """
    Comprehensive periodic or continuous cybersecurity posture telemetry snapshot for an insured entity.
    Ingested from external attack surface management (ASM), EDR, or identity governance agents.
    """
    tenant_id: Annotated[
        str,
        Field(
            min_length=1,
            description="Identifier of the risk telemetry provider or corporate tenant",
            examples=["TENANT-9941"],
        ),
    ]
    company_name: Annotated[
        str,
        Field(
            min_length=1,
            description="Legal commercial entity name matching PolicyCenter Account",
            examples=["ABC Technologies Inc."],
        ),
    ]
    policy_number: Annotated[
        str,
        Field(
            min_length=1,
            description="In-force commercial cyber insurance policy number in Guidewire PolicyCenter",
            examples=["POL-001"],
        ),
    ]
    timestamp: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(timezone.utc),
            description="UTC timestamp of the telemetry observation capture",
        ),
    ]

    # Key Cybersecurity Posture Controls
    mfa_enforcement_rate: Annotated[
        float,
        Field(
            ge=0.0,
            le=1.0,
            description="Proportion of corporate accounts protected by enforced Multi-Factor Authentication (0.0 - 1.0)",
            examples=[0.98],
        ),
    ]
    exposed_rdp_port: Annotated[
        bool,
        Field(
            description="Indicator of whether Remote Desktop Protocol (Port 3389) is reachable from the public Internet",
            examples=[False],
        ),
    ]
    open_ports: Annotated[
        list[int],
        Field(
            default_factory=list,
            description="List of publicly reachable network ports discovered during edge scan",
            examples=[80, 443],
        ),
    ]
    critical_cves: Annotated[
        list[CVEItem],
        Field(
            default_factory=list,
            description="Active critical unpatched vulnerabilities on perimeter and core infrastructure",
        ),
    ]
    edr_agent_coverage: Annotated[
        float,
        Field(
            ge=0.0,
            le=1.0,
            description="Proportion of corporate server and workstation endpoints covered by active EDR agent (0.0 - 1.0)",
            examples=[0.95],
        ),
    ]
    immutable_backups_verified: Annotated[
        bool,
        Field(
            default=True,
            description="Actuarial underwriting factor verifying offline or immutable backup protection against ransomware",
        ),
    ]
    security_awareness_training_rate: Annotated[
        float,
        Field(
            default=0.90,
            ge=0.0,
            le=1.0,
            description="Employee compliance rate with continuous phishing and cyber training (0.0 - 1.0)",
        ),
    ]

    @field_validator("open_ports")
    @classmethod
    def validate_open_ports(cls, ports: list[int]) -> list[int]:
        """Validate port numbers fall within legitimate 1-65535 range."""
        for port in ports:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port number {port} is out of valid range (1 - 65535)")
        return ports

    @property
    def critical_cve_count(self) -> int:
        """Count of vulnerabilities rated CRITICAL."""
        return len([cve for cve in self.critical_cves if cve.severity == CVESeverity.CRITICAL])

    @property
    def max_critical_cve_aging_days(self) -> int:
        """Maximum days of aging among unpatched critical vulnerabilities."""
        crit = [cve.aging_days for cve in self.critical_cves if cve.severity == CVESeverity.CRITICAL]
        return max(crit) if crit else 0


class TelemetryIngestResponse(BaseModel):
    """Standardized response following successful telemetry ingest."""
    status: Annotated[str, Field(examples=["acknowledged"])]
    ingest_id: Annotated[str, Field(description="Unique idempotency and tracking ID")]
    policy_number: Annotated[str, Field(description="Associated policy number")]
    received_at: Annotated[datetime, Field(description="UTC timestamp of ingest")]
    factors_summary: Annotated[dict, Field(description="High-level posture factors summarized")]
